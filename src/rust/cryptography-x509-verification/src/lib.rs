// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]

pub mod certificate;
pub mod ops;
pub mod policy;
pub mod trust_store;
pub mod types;

use std::vec;

use cryptography_x509::extensions::{DuplicateExtensionsError, Extensions};
use cryptography_x509::{
    extensions::{AuthorityKeyIdentifier, NameConstraints, SubjectAlternativeName},
    name::GeneralName,
    oid::{
        AUTHORITY_KEY_IDENTIFIER_OID, NAME_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID,
        SUBJECT_KEY_IDENTIFIER_OID,
    },
};

use crate::certificate::cert_is_self_issued;
use crate::ops::{CryptoOps, VerificationCertificate};
use crate::policy::Policy;
use crate::trust_store::Store;
use crate::types::DNSName;
use crate::types::{DNSConstraint, IPAddress, IPConstraint};
use crate::ApplyNameConstraintStatus::{Applied, Skipped};

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    CandidatesExhausted(Box<ValidationError>),
    Malformed(asn1::ParseError),
    DuplicateExtension(DuplicateExtensionsError),
    FatalError(&'static str),
    Other(String),
}

struct Budget {
    name_constraint_checks: usize,
    signature_checks: usize,
}

impl Budget {
    // The maximum number of name constraint checks performed when attempting
    // path construction. This is the same limit as other validators.
    const DEFAULT_NAME_CONSTRAINT_CHECK_LIMIT: usize = 1 << 20;

    // The maximum number of signature verifications performed when attempting
    // path construction. The is similar to other validators:
    // both Go and rustls-webpki pick 100.
    const DEFAULT_SIGNATURE_CHECK_LIMIT: usize = 1 << 7;

    fn new() -> Budget {
        Budget {
            name_constraint_checks: Self::DEFAULT_NAME_CONSTRAINT_CHECK_LIMIT,
            signature_checks: Self::DEFAULT_SIGNATURE_CHECK_LIMIT,
        }
    }

    fn name_constraint_check(&mut self) -> Result<(), ValidationError> {
        self.name_constraint_checks =
            self.name_constraint_checks
                .checked_sub(1)
                .ok_or(ValidationError::FatalError(
                    "Exceeded maximum name constraint check limit",
                ))?;
        Ok(())
    }

    fn signature_check(&mut self) -> Result<(), ValidationError> {
        self.signature_checks =
            self.signature_checks
                .checked_sub(1)
                .ok_or(ValidationError::FatalError(
                    "Exceeded maximum signature check limit",
                ))?;
        Ok(())
    }
}

impl From<asn1::ParseError> for ValidationError {
    fn from(value: asn1::ParseError) -> Self {
        Self::Malformed(value)
    }
}

impl From<DuplicateExtensionsError> for ValidationError {
    fn from(value: DuplicateExtensionsError) -> Self {
        Self::DuplicateExtension(value)
    }
}

struct NameChain<'a, 'chain> {
    child: Option<&'a NameChain<'a, 'chain>>,
    sans: SubjectAlternativeName<'chain>,
}

impl<'a, 'chain> NameChain<'a, 'chain> {
    fn new(
        child: Option<&'a NameChain<'a, 'chain>>,
        extensions: &Extensions<'chain>,
        self_issued_intermediate: bool,
    ) -> Result<Self, ValidationError> {
        let sans = match (
            self_issued_intermediate,
            extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID),
        ) {
            (false, Some(sans)) => sans.value::<SubjectAlternativeName<'chain>>()?,
            // TODO: there really ought to be a better way to express an empty
            // `asn1::SequenceOf`.
            _ => asn1::parse_single(b"\x30\x00")?,
        };

        Ok(Self { child, sans })
    }

    fn evaluate_single_constraint(
        &self,
        constraint: &GeneralName<'chain>,
        san: &GeneralName<'chain>,
        budget: &mut Budget,
    ) -> Result<ApplyNameConstraintStatus, ValidationError> {
        budget.name_constraint_check()?;

        match (constraint, san) {
            (GeneralName::DNSName(pattern), GeneralName::DNSName(name)) => {
                match (DNSConstraint::new(pattern.0), DNSName::new(name.0)) {
                    (Some(pattern), Some(name)) => Ok(Applied(pattern.matches(&name))),
                    (_, None) => Err(ValidationError::Other(format!(
                        "unsatisfiable DNS name constraint: malformed SAN {}",
                        name.0
                    ))),
                    (None, _) => Err(ValidationError::Other(format!(
                        "malformed DNS name constraint: {}",
                        pattern.0
                    ))),
                }
            }
            (GeneralName::IPAddress(pattern), GeneralName::IPAddress(name)) => {
                match (
                    IPConstraint::from_bytes(pattern),
                    IPAddress::from_bytes(name),
                ) {
                    (Some(pattern), Some(name)) => Ok(Applied(pattern.matches(&name))),
                    (_, None) => Err(ValidationError::Other(format!(
                        "unsatisfiable IP name constraint: malformed SAN {:?}",
                        name,
                    ))),
                    (None, _) => Err(ValidationError::Other(format!(
                        "malformed IP name constraints: {:?}",
                        pattern
                    ))),
                }
            }
            _ => Ok(Skipped),
        }
    }

    fn evaluate_constraints(
        &self,
        constraints: &NameConstraints<'chain>,
        budget: &mut Budget,
    ) -> Result<(), ValidationError> {
        if let Some(child) = self.child {
            child.evaluate_constraints(constraints, budget)?;
        }

        for san in self.sans.clone() {
            // If there are no applicable constraints, the SAN is considered valid so the default is true.
            let mut permit = true;
            if let Some(permitted_subtrees) = &constraints.permitted_subtrees {
                for p in permitted_subtrees.unwrap_read().clone() {
                    let status = self.evaluate_single_constraint(&p.base, &san, budget)?;
                    if status.is_applied() {
                        permit = status.is_match();
                        if permit {
                            break;
                        }
                    }
                }
            }

            if !permit {
                return Err(ValidationError::Other(
                    "no permitted name constraints matched SAN".into(),
                ));
            }

            if let Some(excluded_subtrees) = &constraints.excluded_subtrees {
                for e in excluded_subtrees.unwrap_read().clone() {
                    let status = self.evaluate_single_constraint(&e.base, &san, budget)?;
                    if status.is_match() {
                        return Err(ValidationError::Other(
                            "excluded name constraint matched SAN".into(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

pub type Chain<'c, B> = Vec<VerificationCertificate<'c, B>>;

pub fn verify<'chain, B: CryptoOps>(
    leaf: &VerificationCertificate<'chain, B>,
    intermediates: impl IntoIterator<Item = VerificationCertificate<'chain, B>>,
    policy: &Policy<'_, B>,
    store: &Store<'chain, B>,
) -> Result<Chain<'chain, B>, ValidationError> {
    let builder = ChainBuilder::new(intermediates.into_iter().collect(), policy, store);

    let mut budget = Budget::new();
    builder.build_chain(leaf, &mut budget)
}

struct ChainBuilder<'a, 'chain, B: CryptoOps> {
    intermediates: Vec<VerificationCertificate<'chain, B>>,
    policy: &'a Policy<'a, B>,
    store: &'a Store<'chain, B>,
}

// When applying a name constraint, we need to distinguish between a few different scenarios:
// * `Applied(true)`: The name constraint is the same type as the SAN and matches.
// * `Applied(false)`: The name constraint is the same type as the SAN and does not match.
// * `Skipped`: The name constraint is a different type to the SAN.
enum ApplyNameConstraintStatus {
    Applied(bool),
    Skipped,
}

impl ApplyNameConstraintStatus {
    fn is_applied(&self) -> bool {
        matches!(self, Applied(_))
    }

    fn is_match(&self) -> bool {
        matches!(self, Applied(true))
    }
}

impl<'a, 'chain, B: CryptoOps> ChainBuilder<'a, 'chain, B> {
    fn new(
        intermediates: Vec<VerificationCertificate<'chain, B>>,
        policy: &'a Policy<'a, B>,
        store: &'a Store<'chain, B>,
    ) -> Self {
        Self {
            intermediates,
            policy,
            store,
        }
    }

    /// Identify and return potential issuers for `cert`, considering
    /// candidates from both the trusted store and untrusted intermediate set.
    /// Trusted candidates are returned before untrusted intermediate
    /// candidates, and both groups are opportunisitically ordered by
    /// "likeliness" in terms of AKI/SKI match.
    fn potential_issuers(
        &'a self,
        cert: &'a VerificationCertificate<'chain, B>,
        cert_extensions: &Extensions<'chain>,
    ) -> Vec<&'a VerificationCertificate<'chain, B>> {
        let mut candidates: Vec<&'a VerificationCertificate<'chain, B>> = self
            .store
            .get_by_subject(&cert.certificate().tbs_cert.issuer)
            .iter()
            .chain(self.intermediates.iter().filter(|&candidate| {
                candidate.certificate().subject() == cert.certificate().issuer()
            }))
            .collect();

        let want_kid: Option<&[u8]> = cert_extensions
            .get_extension(&AUTHORITY_KEY_IDENTIFIER_OID)
            .and_then(|ext| ext.value::<AuthorityKeyIdentifier<'_>>().ok())
            .and_then(|aki| aki.key_identifier);

        // This mirrors Go's `findPotentialParents`: we have a global
        // signature budget, so we want to bucket candidates by likeliness
        // to avoid wasting budget on (potentially adversarial) name collisions.
        //
        // Observe that we use a stable sort to preserve trusted candidates
        // before untrusted candidates in each likeliness bucket. In other
        // words, we always try a likely trusted candidate over an equally
        // likely untrusted one.
        //
        // See: <https://github.com/golang/go/blob/d00c67f297e/src/crypto/x509/cert_pool.go#L136>
        candidates.sort_by_key(|candidate| {
            let have_kid: Option<&[u8]> =
                candidate.certificate().extensions().ok().and_then(|exts| {
                    exts.get_extension(&SUBJECT_KEY_IDENTIFIER_OID)
                        .and_then(|ext| ext.value::<&[u8]>().ok())
                });

            match (want_kid, have_kid) {
                // cert AKID matches candidate SKID, highest likelihood.
                (Some(want), Some(have)) if want == have => 0,
                // cert AKID and candidate SKID don't match, lowest likelihood.
                (Some(_), Some(_)) => 2,
                // cert AKID and/or candidate SKID is not present, medium likelihood.
                _ => 1u8,
            }
        });
        candidates
    }

    fn build_chain_inner(
        &self,
        working_cert: &VerificationCertificate<'chain, B>,
        current_depth: u8,
        working_cert_extensions: &Extensions<'chain>,
        name_chain: NameChain<'_, 'chain>,
        budget: &mut Budget,
    ) -> Result<Chain<'chain, B>, ValidationError> {
        if let Some(nc) = working_cert_extensions.get_extension(&NAME_CONSTRAINTS_OID) {
            name_chain.evaluate_constraints(&nc.value()?, budget)?;
        }

        // Look in the store's root set to see if the working cert is listed.
        // If it is, we've reached the end.
        if self.store.contains(working_cert) {
            return Ok(vec![working_cert.clone()]);
        }

        // Check that our current depth does not exceed our policy-configured
        // max depth. We do this after the root set check, since the depth
        // only measures the intermediate chain's length, not the root or leaf.
        if current_depth > self.policy.max_chain_depth {
            return Err(ValidationError::Other(
                "chain construction exceeds max depth".into(),
            ));
        }

        // Otherwise, we collect a list of potential issuers for this cert,
        // and continue with the first that verifies.
        let mut last_err: Option<ValidationError> = None;
        for issuing_cert_candidate in self.potential_issuers(working_cert, working_cert_extensions)
        {
            // A candidate issuer is said to verify if it both
            // signs for the working certificate and conforms to the
            // policy.
            let issuer_extensions = issuing_cert_candidate.certificate().extensions()?;
            match self.policy.valid_issuer(
                issuing_cert_candidate,
                working_cert.certificate(),
                current_depth,
                &issuer_extensions,
                budget,
            ) {
                Ok(_) => {
                    match self.build_chain_inner(
                        issuing_cert_candidate,
                        // NOTE(ww): According to RFC 5280, we should only
                        // increase the chain depth when the certificate is **not**
                        // self-issued. In practice however, implementations widely
                        // ignore this requirement, and unconditionally increment
                        // the depth with every chain member. We choose to do the same;
                        // see `pathlen::self-issued-certs-pathlen` from x509-limbo
                        // for the testcase we intentionally fail.
                        //
                        // Implementation note for someone looking to change this in the future:
                        // care should be taken to avoid infinite recursion with self-signed
                        // certificates in the intermediate set; changing this behavior will
                        // also require a "is not self-signed" check on intermediate candidates.
                        //
                        // See https://gist.github.com/woodruffw/776153088e0df3fc2f0675c5e835f7b8
                        // for an example of this change.
                        current_depth.checked_add(1).ok_or_else(|| {
                            ValidationError::Other(
                                "current depth calculation overflowed".to_string(),
                            )
                        })?,
                        &issuer_extensions,
                        NameChain::new(
                            Some(&name_chain),
                            &issuer_extensions,
                            // Per RFC 5280 4.2.1.10: Name constraints are not applied
                            // to subjects in self-issued certificates, *unless* the
                            // certificate is the "final" (i.e., leaf) certificate in the path.
                            // We accomplish this by only collecting the SANs when the issuing
                            // candidate (which is a non-leaf by definition) isn't self-issued.
                            cert_is_self_issued(issuing_cert_candidate.certificate()),
                        )?,
                        budget,
                    ) {
                        Ok(mut chain) => {
                            chain.push(working_cert.clone());
                            return Ok(chain);
                        }
                        // Immediately return on fatal error.
                        Err(e @ ValidationError::FatalError(..)) => return Err(e),
                        Err(e) => last_err = Some(e),
                    };
                }
                Err(e) => last_err = Some(e),
            };
        }

        // We only reach this if we fail to hit our base case above, or if
        // a chain building step fails to find a next valid certificate.
        Err(ValidationError::CandidatesExhausted(last_err.map_or_else(
            || {
                Box::new(ValidationError::Other(
                    "all candidates exhausted with no interior errors".to_string(),
                ))
            },
            |e| match e {
                // Avoid spamming the user with nested `CandidatesExhausted` errors.
                ValidationError::CandidatesExhausted(e) => e,
                _ => Box::new(e),
            },
        )))
    }

    fn build_chain(
        &self,
        leaf: &VerificationCertificate<'chain, B>,
        budget: &mut Budget,
    ) -> Result<Chain<'chain, B>, ValidationError> {
        // Before anything else, check whether the given leaf cert
        // is well-formed according to our policy (and its underlying
        // certificate profile).
        //
        // The leaf must be an EE; a CA cert in the leaf position will be rejected.
        let leaf_extensions = leaf.certificate().extensions()?;

        self.policy
            .permits_ee(leaf.certificate(), &leaf_extensions)?;

        let mut chain = self.build_chain_inner(
            leaf,
            0,
            &leaf_extensions,
            NameChain::new(None, &leaf_extensions, false)?,
            budget,
        )?;
        // We build the chain in reverse order, fix it now.
        chain.reverse();
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use cryptography_x509::certificate::Certificate;

    use crate::ops::{CryptoOps, VerificationCertificate};
    use crate::policy::{Policy, Subject};
    use crate::trust_store::Store;
    use crate::types::DNSName;
    use crate::{Budget, ChainBuilder, NameChain, ValidationError};

    /// A `CryptoOps` whose public key extraction and signature verification
    /// always succeed, so that `valid_issuer` can be driven to completion
    /// without real cryptographic material.
    struct NullOps;

    impl CryptoOps for NullOps {
        type Key = ();
        type Err = ();
        type CertificateExtra = ();

        fn public_key(&self, _cert: &Certificate<'_>) -> Result<Self::Key, Self::Err> {
            Ok(())
        }

        fn verify_signed_by(
            &self,
            _cert: &Certificate<'_>,
            _key: &Self::Key,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    // A self-issued ("looping") CA certificate that is its own issuer.
    fn looping_ca_pem() -> pem::Pem {
        pem::parse(
            "-----BEGIN CERTIFICATE-----
MIIBcjCCARmgAwIBAgIBATAKBggqhkjOPQQDAjAhMR8wHQYDVQQDDBZsb29waW5n
IHNlbGYtc2lnbmVkIENBMB4XDTIzMTIzMTAwMDAwMFoXDTI0MDEzMTAwMDAwMFow
ITEfMB0GA1UEAwwWbG9vcGluZyBzZWxmLXNpZ25lZCBDQTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABKAoXUGnHdfXJbSXjRjeW+PCVHmlo4KEki69N5pJUA0QyQMR
v9ySOMnWf3Ea7TR4g3zdguwTP7LdpSku3uR1QkmjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBR23MGdG1Ma9iR+3CxKTafD/OE0
dTAKBggqhkjOPQQDAgNHADBEAiA4RCr07KfZdM16VfGNZAQFjvC60SWIU3RRVY/L
qolIOwIgCaIgj9ipK0Q0p+45UJiq+L/ncrxsweJkFq/UYubzhX0=
-----END CERTIFICATE-----",
        )
        .unwrap()
    }

    /// Exercises our pathlen overflow error scenario.
    ///
    /// This condition is logically unreachable from Python, since
    /// we unconditionally limit signature checks to a number smaller
    /// than `u8::MAX`, meaning that we always exhaust the signature budget
    /// before potentially exhausting the pathlen budget.
    ///
    /// To test that directly, we manually lift the signature budget
    /// and start our pathlen state right at `u8::MAX`, guaranteeing
    /// an overflow on the immediate chain building step.
    #[test]
    fn test_build_chain_inner_depth_overflow() {
        let pem = looping_ca_pem();
        let ca = asn1::parse_single::<Certificate<'_>>(pem.contents()).unwrap();
        let ca_exts = ca.extensions().ok().unwrap();

        // The same self-issued CA is both the working certificate and its own
        // (only) candidate issuer, so the search recurses on itself.
        let working = VerificationCertificate::<'_, NullOps>::new(ca.clone(), ());
        let intermediates = vec![VerificationCertificate::<'_, NullOps>::new(ca.clone(), ())];
        let store: Store<'_, NullOps> = Store::new([]);

        let subject = Subject::DNS(DNSName::new("example.com").unwrap());
        let time = asn1::DateTime::new(2024, 1, 1, 0, 0, 0).unwrap();
        let policy = Policy::new(NullOps, subject, time, Some(u8::MAX));

        let builder = ChainBuilder::new(intermediates, &policy, &store);
        let mut budget = Budget {
            name_constraint_checks: usize::MAX,
            signature_checks: usize::MAX,
        };

        let name_chain = NameChain::new(None, &ca_exts, false).ok().unwrap();
        // NOTE: `Result::unwrap_err` would require `Chain` (and therefore
        // `VerificationCertificate`) to be `Debug`, which it isn't.
        let err = match builder.build_chain_inner(
            &working,
            u8::MAX,
            &ca_exts,
            name_chain,
            &mut budget,
        ) {
            Ok(_) => panic!("chain building unexpectedly succeeded"),
            Err(e) => e,
        };

        assert!(matches!(
            err,
            ValidationError::Other(ref msg)
                if msg.contains("current depth calculation overflowed")
        ));
    }
}
