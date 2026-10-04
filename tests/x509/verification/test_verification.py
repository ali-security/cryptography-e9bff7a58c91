# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from functools import lru_cache
from ipaddress import IPv4Address

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store
from tests.x509.test_x509 import _load_cert


@lru_cache(maxsize=1)
def dummy_store() -> Store:
    cert = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    return Store([cert])


_NOT_BEFORE = datetime.datetime(2024, 1, 1)
_NOT_AFTER = datetime.datetime(2034, 1, 1)
_VALIDATION_TIME = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)

_CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _ca_cert(
    subject: str,
    issuer: str,
    public_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
    serial: int,
) -> x509.Certificate:
    """
    A CA certificate that satisfies the web PKI profile, so that path
    building rejects it only on its signature.
    """
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(_CA_KEY_USAGE, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .sign(signing_key, hashes.SHA256())
    )


def _leaf_cert(
    issuer: str,
    public_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
    issuer_public_key: ec.EllipticCurvePublicKey,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name("leaf"))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(1)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([DNSName("example.com")]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_public_key
            ),
            critical=False,
        )
        .sign(signing_key, hashes.SHA256())
    )


class TestPolicyBuilder:
    def test_time_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().time(datetime.datetime.now()).time(
                datetime.datetime.now()
            )

    def test_store_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().store(dummy_store()).store(dummy_store())

    def test_max_chain_depth_already_set(self):
        with pytest.raises(ValueError):
            PolicyBuilder().max_chain_depth(8).max_chain_depth(9)

    def test_ipaddress_subject(self):
        policy = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(IPAddress(IPv4Address("0.0.0.0")))
        )
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self):
        policy = (
            PolicyBuilder()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
        )
        assert policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self):
        # Subject must be a supported GeneralName type
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                "cryptography.io"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                "0.0.0.0"  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(
                IPv4Address("0.0.0.0")  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            PolicyBuilder().store(dummy_store()).build_server_verifier(None)  # type: ignore[arg-type]

    def test_builder_pattern(self):
        now = datetime.datetime.now().replace(microsecond=0)
        store = dummy_store()
        max_chain_depth = 16

        builder = PolicyBuilder()
        builder = builder.time(now)
        builder = builder.store(store)
        builder = builder.max_chain_depth(max_chain_depth)

        verifier = builder.build_server_verifier(DNSName("cryptography.io"))
        assert verifier.subject == DNSName("cryptography.io")
        assert verifier.validation_time == now
        assert verifier.store == store
        assert verifier.max_chain_depth == max_chain_depth

    def test_build_server_verifier_missing_store(self):
        with pytest.raises(
            ValueError, match="A server verifier must have a trust store"
        ):
            PolicyBuilder().build_server_verifier(DNSName("cryptography.io"))


class TestStore:
    def test_store_rejects_empty_list(self):
        with pytest.raises(ValueError):
            Store([])

    def test_store_rejects_non_certificates(self):
        with pytest.raises(TypeError):
            Store(["not a cert"])  # type: ignore[list-item]


class TestServerVerifier:
    @pytest.mark.parametrize(
        ("validation_time", "valid"),
        [
            # 03:15:02 UTC+2, or 1 second before expiry in UTC
            ("2018-11-16T03:15:02+02:00", True),
            # 00:15:04 UTC-1, or 1 second after expiry in UTC
            ("2018-11-16T00:15:04-01:00", False),
        ],
    )
    def test_verify_tz_aware(self, validation_time, valid):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        builder = PolicyBuilder().store(store)
        builder = builder.time(
            datetime.datetime.fromisoformat(validation_time)
        )
        verifier = builder.build_server_verifier(DNSName("cryptography.io"))

        if valid:
            assert verifier.verify(leaf, []) == [leaf]
        else:
            with pytest.raises(
                x509.verification.VerificationError,
                match="cert is not valid at validation time",
            ):
                verifier.verify(leaf, [])


class TestServerVerifierSignatureBudget:
    """
    Path building must not perform an unbounded number of signature
    verifications, no matter how many candidate issuers an attacker
    supplies whose subjects collide with the issuer named by the
    certificate under verification.
    """

    def _verifier(self, root: x509.Certificate):
        builder = PolicyBuilder().store(Store([root]))
        builder = builder.time(_VALIDATION_TIME)
        return builder.build_server_verifier(DNSName("example.com"))

    def test_colliding_candidate_issuers_are_bounded(self):
        root_key = _ec_key()
        root = _ca_cert("root", "root", root_key.public_key(), root_key, 1)

        # The leaf names "intermediate" as its issuer, but none of the
        # candidates below actually signed it.
        real_key = _ec_key()
        leaf_key = _ec_key()
        leaf = _leaf_cert(
            "intermediate",
            leaf_key.public_key(),
            real_key,
            real_key.public_key(),
        )

        # Each of these is a well-formed CA whose subject collides with
        # the leaf's issuer, so each one costs a signature verification.
        decoy_key = _ec_key()
        decoys = [
            _ca_cert(
                "intermediate",
                "root",
                decoy_key.public_key(),
                root_key,
                serial,
            )
            for serial in range(2, 202)
        ]

        with pytest.raises(
            x509.verification.VerificationError,
            match="Exceeded maximum signature check limit",
        ):
            self._verifier(root).verify(leaf, decoys)

    def test_exponential_candidate_paths_are_bounded(self):
        root_key = _ec_key()
        root = _ca_cert("root", "root", root_key.public_key(), root_key, 1)

        # A ladder of untrusted CAs: every level names the next level as
        # its issuer and every level has several interchangeable
        # candidates, so a naive search explores 3**9 candidate paths,
        # each one costing a signature verification.
        levels = 9
        width = 3
        keys = [_ec_key() for _ in range(levels + 1)]
        intermediates = [
            _ca_cert(
                f"ca-{level}",
                f"ca-{level + 1}",
                keys[level - 1].public_key(),
                keys[level],
                level * 100 + index + 1,
            )
            for level in range(1, levels + 1)
            for index in range(width)
        ]

        leaf_key = _ec_key()
        leaf = _leaf_cert(
            "ca-1",
            leaf_key.public_key(),
            keys[0],
            keys[0].public_key(),
        )

        with pytest.raises(
            x509.verification.VerificationError,
            match="Exceeded maximum signature check limit",
        ):
            self._verifier(root).verify(leaf, intermediates)

    def test_key_identifier_match_is_tried_first(self):
        root_key = _ec_key()
        root = _ca_cert("root", "root", root_key.public_key(), root_key, 1)

        intermediate_key = _ec_key()
        intermediate = _ca_cert(
            "intermediate",
            "root",
            intermediate_key.public_key(),
            root_key,
            2,
        )

        leaf_key = _ec_key()
        leaf = _leaf_cert(
            "intermediate",
            leaf_key.public_key(),
            intermediate_key,
            intermediate_key.public_key(),
        )

        decoy_key = _ec_key()
        decoys = [
            _ca_cert(
                "intermediate",
                "root",
                decoy_key.public_key(),
                root_key,
                serial,
            )
            for serial in range(3, 203)
        ]

        # The genuine issuer is last in the candidate list, but its
        # subject key identifier matches the leaf's authority key
        # identifier, so it is tried before the name collisions and the
        # signature budget is never exhausted.
        chain = self._verifier(root).verify(leaf, [*decoys, intermediate])
        assert chain == [leaf, intermediate, root]
