"""CertificatePolicies and NameConstraints (1.0.0)."""

from __future__ import annotations

import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from pydantic import ValidationError
import pytest

from tiny_ca import CertificateFactory, NameConstraintsConfig
from tiny_ca.ca_factory.utils.file_loader import certificate_info
from tiny_ca.ca_factory.utils.name_constraints import (
    _dns_matches,
    _dns_may_match,
    _email_matches,
    _ip_matches,
    build_name_constraints,
    check_certificate,
    check_name_constraints,
)
from tiny_ca.exc import NameConstraintViolation
from tiny_ca.utils.keys import generate_private_key, signing_hash

POLICY = "1.3.6.1.4.1.55555.1.1"
OTHER_POLICY = "1.3.6.1.4.1.55555.9.9"
CPS = "https://pki.example.com/cps"


class _Loader:
    def __init__(self, cert, key):
        self.ca_cert = cert
        self.ca_key = key
        self.base_info = certificate_info(cert)


@pytest.fixture(scope="module")
def root():
    return CertificateFactory.build_self_signed_ca(common_name="Root")


def _factory(cert_key, **kw) -> CertificateFactory:
    return CertificateFactory(_Loader(*cert_key), **kw)


def _policies(cert):
    return cert.extensions.get_extension_for_class(x509.CertificatePolicies)


CONSTRAINTS = NameConstraintsConfig(
    permitted_dns=["example.com"],
    excluded_dns=["secret.example.com"],
    permitted_ip=["10.0.0.0/8"],
    permitted_email=["example.com"],
)


@pytest.fixture(scope="module")
def sub(root):
    """An intermediate CA constrained to example.com / 10/8."""
    return _factory(root).issue_intermediate_ca(
        "Sub", path_length=0, name_constraints=CONSTRAINTS
    )


def _forge_leaf(issuer_cert, issuer_key, dns=(), email=None):
    """Sign a leaf directly with *issuer_key*, bypassing factory checks."""
    key = generate_private_key()
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "forged")]
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(attrs))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
    )
    if dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]), False
        )
    return builder.sign(issuer_key, signing_hash(issuer_key))


# ---------------------------------------------------------------------------
# CertificatePolicies
# ---------------------------------------------------------------------------


def test_policies_in_leaf_intermediate_and_renewal(root):
    factory = _factory(root, certificate_policies=[POLICY], cps_uri=CPS)
    leaf, _, _ = factory.issue_certificate("svc", is_server_cert=True)
    ext = _policies(leaf)
    assert not ext.critical
    (info,) = ext.value
    assert info.policy_identifier.dotted_string == POLICY
    assert info.policy_qualifiers == [CPS]

    inter, _ = factory.issue_intermediate_ca("Policy Sub")
    assert _policies(inter).value[0].policy_identifier.dotted_string == POLICY

    renewed = factory.renew_certificate(leaf)
    assert _policies(renewed).value == ext.value


def test_resign_replaces_foreign_policies(root):
    foreign, _, _ = _factory(
        root, certificate_policies=[OTHER_POLICY]
    ).issue_certificate("x")
    renewed = _factory(root, certificate_policies=[POLICY]).renew_certificate(foreign)
    oids = [p.policy_identifier.dotted_string for p in _policies(renewed).value]
    assert oids == [POLICY]


def test_resign_keeps_policies_when_none_configured(root):
    leaf, _, _ = _factory(root, certificate_policies=[OTHER_POLICY]).issue_certificate(
        "x"
    )
    renewed = _factory(root).renew_certificate(leaf)
    assert _policies(renewed).value == _policies(leaf).value


def test_policy_without_cps_has_no_qualifiers(root):
    leaf, _, _ = _factory(root, certificate_policies=[POLICY]).issue_certificate("x")
    assert _policies(leaf).value[0].policy_qualifiers is None


def test_no_policies_by_default(root):
    leaf, _, _ = _factory(root).issue_certificate("x")
    with pytest.raises(x509.ExtensionNotFound):
        _policies(leaf)


def test_cps_requires_policy(root):
    with pytest.raises(ValueError, match="cps_uri"):
        _factory(root, cps_uri=CPS)


def test_bad_policy_oid(root):
    with pytest.raises(ValueError):
        _factory(root, certificate_policies=["not-an-oid"])


# ---------------------------------------------------------------------------
# NameConstraints: building
# ---------------------------------------------------------------------------


def test_config_requires_a_subtree():
    with pytest.raises(ValidationError, match="at least one"):
        NameConstraintsConfig()


def test_build_name_constraints():
    nc = build_name_constraints(
        NameConstraintsConfig(
            permitted_dns=["example.com"],
            permitted_ip=["192.168.0.0/16"],
            excluded_email=["evil.com"],
        )
    )
    assert nc.permitted_subtrees == [
        x509.DNSName("example.com"),
        x509.IPAddress(ipaddress.ip_network("192.168.0.0/16")),
    ]
    assert nc.excluded_subtrees == [x509.RFC822Name("evil.com")]

    only_excluded = build_name_constraints(NameConstraintsConfig(excluded_dns=["a"]))
    assert only_excluded.permitted_subtrees is None


def test_intermediate_carries_critical_name_constraints(sub):
    cert, _ = sub
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
    assert ext.critical
    assert x509.DNSName("example.com") in ext.value.permitted_subtrees


# ---------------------------------------------------------------------------
# NameConstraints: matching rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "constraint", "expected"),
    [
        ("example.com", "example.com", True),
        ("a.b.Example.COM", "example.com", True),
        ("example.com.", "example.com", True),
        ("badexample.com", "example.com", False),
        ("example.com", ".example.com", False),
        ("www.example.com", ".example.com", True),
        ("anything.org", "", True),
    ],
)
def test_dns_matching(name, constraint, expected):
    assert _dns_matches(name, constraint) is expected


@pytest.mark.parametrize(
    ("address", "constraint", "expected"),
    [
        ("Alice@Example.com", "alice@example.com", True),
        ("bob@example.com", "alice@example.com", False),
        ("bob@example.com", "example.com", True),
        ("bob@mail.example.com", "example.com", False),
        ("bob@mail.example.com", ".example.com", True),
        ("bob@example.com", ".example.com", False),
    ],
)
def test_email_matching(address, constraint, expected):
    assert _email_matches(address, constraint) is expected


def test_ip_matching():
    net = ipaddress.ip_network("10.0.0.0/8")
    assert _ip_matches(ipaddress.ip_address("10.1.2.3"), net)
    assert not _ip_matches(ipaddress.ip_address("11.0.0.1"), net)
    assert not _ip_matches(ipaddress.ip_address("::1"), net)


# ---------------------------------------------------------------------------
# NameConstraints: enforcement at issuance
# ---------------------------------------------------------------------------


def test_constrained_ca_issues_permitted_names(sub):
    factory = _factory(sub)
    cert, _, _ = factory.issue_certificate(
        "www.example.com",
        is_server_cert=True,
        san_ip=["10.0.0.5"],
        email="ops@example.com",
    )
    check_certificate(cert, sub[0])
    # A certificate without any constrained name types is unaffected.
    factory.issue_certificate("plain client", is_client_cert=True)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"common_name": "www.other.org", "is_server_cert": True},
        {"common_name": "secret.example.com", "is_server_cert": True},
        {"common_name": "svc", "san_ip": ["192.168.1.1"]},
        {"common_name": "svc", "email": "ops@other.org"},
    ],
)
def test_constrained_ca_refuses_forbidden_names(sub, kwargs):
    with pytest.raises(NameConstraintViolation):
        _factory(sub).issue_certificate(**kwargs)


def test_renew_and_cosign_refuse_forbidden_names(root, sub):
    outsider, _, _ = _factory(root).issue_certificate("evil.org", is_server_cert=True)
    factory = _factory(sub)
    with pytest.raises(NameConstraintViolation, match="evil.org"):
        factory.renew_certificate(outsider)
    with pytest.raises(NameConstraintViolation):
        factory.cosign_certificate(outsider)


# ---------------------------------------------------------------------------
# NameConstraints: enforcement in validate_chain
# ---------------------------------------------------------------------------


def test_validate_chain_through_constrained_intermediate(root, sub):
    sub_cert, sub_key = sub
    good = _forge_leaf(sub_cert, sub_key, dns=["api.example.com"])
    path = _factory(root).validate_chain(good, [sub_cert])
    assert path[1] == sub_cert

    bad = _forge_leaf(sub_cert, sub_key, dns=["api.example.net"])
    with pytest.raises(NameConstraintViolation, match="permitted"):
        _factory(root).validate_chain(bad, [sub_cert])

    mail = _forge_leaf(sub_cert, sub_key, email="x@mail.example.com")
    with pytest.raises(NameConstraintViolation, match="x@mail.example.com"):
        _factory(root).validate_chain(mail, [sub_cert])

    excluded_dns = _forge_leaf(sub_cert, sub_key, dns=["db.secret.example.com"])
    with pytest.raises(NameConstraintViolation, match="excluded"):
        _factory(root).validate_chain(excluded_dns, [sub_cert])


def test_validate_chain_when_trust_anchor_is_constrained(sub):
    sub_cert, sub_key = sub
    bad = _forge_leaf(sub_cert, sub_key, dns=["www.other.org"])
    with pytest.raises(NameConstraintViolation):
        _factory(sub).validate_chain(bad)


@pytest.mark.parametrize(
    ("name", "constraint", "expected"),
    [
        ("*.com", "evil.com", True),
        ("*.com", ".evil.com", False),
        ("*.a.evil.com", ".evil.com", True),
        ("*.com", "a.evil.com", False),
        ("*.org", "evil.com", False),
        ("x.com", "evil.com", False),
    ],
)
def test_wildcard_against_excluded_subtrees(name, constraint, expected):
    assert _dns_may_match(name, constraint) is expected


def test_wildcard_cannot_slip_past_exclusion():
    constraints = build_name_constraints(
        NameConstraintsConfig(excluded_dns=["evil.com"])
    )
    san = x509.SubjectAlternativeName([x509.DNSName("*.com")])
    with pytest.raises(NameConstraintViolation, match="excluded"):
        check_name_constraints(constraints, x509.Name([]), san, "CN=Sub")


@pytest.mark.parametrize(
    "subtree",
    [
        x509.UniformResourceIdentifier(".corp.example"),
        x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corp")])
        ),
    ],
)
def test_unsupported_constraint_types_fail_closed(subtree):
    constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("example.com"), subtree],
        excluded_subtrees=None,
    )
    with pytest.raises(NameConstraintViolation, match="unsupported name types"):
        check_name_constraints(constraints, x509.Name([]), None, "CN=Foreign")
