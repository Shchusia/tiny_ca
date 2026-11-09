"""
name_constraints.py

Building and enforcing X.509 NameConstraints (RFC 5280 §4.2.1.10) for DNS
names, IP addresses and e-mail addresses.
"""

from __future__ import annotations

from collections.abc import Callable
import ipaddress
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from tiny_ca.exc import NameConstraintViolation
from tiny_ca.models.certificate import NameConstraintsConfig

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def build_name_constraints(config: NameConstraintsConfig) -> x509.NameConstraints:
    """Translate *config* into a ``NameConstraints`` extension value."""

    def subtrees(dns: list[str], ips: list[Any], emails: list[str]) -> list[Any]:
        return (
            [x509.DNSName(d) for d in dns]
            + [x509.IPAddress(ipaddress.ip_network(str(n))) for n in ips]
            + [x509.RFC822Name(e) for e in emails]
        )

    permitted = subtrees(
        config.permitted_dns, config.permitted_ip, config.permitted_email
    )
    excluded = subtrees(config.excluded_dns, config.excluded_ip, config.excluded_email)
    return x509.NameConstraints(
        permitted_subtrees=permitted or None,
        excluded_subtrees=excluded or None,
    )


def _dns_matches(name: str, constraint: str) -> bool:
    name, constraint = name.lower().rstrip("."), constraint.lower().rstrip(".")
    if not constraint:
        return True
    if constraint.startswith("."):
        return name.endswith(constraint)
    return name == constraint or name.endswith("." + constraint)


def _dns_may_match(name: str, constraint: str) -> bool:
    """
    Like :func:`_dns_matches`, but for a wildcard *name* (``*.base``) also
    True when *any* name the wildcard covers falls inside the subtree — used
    for excluded subtrees so ``*.com`` cannot slip past ``evil.com``.
    """
    # A wildcard whose base lies inside the subtree is caught here as well.
    if _dns_matches(name, constraint):
        return True
    if not name.startswith("*."):
        return False
    base = name[2:].lower().rstrip(".")
    constraint = constraint.lower().rstrip(".")
    # "evil.com" itself is covered by "*.com"; ".evil.com" excludes only
    # sub-domains, which a single-label wildcard over "com" cannot reach.
    return not constraint.startswith(".") and constraint.partition(".")[2] == base


def _email_matches(address: str, constraint: str) -> bool:
    address, constraint = address.lower(), constraint.lower()
    if "@" in constraint:
        return address == constraint
    host = address.rpartition("@")[2]
    if constraint.startswith("."):
        return host.endswith(constraint)
    return host == constraint


def _ip_matches(address: _IPAddress, network: _IPNetwork) -> bool:
    return address.version == network.version and address in network


def _names(
    subject: x509.Name, san: x509.SubjectAlternativeName | None
) -> dict[type, list[Any]]:
    names: dict[type, list[Any]] = {
        x509.DNSName: [],
        x509.IPAddress: [],
        x509.RFC822Name: [],
    }
    if san is not None:
        for kind in names:
            names[kind].extend(san.get_values_for_type(kind))
    names[x509.RFC822Name].extend(
        str(attr.value)
        for attr in subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    )
    return names


_MATCHERS: dict[type, Callable[[Any, Any], bool]] = {
    x509.DNSName: _dns_matches,
    x509.IPAddress: _ip_matches,
    x509.RFC822Name: _email_matches,
}
_EXCLUDED_MATCHERS: dict[type, Callable[[Any, Any], bool]] = {
    **_MATCHERS,
    x509.DNSName: _dns_may_match,
}


def check_name_constraints(
    constraints: x509.NameConstraints,
    subject: x509.Name,
    san: x509.SubjectAlternativeName | None,
    issuer: str,
) -> None:
    """
    Raise ``NameConstraintViolation`` if any DNS / IP / e-mail name of a
    certificate with *subject* and *san* violates *constraints* of *issuer*.

    Subtrees of other types (directoryName, URI, otherName, registeredID)
    cannot be evaluated by this library; NameConstraints is a critical
    extension, so such constraints fail closed (RFC 5280 §4.2).
    """
    unsupported = {
        type(g).__name__
        for g in (constraints.permitted_subtrees or [])
        + (constraints.excluded_subtrees or [])
        if type(g) not in _MATCHERS
    }
    if unsupported:
        raise NameConstraintViolation(
            f"NameConstraints of `{issuer}` use unsupported name types "
            f"({', '.join(sorted(unsupported))}); refusing to validate."
        )
    names = _names(subject, san)
    for kind, matches in _MATCHERS.items():
        permitted = [
            g.value for g in constraints.permitted_subtrees or [] if isinstance(g, kind)
        ]
        excluded = [
            g.value for g in constraints.excluded_subtrees or [] if isinstance(g, kind)
        ]
        for value in names[kind]:
            if permitted and not any(matches(value, c) for c in permitted):
                raise NameConstraintViolation(
                    f"Name `{value}` is outside the permitted subtrees of `{issuer}`."
                )
            if any(_EXCLUDED_MATCHERS[kind](value, c) for c in excluded):
                raise NameConstraintViolation(
                    f"Name `{value}` is in an excluded subtree of `{issuer}`."
                )


def issuer_name_constraints(issuer: x509.Certificate) -> x509.NameConstraints | None:
    """Return *issuer*'s NameConstraints extension value, or ``None``."""
    try:
        return issuer.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None


def subject_alt_name(cert: x509.Certificate) -> x509.SubjectAlternativeName | None:
    """Return *cert*'s SubjectAlternativeName extension value, or ``None``."""
    try:
        return cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return None


def check_certificate(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Enforce *issuer*'s NameConstraints (if any) on *cert*."""
    constraints = issuer_name_constraints(issuer)
    if constraints is not None:
        check_name_constraints(
            constraints,
            cert.subject,
            subject_alt_name(cert),
            issuer.subject.rfc4514_string(),
        )
