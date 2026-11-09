"""
signer_loader.py

CA material provider for CAs whose private key is held by an external signer
(HSM, smart card, KMS) instead of a PEM file.
"""

from __future__ import annotations

from logging import Logger
from pathlib import Path
import secrets
from typing import Protocol, runtime_checkable

from cryptography import x509

from tiny_ca.exc import ErrorLoadCert, SignerError
from tiny_ca.models.certificate import CertificateInfo
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.signing import CASigner, Pkcs11Signer, verify_signature
from tiny_ca.utils.keys import signing_hash

from .file_loader import certificate_info, check_ca_material


@runtime_checkable
class ISignerCALoader(Protocol):
    """
    CA-material provider that signs through a :class:`~tiny_ca.signing.CASigner`
    instead of exposing a private key.  Accepted by ``CertificateFactory``
    wherever an ``ICALoader`` is.
    """

    @property
    def ca_cert(self) -> x509.Certificate: ...

    @property
    def ca_signer(self) -> CASigner: ...

    @property
    def base_info(self) -> CertificateInfo: ...


class SignerCALoader:
    """
    Pairs a CA certificate with an external :class:`~tiny_ca.signing.CASigner`.

    On construction the loader runs the same checks as ``CAFileLoader``
    (the certificate is a CA, the signer's public key matches it, expiry
    warning) and then asks the signer to sign a random challenge, verifying
    the result against the certificate.  A misconfigured token (wrong key
    label, wrong PIN, wrong slot) is therefore detected at start-up rather
    than on the first issuance.

    Parameters
    ----------
    ca_cert : x509.Certificate | str | Path
        The CA certificate, or the path of a PEM file containing it.
    signer : CASigner
        Signer holding the CA private key.
    logger : Logger | None
        Logger for diagnostic messages.  Falls back to ``DEFAULT_LOGGER``.

    Raises
    ------
    ErrorLoadCert
        If the certificate cannot be read or is not a CA matching *signer*.
    SignerError
        If the signer fails the challenge signature.
    """

    def __init__(
        self,
        ca_cert: x509.Certificate | str | Path,
        signer: CASigner,
        logger: Logger | None = None,
    ) -> None:
        self._logger = logger or DEFAULT_LOGGER
        source: str | Path = "<certificate object>"
        if not isinstance(ca_cert, x509.Certificate):
            source = Path(ca_cert)
            try:
                ca_cert = x509.load_pem_x509_certificate(source.read_bytes())
            except Exception as exc:
                raise ErrorLoadCert(path_to_file=source, exc=str(exc)) from exc
        check_ca_material(
            ca_cert, signer.public_key(), source, "<external signer>", self._logger
        )
        self._self_test(ca_cert, signer)
        self._ca_cert = ca_cert
        self._signer = signer
        self._base_info = certificate_info(ca_cert)
        self._logger.info("CA loaded with external signer %s", type(signer).__name__)

    @staticmethod
    def _self_test(ca_cert: x509.Certificate, signer: CASigner) -> None:
        challenge = secrets.token_bytes(32)
        public_key = ca_cert.public_key()
        algorithm = signing_hash(public_key)  # type: ignore[arg-type]
        try:
            signature = signer.sign(challenge, algorithm)
        except Exception as exc:
            raise SignerError(f"signer self-test failed: {exc}") from exc
        if not verify_signature(public_key, signature, challenge, algorithm):  # type: ignore[arg-type]
            raise SignerError(
                "signer self-test failed: signature does not match the CA "
                "certificate"
            )

    @classmethod
    def from_pkcs11(
        cls,
        ca_cert: x509.Certificate | str | Path,
        module_path: str | Path,
        token_label: str,
        pin: str,
        key_label: str | None = None,
        key_id: bytes | None = None,
        logger: Logger | None = None,
    ) -> SignerCALoader:
        """
        Open the CA key on a PKCS#11 token and build the loader.

        Requires ``pip install 'tiny-ca[hsm]'``.  Call
        ``loader.ca_signer.close()`` to end the PKCS#11 session.
        """
        if not isinstance(ca_cert, x509.Certificate):
            cert_path = Path(ca_cert)
            try:
                ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            except Exception as exc:
                raise ErrorLoadCert(path_to_file=cert_path, exc=str(exc)) from exc
        signer = Pkcs11Signer.open(
            module_path=module_path,
            token_label=token_label,
            pin=pin,
            public_key=ca_cert.public_key(),  # type: ignore[arg-type]
            key_label=key_label,
            key_id=key_id,
        )
        try:
            return cls(ca_cert, signer, logger=logger)
        except Exception:
            signer.close()
            raise

    @property
    def ca_cert(self) -> x509.Certificate:
        return self._ca_cert

    @property
    def ca_signer(self) -> CASigner:
        return self._signer

    @property
    def base_info(self) -> CertificateInfo:
        return self._base_info
