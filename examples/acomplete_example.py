#!/usr/bin/env python3
"""
Complete asynchronous example demonstrating all features of the Async Certificate Lifecycle Manager.

Run with: python acomplete_example.py
"""

import asyncio
import logging
from pathlib import Path
from datetime import datetime, UTC

from cryptography import x509
from cryptography.x509.oid import NameOID

from tiny_ca import (
    CertificateFactory,
    CAFileLoader,
    CertType,
    CAConfig,
    ClientConfig,
)
from tiny_ca.db.async_db_manager import AsyncDBHandler
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.exc import ValidationCertError, CertNotFound, NotUniqueCertOwner
from tiny_ca.db.const import CertificateStatus, RevokeStatus

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def print_section(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_cert_details(cert: x509.Certificate, title: str = "Certificate"):
    """Print detailed certificate information."""
    print(f"\n  {title}:")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Issuer: {cert.issuer.rfc4514_string()}")
    print(f"    Serial: {cert.serial_number}")
    print(f"    Valid from: {cert.not_valid_before_utc}")
    print(f"    Valid to: {cert.not_valid_after_utc}")

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        print(f"    Common Name: {cn_attrs[0].value}")


class AsyncCertificateManagerDemo:
    """Asynchronous demonstration class for Certificate Lifecycle Manager features."""

    def __init__(self, db_path: str = "sqlite+aiosqlite:///async_demo_ca.db"):
        self.db_path = db_path
        self.manager = None
        self.factory = None
        self.ca_cert_path = None
        self.ca_key_path = None
        self.db_handler = None

    async def setup(self):
        """Initialize the certificate manager."""
        print_section("1. INITIALIZATION")

        # Create async database handler
        self.db_handler = AsyncDBHandler(db_url=self.db_path, logger=logger)
        await self.db_handler._db.init_db()
        print(f"  ✓ Async database handler created: {self.db_path}")

        # Create async lifecycle manager
        self.manager = AsyncCertLifecycleManager(
            db_handler=self.db_handler, logger=logger
        )
        print("  ✓ Async Certificate Lifecycle Manager created")

        return self

    async def create_root_ca(self):
        """Create a self-signed root CA certificate."""
        print_section("2. CREATE ROOT CA")

        ca_config = CAConfig(
            common_name="Async Demo Root CA",
            organization="Async Demo Org",
            country="US",
            key_size=4096,
            days_valid=3650,
        )

        print(f"  Creating CA with:")
        print(f"    CN: {ca_config.common_name}")
        print(f"    Organization: {ca_config.organization}")
        print(f"    Key size: {ca_config.key_size} bits")

        # Create self-signed CA
        self.ca_cert_path, self.ca_key_path = await self.manager.create_self_signed_ca(
            config=ca_config,
            cert_path="async_ca",
            is_overwrite=True,
        )

        print(f"\n  ✓ CA created successfully:")
        print(f"    Certificate: {self.ca_cert_path}")
        print(f"    Private key: {self.ca_key_path}")

        # Load CA into factory
        self.factory = CertificateFactory(
            ca_loader=CAFileLoader(
                ca_cert_path=self.ca_cert_path,
                ca_key_path=self.ca_key_path,
                logger=logger,
            ),
            logger=logger,
        )
        self.manager.factory = self.factory
        print("  ✓ Certificate Factory initialized with CA")

        return self

    async def issue_server_certificate(self):
        """Issue a server certificate."""
        print_section("3. ISSUE SERVER CERTIFICATE")

        server_config = ClientConfig(
            common_name="api.async-demo.com",
            email="admin@async-demo.com",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,
            is_server_cert=True,
            is_client_cert=False,
            san_dns=["api.async-demo.com", "www.async-demo.com"],
            san_ip=["127.0.0.1", "10.0.0.1"],
            name="async-api-server",
        )

        print(f"  Issuing server certificate for: {server_config.common_name}")

        cert, private_key, csr = await self.manager.issue_certificate(
            config=server_config,
            cert_path="async_certs/server",
            is_overwrite=True,
        )

        print_cert_details(cert, "Server Certificate")

        # Export to PKCS#12
        p12_bytes = await self.manager.export_pkcs12(
            cert, private_key, password=b"async-password"
        )
        p12_path = Path("async_certs/server/async-api-server.p12")
        p12_path.write_bytes(p12_bytes)
        print(f"  ✓ PKCS#12 bundle saved: {p12_path}")

        return cert, private_key

    async def issue_client_certificate(self):
        """Issue a client certificate."""
        print_section("4. ISSUE CLIENT CERTIFICATE")

        client_config = ClientConfig(
            common_name="alice.smith",
            email="alice@example.com",
            serial_type=CertType.USER,
            key_size=2048,
            days_valid=365,
            is_server_cert=False,
            is_client_cert=True,
            name="alice-client",
        )

        print(f"  Issuing client certificate for: {client_config.common_name}")

        cert, private_key, csr = await self.manager.issue_certificate(
            config=client_config,
            cert_path="async_certs/client",
            is_overwrite=True,
        )

        print_cert_details(cert, "Client Certificate")

        # Export to PKCS#12
        p12_bytes = await self.manager.export_pkcs12(
            cert, private_key, password=b"alice123"
        )
        p12_path = Path("async_certs/client/alice-client.p12")
        p12_path.write_bytes(p12_bytes)
        print(f"  ✓ PKCS#12 bundle saved: {p12_path}")

        return cert

    async def issue_intermediate_ca(self):
        """Issue an intermediate CA certificate."""
        print_section("5. ISSUE INTERMEDIATE CA")

        cert, key = await self.manager.issue_intermediate_ca(
            common_name="Async Intermediate CA",
            key_size=4096,
            days_valid=1825,
            path_length=0,
            organization="Async Sub CA",
            country="US",
            cert_path="async_ca/intermediate",
        )

        print_cert_details(cert, "Intermediate CA Certificate")

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        print(f"    CA: {bc.value.ca}, Path Length: {bc.value.path_length}")

        print(f"  ✓ Intermediate CA issued successfully")

        return cert

    async def list_and_inspect_certificates(self):
        """List and inspect certificates."""
        print_section("6. LIST AND INSPECT CERTIFICATES")

        # List all certificates
        all_certs = await self.manager.list_certificates(limit=20, offset=0)
        print(f"  Total certificates in database: {len(all_certs)}")

        # List by status
        valid_certs = await self.manager.list_certificates(status="valid")
        print(f"  Valid certificates: {len(valid_certs)}")

        # List by type
        service_certs = await self.manager.list_certificates(key_type="service")
        print(f"  Service certificates: {len(service_certs)}")

        # Get expiring soon
        expiring = await self.manager.get_expiring_soon(within_days=30)
        print(f"  Certificates expiring within 30 days: {len(expiring)}")

        # Inspect first certificate
        if valid_certs:
            from cryptography import x509 as crypto_x509

            cert_pem = valid_certs[0].certificate_pem.encode()
            cert = crypto_x509.load_pem_x509_certificate(cert_pem)

            details = await self.manager.inspect_certificate(cert)
            print(f"\n  Certificate Details:")
            print(f"    CN: {details.common_name}")
            print(f"    Serial: {details.serial_number}")
            print(f"    Is CA: {details.is_ca}")
            print(f"    SHA256: {details.fingerprint_sha256[:50]}...")

        return all_certs

    async def check_certificate_status(self, serial: int):
        """Check certificate status."""
        print_section("7. CHECK CERTIFICATE STATUS")

        status = await self.manager.get_certificate_status(serial)

        icons = {
            CertificateStatus.VALID: "✅",
            CertificateStatus.REVOKED: "❌",
            CertificateStatus.EXPIRED: "⚠️",
            CertificateStatus.UNKNOWN: "❓",
        }

        print(
            f"  {icons.get(status, '❓')} Certificate {serial}: {status.value.upper()}"
        )

        return status

    async def revoke_certificate(self, serial: int, reason: x509.ReasonFlags):
        """Revoke a certificate."""
        print_section("8. REVOKE CERTIFICATE")

        print(f"  Revoking certificate: {serial}")
        print(f"    Reason: {reason}")

        success = await self.manager.revoke_certificate(serial=serial, reason=reason)

        if success:
            print(f"  ✓ Certificate {serial} revoked successfully")
        else:
            print(f"  ✗ Failed to revoke certificate {serial}")

        return success

    async def generate_crl(self):
        """Generate CRL."""
        print_section("9. GENERATE CRL")

        crl = await self.manager.generate_crl(days_valid=7)

        print(f"  CRL generated:")
        print(f"    Issuer: {crl.issuer.rfc4514_string()}")
        print(f"    Last Update: {crl.last_update_utc}")
        print(f"    Next Update: {crl.next_update_utc}")
        print(f"    Revoked count: {len(list(crl))}")

        # Verify CRL
        await self.manager.verify_crl(crl)
        print(f"  ✓ CRL signature verified")

        return crl

    async def renew_certificate(self, serial: int):
        """Renew certificate."""
        print_section("10. RENEW CERTIFICATE")

        print(f"  Renewing certificate: {serial}")

        renewed = await self.manager.renew_certificate(
            serial=serial,
            days_valid=365,
        )

        print_cert_details(renewed, "Renewed Certificate")
        print(f"  ✓ Certificate renewed (new serial: {renewed.serial_number})")

        return renewed

    async def cosign_certificate(self, cert: x509.Certificate):
        """Co-sign certificate."""
        print_section("11. CO-SIGN CERTIFICATE")

        print(f"  Co-signing certificate: {cert.serial_number}")

        cosigned = await self.manager.cosign_certificate(
            cert=cert,
            days_valid=180,
        )

        print_cert_details(cosigned, "Co-signed Certificate")
        print(f"  ✓ Certificate co-signed (new serial: {cosigned.serial_number})")

        return cosigned

    async def rotate_certificate(self, serial: int):
        """Rotate certificate."""
        print_section("12. ROTATE CERTIFICATE")

        new_config = ClientConfig(
            common_name="rotated.async-demo.com",
            email="rotated@async-demo.com",
            serial_type=CertType.SERVICE,
            is_server_cert=True,
            san_dns=["rotated.async-demo.com"],
        )

        print(f"  Rotating certificate {serial} → CN: {new_config.common_name}")

        try:
            new_cert, new_key, new_csr = await self.manager.rotate_certificate(
                serial=serial,
                config=new_config,
                cert_path="async_certs/rotated",
            )

            print_cert_details(new_cert, "Rotated Certificate")
            print(f"  ✓ Certificate rotated successfully")

            return new_cert
        except CertNotFound:
            print(f"  ✗ Certificate {serial} not found")
            raise

    async def verify_certificate(self, cert: x509.Certificate) -> bool:
        """Verify certificate."""
        print_section("13. VERIFY CERTIFICATE")

        try:
            is_valid = await self.manager.verify_certificate(cert)
            print(f"  ✅ Certificate is VALID")
            return True
        except ValidationCertError as e:
            print(f"  ❌ Certificate verification FAILED: {e}")
            return False

    async def get_certificate_chain(self, cert: x509.Certificate):
        """Get certificate chain."""
        print_section("14. GET CERTIFICATE CHAIN")

        chain = await self.manager.get_cert_chain(cert)

        print(f"  Chain length: {len(chain)}")
        for i, c in enumerate(chain):
            cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            print(f"    [{i}] {cn[0].value if cn else 'Unknown'}")

        return chain

    async def delete_certificate(self, serial: int):
        """Delete certificate."""
        print_section("15. DELETE CERTIFICATE")

        print(f"  Deleting certificate: {serial}")

        success = await self.manager.delete_certificate(serial=serial)

        if success:
            print(f"  ✓ Certificate {serial} deleted")
        else:
            print(f"  ✗ Certificate {serial} not found")

        return success

    async def refresh_expired_statuses(self):
        """Refresh expired statuses."""
        print_section("16. REFRESH EXPIRED STATUSES")

        count = await self.manager.refresh_expired_statuses()
        print(f"  ✓ Marked {count} certificates as expired")

        return count

    async def cleanup(self):
        """Cleanup."""
        if self.db_handler:
            await self.db_handler._db.engine.dispose()
        print("  ✓ Database connection closed")


async def run_async_demo():
    """Run async demonstration."""
    print("\n" + "🔐" * 35)
    print("  ASYNC CERTIFICATE LIFECYCLE MANAGER - COMPLETE DEMO")
    print("🔐" * 35)

    demo = AsyncCertificateManagerDemo()

    try:
        # Create directories
        Path("async_certs/server").mkdir(parents=True, exist_ok=True)
        Path("async_certs/client").mkdir(parents=True, exist_ok=True)
        Path("async_ca").mkdir(parents=True, exist_ok=True)
        Path("async_ca/intermediate").mkdir(parents=True, exist_ok=True)
        Path("async_certs/rotated").mkdir(parents=True, exist_ok=True)

        # Setup
        await demo.setup()
        await demo.create_root_ca()

        # Issue certificates
        server_cert, _ = await demo.issue_server_certificate()
        client_cert = await demo.issue_client_certificate()
        await demo.issue_intermediate_ca()

        # List and inspect
        await demo.list_and_inspect_certificates()

        # Check status
        await demo.check_certificate_status(server_cert.serial_number)

        # Get chain
        await demo.get_certificate_chain(server_cert)

        # Verify
        await demo.verify_certificate(server_cert)
        await demo.verify_certificate(client_cert)

        # Generate empty CRL
        await demo.generate_crl()

        # Revoke client certificate
        await demo.revoke_certificate(
            serial=client_cert.serial_number, reason=x509.ReasonFlags.key_compromise
        )

        # Generate CRL with revoked entries
        await demo.generate_crl()

        # Check revoked status
        await demo.check_certificate_status(client_cert.serial_number)

        # Renew server certificate
        renewed = await demo.renew_certificate(server_cert.serial_number)

        # Co-sign revoked certificate
        cosigned = await demo.cosign_certificate(client_cert)

        # Rotate certificate
        await demo.rotate_certificate(server_cert.serial_number)

        # Refresh expired
        await demo.refresh_expired_statuses()

        # Verify renewed
        await demo.verify_certificate(renewed)

        # Delete test certificate
        await demo.delete_certificate(client_cert.serial_number)

        # Final CRL
        await demo.generate_crl()

        print_section("DEMO COMPLETED SUCCESSFULLY")

    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        raise
    finally:
        await demo.cleanup()


if __name__ == "__main__":
    asyncio.run(run_async_demo())
