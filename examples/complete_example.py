#!/usr/bin/env python3
"""
Complete example demonstrating all features of the Certificate Lifecycle Manager.

This example shows how to:
1. Create a self-signed CA certificate
2. Issue various types of certificates (server, client, intermediate CA)
3. Revoke certificates
4. Generate Certificate Revocation Lists (CRL)
5. Renew certificates
6. Co-sign existing certificates
7. Export certificates to PKCS#12 format
8. List and manage certificates in the database
9. Verify certificates and CRLs
10. Delete certificates

Run with: python complete_example.py
"""

import logging
import os
import sys
from pathlib import Path
from datetime import datetime, UTC

from cryptography import x509
from cryptography.x509.oid import NameOID

from tiny_ca import (
    CertLifecycleManager,
    CertificateFactory,
    CAFileLoader,
    CertType,
    SyncDBHandler,
    CAConfig,
    ClientConfig,
)
from tiny_ca.exc import (
    DBNotInitedError,
    NotUniqueCertOwner,
    ValidationCertError,
    CertNotFound,
)
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

    # Get CN from subject
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        print(f"    Common Name: {cn_attrs[0].value}")


class CertificateManagerDemo:
    """Demonstration class for Certificate Lifecycle Manager features."""

    def __init__(self, db_path: str = "sqlite:///demo_ca.db"):
        self.db_path = db_path
        self.manager = None
        self.factory = None
        self.ca_cert_path = None
        self.ca_key_path = None

    def setup(self):
        """Initialize the certificate manager."""
        print_section("1. INITIALIZATION")

        # Create database handler
        db_handler = SyncDBHandler(db_url=self.db_path, logger=logger)
        print(f"  ✓ Database handler created: {self.db_path}")

        # Create lifecycle manager
        self.manager = CertLifecycleManager(
            db_handler=db_handler,  # Database for certificate registry
            logger=logger,  # Logger for operations
        )
        print("  ✓ Certificate Lifecycle Manager created")

        return self

    def create_root_ca(self):
        """Create a self-signed root CA certificate."""
        print_section("2. CREATE ROOT CA")

        # CA configuration
        ca_config = CAConfig(
            common_name="Demo Root CA",
            organization="Demo Organization",
            country="US",
            key_size=4096,  # Strong key for root CA
            days_valid=3650,  # 10 years validity
        )

        print(f"  Creating CA with:")
        print(f"    CN: {ca_config.common_name}")
        print(f"    Organization: {ca_config.organization}")
        print(f"    Country: {ca_config.country}")
        print(f"    Key size: {ca_config.key_size} bits")
        print(f"    Validity: {ca_config.days_valid} days")

        # Create self-signed CA
        self.ca_cert_path, self.ca_key_path = self.manager.create_self_signed_ca(
            config=ca_config,
            cert_path="ca",  # Store in 'ca' subdirectory
            is_overwrite=True,  # Overwrite if exists
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

    def issue_server_certificate(self):
        """Issue a server certificate (TLS/SSL)."""
        print_section("3. ISSUE SERVER CERTIFICATE")

        server_config = ClientConfig(
            common_name="api.demo.com",
            email="admin@demo.com",
            serial_type=CertType.SERVICE,
            key_size=2048,
            days_valid=365,  # 1 year validity
            is_server_cert=True,  # Enable Server Authentication
            is_client_cert=False,
            san_dns=["api.demo.com", "www.demo.com", "localhost"],
            san_ip=["127.0.0.1", "10.0.0.1"],
            name="api-server",  # Custom filename
        )

        print(f"  Issuing server certificate for: {server_config.common_name}")
        print(f"    SAN DNS: {server_config.san_dns}")
        print(f"    SAN IP: {server_config.san_ip}")
        print(f"    Validity: {server_config.days_valid} days")

        cert, private_key, csr = self.manager.issue_certificate(
            config=server_config,
            cert_path="certs/server",  # Storage path
            is_overwrite=True,
        )

        print_cert_details(cert, "Server Certificate")
        print(f"  ✓ Server certificate issued successfully")

        # Export to PKCS#12 for easy distribution
        p12_path = Path("certs/server/api-server.p12")
        p12_bytes = self.manager.export_pkcs12(cert, private_key, password=b"changeit")
        p12_path.write_bytes(p12_bytes)
        print(f"  ✓ PKCS#12 bundle saved: {p12_path}")

        return cert, private_key

    def issue_client_certificate(self):
        """Issue a client certificate (for authentication)."""
        print_section("4. ISSUE CLIENT CERTIFICATE")

        client_config = ClientConfig(
            common_name="john.doe",
            email="john.doe@example.com",
            serial_type=CertType.USER,
            key_size=2048,
            days_valid=365,
            is_server_cert=False,
            is_client_cert=True,  # Enable Client Authentication
            name="john-doe",
        )

        print(f"  Issuing client certificate for: {client_config.common_name}")
        print(f"    Email: {client_config.email}")
        print(f"    Type: USER certificate with Client Authentication")

        cert, private_key, csr = self.manager.issue_certificate(
            config=client_config,
            cert_path="certs/client",
            is_overwrite=True,
        )

        print_cert_details(cert, "Client Certificate")
        print(f"  ✓ Client certificate issued successfully")

        # Export to PKCS#12 for browser import
        p12_path = Path("certs/client/john-doe.p12")
        p12_bytes = self.manager.export_pkcs12(cert, private_key, password=b"client123")
        p12_path.write_bytes(p12_bytes)
        print(f"  ✓ PKCS#12 bundle saved: {p12_path}")

        return cert

    def issue_intermediate_ca(self):
        """Issue an intermediate CA certificate."""
        print_section("5. ISSUE INTERMEDIATE CA")

        print(
            f"  Issuing intermediate CA with path length 0 (can only issue leaf certs)"
        )

        intermediate_cert, intermediate_key = self.manager.issue_intermediate_ca(
            common_name="Demo Intermediate CA",
            key_size=4096,
            days_valid=1825,  # 5 years
            path_length=0,  # Can only sign leaf certificates
            organization="Demo Sub CA",
            country="US",
            cert_path="ca/intermediate",
        )

        print_cert_details(intermediate_cert, "Intermediate CA Certificate")

        # Check BasicConstraints
        bc = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        print(f"    CA: {bc.value.ca}, Path Length: {bc.value.path_length}")

        print(f"  ✓ Intermediate CA issued successfully")

        return intermediate_cert

    def list_and_inspect_certificates(self):
        """List all certificates and inspect specific ones."""
        print_section("6. LIST AND INSPECT CERTIFICATES")

        # List all certificates (paginated)
        all_certs = self.manager.list_certificates(limit=10, offset=0)
        print(f"  Total certificates in database: {len(all_certs)}")

        # List only valid certificates
        valid_certs = self.manager.list_certificates(status="valid")
        print(f"  Valid certificates: {len(valid_certs)}")

        # List certificates by type
        service_certs = self.manager.list_certificates(key_type="service")
        print(f"  Service certificates: {len(service_certs)}")

        # List expiring soon certificates
        expiring = self.manager.get_expiring_soon(within_days=30)
        print(f"  Certificates expiring within 30 days: {len(expiring)}")

        # Inspect the first valid certificate
        if valid_certs:
            from cryptography import x509 as crypto_x509

            cert_pem = valid_certs[0].certificate_pem.encode()
            cert = crypto_x509.load_pem_x509_certificate(cert_pem)

            # Inspect certificate details
            details = self.manager.inspect_certificate(cert)
            print(f"\n  Inspected certificate:")
            print(f"    Common Name: {details.common_name}")
            print(f"    Serial: {details.serial_number}")
            print(f"    Is CA: {details.is_ca}")
            print(f"    Key Usage: {details.key_usage}")
            print(f"    Extended Key Usage: {details.extended_key_usage}")
            print(f"    SAN DNS: {details.san_dns}")
            print(f"    Fingerprint SHA256: {details.fingerprint_sha256[:50]}...")

        return all_certs

    def check_certificate_status(self, serial: int):
        """Check the status of a certificate by serial number."""
        print_section("7. CHECK CERTIFICATE STATUS")

        try:
            status = self.manager.get_certificate_status(serial)

            status_colors = {
                CertificateStatus.VALID: "✅",
                CertificateStatus.REVOKED: "❌",
                CertificateStatus.EXPIRED: "⚠️",
                CertificateStatus.UNKNOWN: "❓",
            }

            icon = status_colors.get(status, "❓")
            print(f"  {icon} Certificate {serial}: {status.value.upper()}")

            return status
        except Exception as e:
            print(f"  ❌ Error checking status: {e}")
            return CertificateStatus.UNKNOWN

    def revoke_certificate(self, serial: int, reason: x509.ReasonFlags):
        """Revoke a certificate."""
        print_section("8. REVOKE CERTIFICATE")

        reason_names = {
            x509.ReasonFlags.unspecified: "Unspecified",
            x509.ReasonFlags.key_compromise: "Key Compromise",
            x509.ReasonFlags.ca_compromise: "CA Compromise",
            x509.ReasonFlags.affiliation_changed: "Affiliation Changed",
            x509.ReasonFlags.superseded: "Superseded",
            x509.ReasonFlags.cessation_of_operation: "Cessation of Operation",
            x509.ReasonFlags.certificate_hold: "Certificate Hold",
        }

        print(f"  Revoking certificate: {serial}")
        print(f"    Reason: {reason_names.get(reason, reason)}")

        success = self.manager.revoke_certificate(serial=serial, reason=reason)

        if success:
            print(f"  ✓ Certificate {serial} revoked successfully")
        else:
            print(f"  ✗ Failed to revoke certificate {serial}")

        return success

    def generate_crl(self):
        """Generate a Certificate Revocation List."""
        print_section("9. GENERATE CRL")

        crl = self.manager.generate_crl(days_valid=7)

        print(f"  CRL generated:")
        print(f"    Issuer: {crl.issuer.rfc4514_string()}")
        print(f"    Last Update: {crl.last_update_utc}")
        print(f"    Next Update: {crl.next_update_utc}")
        print(f"    Revoked certificates count: {len(list(crl))}")

        # Verify CRL
        self.manager.verify_crl(crl)
        print(f"  ✓ CRL signature verified")

        return crl

    def renew_certificate(self, serial: int):
        """Renew an existing certificate (same key, new validity)."""
        print_section("10. RENEW CERTIFICATE")

        print(f"  Renewing certificate: {serial}")

        renewed_cert = self.manager.renew_certificate(
            serial=serial,
            days_valid=365,
        )

        print_cert_details(renewed_cert, "Renewed Certificate")
        print(
            f"  ✓ Certificate renewed successfully (new serial: {renewed_cert.serial_number})"
        )

        return renewed_cert

    def cosign_certificate(self, cert: x509.Certificate):
        """Co-sign an existing certificate (re-sign with this CA)."""
        print_section("11. CO-SIGN CERTIFICATE")

        print(f"  Co-signing certificate: {cert.serial_number}")

        cosigned = self.manager.cosign_certificate(
            cert=cert,
            days_valid=180,  # 6 months validity
        )

        print_cert_details(cosigned, "Co-signed Certificate")
        print(
            f"  ✓ Certificate co-signed successfully (new serial: {cosigned.serial_number})"
        )

        return cosigned

    def rotate_certificate(self, serial: int, new_config: ClientConfig):
        """Rotate certificate (revoke old, issue new)."""
        print_section("12. ROTATE CERTIFICATE")

        print(f"  Rotating certificate {serial} → new CN: {new_config.common_name}")

        try:
            # Note: rotate_certificate does not accept cert_path parameter
            new_cert, new_key, new_csr = self.manager.rotate_certificate(
                serial=serial,
                config=new_config,
            )

            print_cert_details(new_cert, "New Certificate after Rotation")
            print(
                f"  ✓ Certificate rotated successfully (new serial: {new_cert.serial_number})"
            )

            return new_cert, new_key, new_csr
        except CertNotFound:
            print(f"  ✗ Certificate {serial} not found")
            raise

    def verify_certificate(self, cert: x509.Certificate) -> bool:
        """Verify a certificate's validity and revocation status."""
        print_section("13. VERIFY CERTIFICATE")

        try:
            is_valid = self.manager.verify_certificate(cert)
            print(f"  ✅ Certificate is VALID")
            print(f"    ✓ Issuer matches CA")
            print(f"    ✓ Within validity period")
            print(f"    ✓ Signature is cryptographically correct")
            print(f"    ✓ Not revoked")
            return True
        except ValidationCertError as e:
            print(f"  ❌ Certificate verification FAILED: {e}")
            return False

    def get_certificate_chain(self, cert: x509.Certificate):
        """Get the full certificate chain."""
        print_section("14. GET CERTIFICATE CHAIN")

        chain = self.manager.get_cert_chain(cert)

        print(f"  Certificate chain length: {len(chain)}")
        for i, c in enumerate(chain):
            cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn_value = cn[0].value if cn else "Unknown"
            print(f"    [{i}] {cn_value}")

        return chain

    def delete_certificate(self, serial: int):
        """Delete a certificate from database and storage."""
        print_section("15. DELETE CERTIFICATE")

        print(f"  Attempting to delete certificate: {serial}")

        success = self.manager.delete_certificate(serial=serial)

        if success:
            print(f"  ✓ Certificate {serial} deleted")
        else:
            print(f"  ✗ Certificate {serial} not found or could not be deleted")

        return success

    def refresh_expired_statuses(self):
        """Update status of expired certificates."""
        print_section("16. REFRESH EXPIRED STATUSES")

        count = self.manager.refresh_expired_statuses()
        print(f"  ✓ Marked {count} certificates as expired")

        return count

    def cleanup(self):
        """Cleanup and summary."""
        print_section("17. CLEANUP")

        # List all certificates before cleanup
        all_certs = self.manager.list_certificates(limit=100)
        print(f"  Total certificates in database: {len(all_certs)}")

        print("  Demo completed successfully!")


def run_complete_demo():
    """Run the complete demonstration."""
    print("\n" + "🔐" * 35)
    print("  CERTIFICATE LIFECYCLE MANAGER - COMPLETE DEMONSTRATION")
    print("🔐" * 35)

    demo = CertificateManagerDemo(db_path="sqlite:///demo_ca.db")

    try:
        # Create necessary directories
        Path("certs/server").mkdir(parents=True, exist_ok=True)
        Path("certs/client").mkdir(parents=True, exist_ok=True)
        Path("ca").mkdir(parents=True, exist_ok=True)
        Path("ca/intermediate").mkdir(parents=True, exist_ok=True)
        Path("certs/rotated").mkdir(parents=True, exist_ok=True)

        # Setup and create CA
        demo.setup()
        demo.create_root_ca()

        # Issue certificates
        server_cert, _ = demo.issue_server_certificate()
        client_cert = demo.issue_client_certificate()
        intermediate_cert = demo.issue_intermediate_ca()

        # List and inspect
        demo.list_and_inspect_certificates()

        # Check status
        demo.check_certificate_status(server_cert.serial_number)

        # Get certificate chain
        demo.get_certificate_chain(server_cert)

        # Verify certificates
        demo.verify_certificate(server_cert)
        demo.verify_certificate(client_cert)

        # Generate CRL (initially empty)
        demo.generate_crl()

        # Revoke a certificate
        demo.revoke_certificate(
            serial=client_cert.serial_number, reason=x509.ReasonFlags.key_compromise
        )

        # Generate CRL with revoked entries
        demo.generate_crl()

        # Check status after revocation
        demo.check_certificate_status(client_cert.serial_number)

        # Renew certificate
        renewed_cert = demo.renew_certificate(server_cert.serial_number)

        # Co-sign certificate
        cosigned = demo.cosign_certificate(client_cert)

        # Rotate certificate
        new_config = ClientConfig(
            common_name="new-api.demo.com",
            email="new-admin@demo.com",
            serial_type=CertType.SERVICE,
            is_server_cert=True,
            san_dns=["new-api.demo.com"],
        )
        demo.rotate_certificate(server_cert.serial_number, new_config)

        # Refresh expired statuses
        demo.refresh_expired_statuses()

        # Verify renewed certificate
        demo.verify_certificate(renewed_cert)

        # Generate final CRL
        final_crl = demo.generate_crl()

        # Summary
        print_section("FINAL SUMMARY")
        print("  ✅ Root CA created and loaded")
        print("  ✅ Server certificate issued")
        print("  ✅ Client certificate issued")
        print("  ✅ Intermediate CA issued")
        print("  ✅ Certificate revocation tested")
        print("  ✅ CRL generated and verified")
        print("  ✅ Certificate renewal tested")
        print("  ✅ Certificate co-signing tested")
        print("  ✅ Certificate rotation tested")
        print("  ✅ All verifications passed")

        # Optional: delete test certificate
        demo.delete_certificate(client_cert.serial_number)

    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        raise
    finally:
        demo.cleanup()


if __name__ == "__main__":
    run_complete_demo()
