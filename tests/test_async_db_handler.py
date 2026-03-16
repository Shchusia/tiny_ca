from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ReasonFlags
from sqlalchemy import Row
from sqlalchemy.ext.asyncio import AsyncSession

from tiny_ca.const import CertType
from tiny_ca.db.async_db_manager import AsyncDBHandler, DatabaseManager
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.db.models import CertificateRecord
from tiny_ca.settings import DEFAULT_LOGGER


@pytest.fixture
def mock_session():
    """Create a mock AsyncSession."""
    session = AsyncMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.execute = AsyncMock()
    session.stream = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.fixture
def mock_db_manager(mock_session):
    """Create a mock DatabaseManager."""
    manager = MagicMock(spec=DatabaseManager)
    manager.get_session.return_value.__aenter__.return_value = mock_session
    return manager


@pytest.fixture
def handler(mock_db_manager):
    """Create an AsyncDBHandler with mocked DatabaseManager."""
    with patch(
        "tiny_ca.db.async_db_manager.DatabaseManager", return_value=mock_db_manager
    ):
        handler = AsyncDBHandler(
            db_url="sqlite+aiosqlite:///:memory:", logger=MagicMock()
        )
        handler._db = mock_db_manager
        return handler


@pytest.fixture
def sample_certificate():
    """Create a sample X.509 certificate for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert


class TestAsyncDBHandler:
    """Tests for AsyncDBHandler class."""

    @pytest.mark.asyncio
    async def test_init_with_default_logger(self):
        """Test initialization with default logger."""
        with patch(
            "tiny_ca.db.async_db_manager.DatabaseManager"
        ) as mock_db_manager_class:
            handler = AsyncDBHandler(db_url="sqlite+aiosqlite:///:memory:", logger=None)
            assert handler._logger == DEFAULT_LOGGER
            mock_db_manager_class.assert_called_once_with(
                db_url="sqlite+aiosqlite:///:memory:"
            )

    @pytest.mark.asyncio
    async def test_init_with_custom_logger(self):
        """Test initialization with custom logger."""
        mock_logger = MagicMock()
        with patch(
            "tiny_ca.db.async_db_manager.DatabaseManager"
        ) as mock_db_manager_class:
            handler = AsyncDBHandler(
                db_url="sqlite+aiosqlite:///:memory:", logger=mock_logger
            )
            handler._db.init_db()
            assert handler._logger == mock_logger

    @pytest.mark.asyncio
    async def test_get_by_serial_found(self, handler, mock_session):
        """Test get_by_serial when certificate is found."""
        mock_cert = MagicMock(spec=CertificateRecord)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_cert
        mock_session.execute.return_value = mock_result

        result = await handler.get_by_serial(12345)

        assert result == mock_cert
        handler._logger.debug.assert_called_once_with(
            "get_by_serial(%d) → %s", 12345, mock_cert
        )
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_serial_not_found(self, handler, mock_session):
        """Test get_by_serial when certificate is not found."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await handler.get_by_serial(12345)

        assert result is None
        handler._logger.debug.assert_called_once_with(
            "get_by_serial(%d) → %s", 12345, None
        )

    @pytest.mark.asyncio
    async def test_get_by_serial_exception(self, handler, mock_session):
        """Test get_by_serial when database exception occurs."""
        mock_session.execute.side_effect = Exception("Database error")

        result = await handler.get_by_serial(12345)

        assert result is None
        handler._logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_by_name_found(self, handler, mock_session):
        """Test get_by_name when certificate is found."""
        mock_cert = MagicMock(spec=CertificateRecord)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_cert
        mock_session.execute.return_value = mock_result

        result = await handler.get_by_name("test.example.com")

        assert result == mock_cert
        handler._logger.debug.assert_called_once_with(
            "get_by_name(%r) → %s", "test.example.com", mock_cert
        )

    @pytest.mark.asyncio
    async def test_get_by_name_not_found(self, handler, mock_session):
        """Test get_by_name when certificate is not found."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await handler.get_by_name("test.example.com")

        assert result is None
        handler._logger.debug.assert_called_once_with(
            "get_by_name(%r) → %s", "test.example.com", None
        )

    @pytest.mark.asyncio
    async def test_get_by_name_exception(self, handler, mock_session):
        """Test get_by_name when database exception occurs."""
        mock_session.execute.side_effect = Exception("Database error")

        result = await handler.get_by_name("test.example.com")

        assert result is None
        handler._logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_cert_in_db_success(
        self, handler, mock_session, sample_certificate
    ):
        """Test successful certificate registration."""
        mock_session.commit.return_value = None

        result = await handler.register_cert_in_db(
            cert=sample_certificate, uuid="test-uuid-123", key_type=CertType.DEVICE
        )

        assert result is True
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        handler._logger.info.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_cert_in_db_with_string_common_name(
        self, handler, mock_session
    ):
        """Test certificate registration with string common name."""
        mock_cert = MagicMock(spec=x509.Certificate)
        mock_cert.subject.get_attributes_for_oid.return_value = [
            MagicMock(value="test.example.com")
        ]
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before_utc = datetime.now(UTC)
        mock_cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
        mock_cert.public_bytes.return_value = (
            b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        )

        mock_session.commit.return_value = None

        result = await handler.register_cert_in_db(
            cert=mock_cert, uuid="test-uuid-123", key_type=CertType.SERVICE
        )

        assert result is True
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_cert_in_db_with_bytes_common_name(
        self, handler, mock_session
    ):
        """Test certificate registration with bytes common name."""
        mock_cert = MagicMock(spec=x509.Certificate)
        mock_cert.subject.get_attributes_for_oid.return_value = [
            MagicMock(value=b"test.example.com")
        ]
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before_utc = datetime.now(UTC)
        mock_cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
        mock_cert.public_bytes.return_value = (
            b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        )

        mock_session.commit.return_value = None

        result = await handler.register_cert_in_db(
            cert=mock_cert, uuid="test-uuid-123", key_type=CertType.USER
        )

        assert result is True
        mock_session.add.assert_called_once()

    # @pytest.mark.asyncio
    # async def test_register_cert_in_db_index_error(self, handler, mock_session, sample_certificate):
    #     """Test certificate registration with missing common name."""
    #     mock_cert = MagicMock(spec=x509.Certificate)
    #     mock_cert.subject.get_attributes_for_oid.return_value = []  # No CN attribute
    #
    #     with pytest.raises(IndexError):
    #         await handler.register_cert_in_db(
    #             cert=mock_cert,
    #             uuid="test-uuid-123"
    #         )

    @pytest.mark.asyncio
    async def test_register_cert_in_db_exception(
        self, handler, mock_session, sample_certificate
    ):
        """Test certificate registration when database exception occurs."""
        mock_session.commit.side_effect = Exception("Database error")

        result = await handler.register_cert_in_db(
            cert=sample_certificate, uuid="test-uuid-123"
        )

        assert result is False
        mock_session.rollback.assert_called_once()
        handler._logger.error.assert_called_once()

    # @pytest.mark.asyncio
    # async def test_revoke_certificate_success(self, handler, mock_session):
    #     """Test successful certificate revocation."""
    #     mock_cert = MagicMock(spec=CertificateRecord)
    #     mock_cert.status = CertificateStatus.VALID
    #     mock_result = MagicMock()
    #     mock_result.scalar_one_or_none.return_value = mock_cert
    #     mock_session.execute.return_value = mock_result
    #     mock_session.commit.return_value = None
    #
    #     result, status = await handler.revoke_certificate(
    #         serial_number=12345,
    #         reason=ReasonFlags.key_compromise
    #     )
    #
    #     assert result is True
    #     assert status == RevokeStatus.OK
    #     assert mock_cert.status == CertificateStatus.REVOKED
    #     assert mock_cert.revocation_reason == 1  # key_compromise value
    #     assert mock_cert.revocation_date is not None
    #     mock_session.commit.assert_called_once()
    #     handler._logger.info.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_certificate_with_reason_object(self, handler, mock_session):
        """Test certificate revocation with reason that has value attribute."""
        mock_cert = MagicMock(spec=CertificateRecord)
        mock_cert.status = CertificateStatus.VALID
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_cert
        mock_session.execute.return_value = mock_result
        mock_session.commit.return_value = None

        mock_reason = MagicMock()
        mock_reason.value = 3

        result, status = await handler.revoke_certificate(
            serial_number=12345, reason=mock_reason
        )

        assert result is True
        assert status == RevokeStatus.OK
        assert mock_cert.revocation_reason == 3

    @pytest.mark.asyncio
    async def test_revoke_certificate_not_found(self, handler, mock_session):
        """Test revoke certificate when certificate not found."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result, status = await handler.revoke_certificate(serial_number=12345)

        assert result is False
        assert status == RevokeStatus.NOT_FOUND
        handler._logger.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_certificate_exception(self, handler, mock_session):
        """Test revoke certificate when database exception occurs."""
        mock_session.execute.side_effect = Exception("Database error")

        result, status = await handler.revoke_certificate(serial_number=12345)

        assert result is False
        assert status == RevokeStatus.UNKNOWN_ERROR
        mock_session.rollback.assert_called_once()
        handler._logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_revoked_certificates(self, handler, mock_session):
        """Test getting revoked certificates."""
        mock_row1 = MagicMock(spec=Row)
        mock_row2 = MagicMock(spec=Row)

        mock_stream = AsyncMock()
        mock_stream.__aiter__.return_value = [mock_row1, mock_row2]
        mock_session.stream.return_value = mock_stream

        result = []
        async for row in handler.get_revoked_certificates():
            result.append(row)

        assert len(result) == 2
        assert result[0] == mock_row1
        assert result[1] == mock_row2
        mock_session.stream.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_revoked_certificates_empty(self, handler, mock_session):
        """Test getting revoked certificates when none exist."""
        mock_stream = AsyncMock()
        mock_stream.__aiter__.return_value = []
        mock_session.stream.return_value = mock_stream

        result = []
        async for row in handler.get_revoked_certificates():
            result.append(row)

        assert len(result) == 0
        mock_session.stream.assert_called_once()

    # @pytest.mark.asyncio
    # async def test_context_manager_session_cleanup(self, handler, mock_session):
    #     """Test that session is properly closed after operations."""
    #     mock_cert = MagicMock(spec=CertificateRecord)
    #     mock_result = MagicMock()
    #     mock_result.scalar_one_or_none.return_value = mock_cert
    #     mock_session.execute.return_value = mock_result
    #
    #     await handler.get_by_serial(12345)
    #
    #     # Verify session context manager was used
    #     handler._db.get_session.assert_called_once()
    #     mock_session.__aenter__.assert_called_once()
    #     mock_session.__aexit__.assert_called_once()

    # @pytest.mark.asyncio
    # async def test_context_manager_session_cleanup_on_error(self, handler, mock_session):
    #     """Test that session is properly closed even on error."""
    #     mock_session.execute.side_effect = Exception("Database error")
    #
    #     await handler.get_by_serial(12345)
    #
    #     # Verify session context manager was used even after error
    #     handler._db.get_session.assert_called_once()
    #     mock_session.__aenter__.assert_called_once()
    #     mock_session.__aexit__.assert_called_once()
