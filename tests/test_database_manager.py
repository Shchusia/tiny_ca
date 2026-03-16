from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tiny_ca.db.async_db_manager import DatabaseManager


@pytest.fixture
def db_manager():
    """Create a DatabaseManager instance for testing."""
    # return DatabaseManager(db_url="sqlite+aiosqlite:///:memory:")
    return DatabaseManager(db_url="sqlite+aiosqlite:///ca_repository.db")


class TestDatabaseManager:
    """Tests for DatabaseManager class."""

    def test_init_default_db_url(self):
        """Test initialization with default database URL."""
        manager = DatabaseManager()
        assert str(manager.engine.url) == "sqlite+aiosqlite:///ca_repository.db"
        assert isinstance(manager.engine, AsyncEngine)
        assert isinstance(manager.async_session, async_sessionmaker)

    def test_init_custom_db_url(self):
        """Test initialization with custom database URL."""
        custom_url = "sqlite+aiosqlite:///:memory:"
        manager = DatabaseManager(db_url=custom_url)
        assert str(manager.engine.url) == custom_url

    def test_get_session(self, db_manager):
        """Test get_session returns an AsyncSession instance."""
        session = db_manager.get_session()
        assert isinstance(session, AsyncSession)

    # @pytest.mark.asyncio
    # async def test_init_db(self, db_manager):
    #     """Test init_db creates database tables."""
    #     with patch.object(db_manager.engine, 'begin') as mock_begin:
    #         mock_conn = AsyncMock()
    #         mock_begin.return_value.__aenter__.return_value = mock_conn
    #
    #         await db_manager.init_db()
    #
    #         mock_begin.assert_called_once()
    #         mock_conn.run_sync.assert_called_once()
