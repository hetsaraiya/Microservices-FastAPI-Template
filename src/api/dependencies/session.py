from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    async_sessionmaker as sqlalchemy_async_sessionmaker,
    AsyncSession as SQLAlchemyAsyncSession,
    AsyncSessionTransaction as SQLAlchemyAsyncSessionTransaction,
)

from src.repository.database import async_db


from src.utilities.logging.logger import logger

async def get_async_session() -> AsyncGenerator[SQLAlchemyAsyncSession, None]:
    async_session_factory = async_db.async_session_factory # Get session factory
    async with async_session_factory() as session:  # Create new session
        try:
            logger.info("Opening database session")
            yield session
        except Exception as e:
            logger.error(f"Exception caught: {str(e)}")
            await session.rollback()
            raise
        finally:
            logger.info("Closing database session")