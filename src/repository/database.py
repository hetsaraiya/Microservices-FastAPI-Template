from pydantic import PostgresDsn
from sqlalchemy.ext.asyncio import (
    AsyncEngine as SQLAlchemyAsyncEngine,
    create_async_engine as create_sqlalchemy_async_engine,
    AsyncSession as SQLAlchemyAsyncSession,
    async_sessionmaker
)
from sqlalchemy.pool import Pool as SQLAlchemyPool

from src.config.manager import settings
from src.utilities.logging.logger import logger
from typing import AsyncGenerator

class AsyncDatabase:
    def __init__(self):
        self.postgres_uri: str = (
            f"{settings.DB_POSTGRES_SCHEMA}://{settings.DB_POSTGRES_USERNAME}:"
            f"{settings.DB_POSTGRES_PASSWORD}@{settings.DB_POSTGRES_HOST}:"
            f"{settings.DB_POSTGRES_PORT}/{settings.DB_POSTGRES_NAME}"
        )

        # Sets up a fast, efficient connection to the database that can handle multiple requests simultaneously without slowing down the app.
        self.async_engine: SQLAlchemyAsyncEngine = create_sqlalchemy_async_engine(
            url=self.set_async_db_uri,  # Set the database connection URL.
            echo=settings.IS_DB_ECHO_LOG,  # Enable SQL query logging if needed for debugging.
            pool_size=settings.DB_POOL_SIZE,  # Set the number of pre-created connections in the pool.
            max_overflow=settings.DB_POOL_OVERFLOW,  # Allow extra connections when the pool is full.
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_timeout=30
        )
        
        self.async_session: SQLAlchemyAsyncSession = SQLAlchemyAsyncSession(bind=self.async_engine)
        self.pool: SQLAlchemyPool = self.async_engine.pool
        
        # Create the session factory
        self.async_session_factory = async_sessionmaker(
            bind=self.async_engine,
            class_=SQLAlchemyAsyncSession,
            expire_on_commit=False
        )
    
    async def get_session(self) -> AsyncGenerator[SQLAlchemyAsyncSession, None]:
        """
        Provides a new SQLAlchemy async session.
        """
        async with self.async_session_factory() as session:
            yield session

    @property
    def set_async_db_uri(self) -> str | PostgresDsn:
        """
        Set the synchronous database driver into asynchronous version by utilizing AsyncPG:

            `postgresql://` => `postgresql+asyncpg://`
        """
        return (
            self.postgres_uri.replace("postgresql://", "postgresql+asyncpg://")
            if self.postgres_uri
            else self.postgres_uri
        )


async_db: AsyncDatabase = AsyncDatabase()
