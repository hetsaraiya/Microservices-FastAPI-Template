"""
Service connection initialization and management
"""
import asyncio
from typing import Optional
from fastapi import FastAPI

from src.services.redis.client import get_redis_client
from src.services.kafka.manager import KafkaManager
from src.utilities.logging.logger import logger


async def initialize_redis_connection(app: FastAPI) -> None:
    """
    Initialize Redis connection and store it in app state.
    
    Args:
        app: FastAPI application instance
        
    Raises:
        ConnectionError: If Redis connection fails
    """
    try:
        logger.info("Initializing Redis connection...")
        redis_client = get_redis_client()
        
        # Test the connection
        await asyncio.to_thread(redis_client.ping)
        
        # Store in app state
        app.state.redis_client = redis_client
        logger.info("Redis connection established successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Redis connection: {e}")
        raise ConnectionError(f"Redis connection failed: {e}") from e


async def initialize_kafka_connection(app: FastAPI) -> None:
    """
    Initialize Kafka connection and store it in app state.
    
    Args:
        app: FastAPI application instance
        
    Raises:
        ConnectionError: If Kafka connection fails
    """
    try:
        logger.info("Initializing Kafka connection...")
        kafka_manager = KafkaManager()
        
        # Start Kafka manager (connects to Kafka)
        await kafka_manager.start()
        
        # Store in app state
        app.state.kafka_manager = kafka_manager
        logger.info("Kafka connection established successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Kafka connection: {e}")
        raise ConnectionError(f"Kafka connection failed: {e}") from e


async def close_redis_connection(app: FastAPI) -> None:
    """
    Close Redis connection.
    
    Args:
        app: FastAPI application instance
    """
    try:
        if hasattr(app.state, "redis_client") and app.state.redis_client:
            logger.info("Closing Redis connection...")
            app.state.redis_client.close()
            app.state.redis_client = None
            logger.info("Redis connection closed successfully")
    except Exception as e:
        logger.error(f"Error closing Redis connection: {e}")


async def close_kafka_connection(app: FastAPI) -> None:
    """
    Close Kafka connection.
    
    Args:
        app: FastAPI application instance
    """
    try:
        if hasattr(app.state, "kafka_manager") and app.state.kafka_manager:
            logger.info("Closing Kafka connection...")
            await app.state.kafka_manager.stop()
            app.state.kafka_manager = None
            logger.info("Kafka connection closed successfully")
    except Exception as e:
        logger.error(f"Error closing Kafka connection: {e}")


def get_redis_from_app(app: FastAPI):
    """
    Get Redis client from app state.
    
    Args:
        app: FastAPI application instance
        
    Returns:
        Redis client instance
        
    Raises:
        RuntimeError: If Redis client is not initialized
    """
    if not hasattr(app.state, "redis_client") or not app.state.redis_client:
        raise RuntimeError("Redis client not initialized")
    return app.state.redis_client


def get_kafka_from_app(app: FastAPI) -> KafkaManager:
    """
    Get Kafka manager from app state.
    
    Args:
        app: FastAPI application instance
        
    Returns:
        KafkaManager instance
        
    Raises:
        RuntimeError: If Kafka manager is not initialized
    """
    if not hasattr(app.state, "kafka_manager") or not app.state.kafka_manager:
        raise RuntimeError("Kafka manager not initialized")
    return app.state.kafka_manager
