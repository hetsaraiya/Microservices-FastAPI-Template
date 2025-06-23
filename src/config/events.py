import typing
import asyncio

from fastapi import FastAPI
import loguru

from src.repository.events import dispose_db_connection, initialize_db_connection
from src.utilities.tasks.token_cleanup import start_token_cleanup_task
from src.services.connections import (
    initialize_redis_connection,
    initialize_kafka_connection,
    close_redis_connection,
    close_kafka_connection
)


def execute_backend_server_event_handler(backend_app: FastAPI) -> typing.Any:
    async def launch_backend_server_events() -> None:
        # Initialize database connection
        await initialize_db_connection(backend_app=backend_app)
        
        # Initialize Redis connection
        try:
            await initialize_redis_connection(backend_app)
            loguru.logger.success("Redis connection established successfully")
        except Exception as e:
            loguru.logger.warning(f"Failed to initialize Redis: {e}")
            loguru.logger.warning("Application will continue without Redis functionality")
            # Set Redis as unavailable in app state
            backend_app.state.redis_available = False
        
        # Initialize Kafka connection
        try:
            await initialize_kafka_connection(backend_app)
            loguru.logger.success("Kafka connection established successfully")
        except Exception as e:
            loguru.logger.warning(f"Failed to initialize Kafka: {e}")
            loguru.logger.warning("Application will continue without Kafka functionality")
            # Set Kafka as unavailable in app state
            backend_app.state.kafka_available = False
        
        # Start background tasks
        # backend_app.state.token_cleanup_task = asyncio.create_task(start_token_cleanup_task())
        
        loguru.logger.info("Application startup completed")

    return launch_backend_server_events


def terminate_backend_server_event_handler(backend_app: FastAPI) -> typing.Any:
    @loguru.logger.catch
    async def stop_backend_server_events() -> None:
        loguru.logger.info("Starting application shutdown...")
        
        # Cancel background tasks
        if hasattr(backend_app.state, "token_cleanup_task"):
            backend_app.state.token_cleanup_task.cancel()
            try:
                await backend_app.state.token_cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close Kafka connection
        await close_kafka_connection(backend_app)
        
        # Close Redis connection
        await close_redis_connection(backend_app)
        
        # Close database connection
        await dispose_db_connection(backend_app=backend_app)
        
        loguru.logger.info("Application shutdown completed")

    return stop_backend_server_events
