import typing
import asyncio

from fastapi import FastAPI
import loguru

from src.repository.events import dispose_db_connection, initialize_db_connection
from src.utilities.tasks.token_cleanup import start_token_cleanup_task


def execute_backend_server_event_handler(backend_app: FastAPI) -> typing.Any:
    async def launch_backend_server_events() -> None:
        await initialize_db_connection(backend_app=backend_app)
        
        # Start background tasks
        # backend_app.state.token_cleanup_task = asyncio.create_task(start_token_cleanup_task())

    return launch_backend_server_events


def terminate_backend_server_event_handler(backend_app: FastAPI) -> typing.Any:
    @loguru.logger.catch
    async def stop_backend_server_events() -> None:
        # Cancel background tasks
        if hasattr(backend_app.state, "token_cleanup_task"):
            backend_app.state.token_cleanup_task.cancel()
            try:
                await backend_app.state.token_cleanup_task
            except asyncio.CancelledError:
                pass
        
        await dispose_db_connection(backend_app=backend_app)

    return stop_backend_server_events
