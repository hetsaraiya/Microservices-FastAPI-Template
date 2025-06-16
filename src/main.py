from fastapi import FastAPI, Request
import uvicorn
import time
from fastapi.middleware.cors import CORSMiddleware

from src.api.endpoints import router as api_endpoint_router
from src.config.events import execute_backend_server_event_handler, terminate_backend_server_event_handler
from src.config.manager import settings
from src.utilities.exceptions.database import EntityDoesNotExist
from src.utilities.exceptions.exceptions import *

# Enhanced logging imports
from src.utilities.logging.logger import setup_logging, get_logger
from src.utilities.logging.middleware import RequestLoggingMiddleware, ErrorLoggingMiddleware
from src.utilities.logging.config import LoggingSettings, LogLevel, LogFormat

# Security middleware imports
from src.middleware.security import SecurityMiddleware, SecurityConfig, RateLimitConfig, AttackPatterns

def initialize_backend_application() -> FastAPI:
    app = FastAPI(**settings.set_backend_app_attributes)  # type: ignore

    # Add security middleware first (highest priority)
    app.add_middleware(SecurityMiddleware, config=SecurityConfig(
        enable_attack_detection=settings.ENABLE_ATTACK_DETECTION,
        enable_rate_limiting=settings.ENABLE_RATE_LIMITING,
        enable_ip_blocking=settings.ENABLE_IP_BLOCKING,
        enable_user_agent_filtering=settings.ENABLE_USER_AGENT_FILTERING,
        max_request_size_mb=settings.MAX_REQUEST_SIZE_MB,
        block_empty_user_agents=settings.BLOCK_EMPTY_USER_AGENTS,
        rate_limit=RateLimitConfig(
            requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
            requests_per_hour=settings.RATE_LIMIT_PER_HOUR,
            burst_limit=settings.RATE_LIMIT_BURST,
            block_duration_minutes=settings.RATE_LIMIT_BLOCK_DURATION
        )
    ))

    # Add enhanced logging middleware
    app.add_middleware(
        ErrorLoggingMiddleware,
        include_traceback=settings.BACKTRACE_ENABLED,
        mask_sensitive=settings.MASK_SENSITIVE_DATA
    )
    
    app.add_middleware(
        RequestLoggingMiddleware,
        log_requests=settings.ENABLE_REQUEST_LOGGING,
        log_responses=settings.ENABLE_REQUEST_LOGGING,
        log_request_body=settings.LOG_REQUEST_BODY,
        log_response_body=settings.LOG_RESPONSE_BODY,
        log_headers=settings.LOG_HEADERS,
        mask_sensitive_data=settings.MASK_SENSITIVE_DATA,
        max_body_size=settings.MAX_LOG_BODY_SIZE,
        performance_threshold_ms=settings.PERFORMANCE_THRESHOLD_MS,
        exclude_paths=["/health", "/metrics", "/docs", "/redoc", "/openapi.json"]
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=settings.IS_ALLOWED_CREDENTIALS,
        allow_methods=settings.ALLOWED_METHODS,
        allow_headers=settings.ALLOWED_HEADERS,
    )

    app.add_exception_handler(UserNotFoundException, user_not_found_exception_handler)
    app.add_exception_handler(UserAlreadyExistsException, user_already_exists_exception_handler)
    app.add_exception_handler(InvalidCredentialsException, invalid_credentials_exception_handler)
    app.add_exception_handler(AuthorizationHeaderException, authorization_header_exception_handler)
    app.add_exception_handler(SecurityException, security_exception_handler)
    app.add_exception_handler(EntityDoesNotExist, entity_does_not_exist_exception_handler)
    app.add_exception_handler(EntityAlreadyExists, entity_already_exists_exception_handler)
    app.add_exception_handler(InternalServerErrorException, internal_server_error_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)

    app.add_event_handler(
        "startup",
        execute_backend_server_event_handler(backend_app=app),
    )
    app.add_event_handler(
        "shutdown",
        terminate_backend_server_event_handler(backend_app=app),
    )

    app.include_router(router=api_endpoint_router, prefix=settings.API_PREFIX)

    return app


backend_app: FastAPI = initialize_backend_application()

if __name__ == "__main__":
    uvicorn.run(
        app="main:backend_app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
        workers=settings.SERVER_WORKERS,
        log_level=settings.LOGGING_LEVEL,
    )
