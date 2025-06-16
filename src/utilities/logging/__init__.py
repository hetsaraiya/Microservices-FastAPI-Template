"""
Comprehensive Logging System for FastAPI Application

This package provides a complete logging solution with:
- Multiple log handlers (console, file, error, security, performance)
- Structured JSON logging for production
- Correlation ID tracking
- Sensitive data masking
- Request/response logging middleware
- Security audit logging
- Performance monitoring
- Logging decorators for functions and methods
- Context management for distributed tracing

Usage:
    from src.utilities.logging import logger, get_logger
    
    # Enhanced logging is automatically initialized by default
    # Simply import and use the logger
    logger.info("This will use the enhanced logging system")
    
    # Or get a named logger instance
    named_logger = get_logger("my_module")
    
    # Log with context (automatic correlation ID and context handling)
    logger.info("Processing request", extra={"user_id": "123"})
    
    # Manual setup for custom configuration (optional)
    # setup_logging(environment="production", log_level="DEBUG")
"""

# Main logging setup and configuration
from .logger import (
    setup_logging,
    get_logger,
    get_specialized_loggers,
    get_api_logger,
    get_database_logger,
    get_auth_logger,
    get_external_api_logger,
    EnhancedLogger,
    SpecializedLoggers,
    logger  # For backward compatibility
)

# Configuration classes and utilities
from .config import (
    LogLevel,
    LogFormat,
    LoggingSettings,
    LogFormats,
    get_environment_config,
    create_log_directories,
    get_log_format
)

# Formatters and data processing
from .formatters import (
    SensitiveDataMasker,
    JSONLogFormatter,
    LogSanitizer,
    StructuredLogFormatter,
    get_console_formatter,
    get_file_formatter,
    get_json_formatter
)

# Context management
from .context import (
    LoggingContext,
    RequestContext,
    PerformanceTimer,
    CorrelationIdGenerator,
    get_current_context,
    get_correlation_id,
    set_correlation_id,
    get_user_id,
    set_user_id,
    bind_context
)

# Logging decorators
from .decorators import (
    log_function_call,
    log_performance,
    log_errors,
    audit_log,
    log_api_call,
    log_database_operation,
    log_external_api_call,
    LoggingDecorators
)

# Middleware components
from .middleware import (
    RequestLoggingMiddleware,
    ErrorLoggingMiddleware
)

# Version and metadata
__version__ = "1.0.0"
__author__ = "FastAPI Template"
__description__ = "Comprehensive logging system for FastAPI applications"

# Default exports for convenience
__all__ = [
    # Main setup and loggers
    "setup_logging",
    "get_logger",
    "get_specialized_loggers",
    "get_api_logger",
    "get_database_logger",
    "get_auth_logger",
    "get_external_api_logger",
    "EnhancedLogger",
    "SpecializedLoggers",
    "logger",
    
    # Configuration
    "LogLevel",
    "LogFormat",
    "LoggingSettings",
    "LogFormats",
    "get_environment_config",
    "create_log_directories",
    "get_log_format",
    
    # Formatters
    "SensitiveDataMasker",
    "JSONLogFormatter",
    "LogSanitizer",
    "StructuredLogFormatter",
    "get_console_formatter",
    "get_file_formatter",
    "get_json_formatter",
    
    # Context management
    "LoggingContext",
    "RequestContext",
    "PerformanceTimer",
    "CorrelationIdGenerator",
    "get_current_context",
    "get_correlation_id",
    "set_correlation_id",
    "get_user_id",
    "set_user_id",
    "bind_context",
    
    # Decorators
    "log_function_call",
    "log_performance",
    "log_errors",
    "audit_log",
    "log_api_call",
    "log_database_operation",
    "log_external_api_call",
    "LoggingDecorators",

    # Middleware
    "RequestLoggingMiddleware",
    "ErrorLoggingMiddleware",
]