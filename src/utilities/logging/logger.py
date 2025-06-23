"""
Enhanced Logging System for FastAPI Application

This module provides a comprehensive logging system with multiple handlers,
structured logging, correlation IDs, and environment-specific configurations.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger
import loguru

from .config import (
    LogLevel, LogFormat, LoggingSettings, LogFormats,
    get_environment_config, create_log_directories, get_log_format
)
from .formatters import (
    SensitiveDataMasker, JSONLogFormatter, LogSanitizer,
    get_console_formatter, get_file_formatter, get_json_formatter
)
from .context import get_current_context


class EnhancedLogger:
    """Enhanced logger with multiple specialized handlers."""
    
    def __init__(self, settings: Optional[LoggingSettings] = None):
        """
        Initialize the enhanced logger.
        
        Args:
            settings: Logging configuration settings
        """
        self.settings = settings or LoggingSettings()
        self.masker = SensitiveDataMasker() if self.settings.mask_sensitive_data else None
        self.sanitizer = LogSanitizer()
        self.directories = create_log_directories(self.settings.log_base_dir)
        
        # Store original logger for restoration
        self._original_handlers = []
        
        # Setup the logger
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Configure the logger with all handlers."""
        # Remove existing handlers
        logger.remove()
        
        # Add console handler
        if self.settings.enable_console_logging:
            self._add_console_handler()
        
        # Add file handlers
        if self.settings.enable_file_logging:
            self._add_file_handlers()
        
        # Add specialized handlers
        if self.settings.enable_error_file:
            self._add_error_handler()
        
        if self.settings.enable_security_logging:
            self._add_security_handler()
        
        if self.settings.enable_performance_logging:
            self._add_performance_handler()
        
        if self.settings.enable_request_logging:
            self._add_request_handler()
    
    def _add_console_handler(self) -> None:
        """Add console logging handler."""
        try:
            console_format = get_console_formatter(self.settings.environment)
            
            logger.add(
                sys.stdout,
                level=self.settings.log_level.value,
                format=console_format,
                colorize=self.settings.colorize_console,
                enqueue=self.settings.async_logging,
                backtrace=self.settings.backtrace_enabled,
                diagnose=self.settings.diagnose_enabled,
                filter=self._create_context_filter()
            )
            
        except Exception as e:
            print(f"Error adding console handler: {e}")
    
    def _add_file_handlers(self) -> None:
        """Add main application file handler."""
        try:
            app_log_path = self.directories["app"] / "app_{time:YYYY-MM-DD}.log"
            
            file_format = get_file_formatter(self.settings.environment)
            if self.settings.enable_json_logging:
                file_format = LogFormats.JSON_FILE
            
            logger.add(
                str(app_log_path),
                level=self.settings.log_level.value,
                format=file_format,
                rotation=self.settings.rotation_size,
                retention=self.settings.retention_time,
                compression=self.settings.compression,
                enqueue=self.settings.async_logging,
                backtrace=self.settings.backtrace_enabled,
                diagnose=self.settings.diagnose_enabled,
                serialize=self.settings.enable_json_logging,
                filter=self._create_context_filter()
            )
            
        except Exception as e:
            print(f"Error adding file handler: {e}")
    
    def _add_error_handler(self) -> None:
        """Add error-specific file handler."""
        try:
            error_log_path = self.directories["error"] / "error_{time:YYYY-MM-DD}.log"
            
            logger.add(
                str(error_log_path),
                level="ERROR",
                format=LogFormats.DETAILED,
                rotation=self.settings.rotation_size,
                retention=self.settings.retention_time,
                compression=self.settings.compression,
                enqueue=self.settings.async_logging,
                backtrace=True,
                diagnose=True,
                filter=lambda record: record["level"].no >= logger.level("ERROR").no
            )
            
        except Exception as e:
            print(f"Error adding error handler: {e}")
    
    def _add_security_handler(self) -> None:
        """Add security audit log handler."""
        try:
            security_log_path = self.directories["security"] / "security_{time:YYYY-MM-DD}.log"
            
            logger.add(
                str(security_log_path),
                level="INFO",
                format=LogFormats.SECURITY_FORMAT,
                rotation=self.settings.rotation_size,
                retention="1 year",  # Keep security logs longer
                compression=self.settings.compression,
                enqueue=self.settings.async_logging,
                serialize=True,  # Always use JSON for security logs
                filter=lambda record: record.get("extra", {}).get("security_event", False)
            )
            
        except Exception as e:
            print(f"Error adding security handler: {e}")
    
    def _add_performance_handler(self) -> None:
        """Add performance monitoring log handler."""
        try:
            perf_log_path = self.directories["performance"] / "performance_{time:YYYY-MM-DD}.log"
            
            logger.add(
                str(perf_log_path),
                level="INFO",
                format=LogFormats.PERFORMANCE_FORMAT,
                rotation=self.settings.rotation_size,
                retention=self.settings.retention_time,
                compression=self.settings.compression,
                enqueue=self.settings.async_logging,
                serialize=True,
                filter=lambda record: (
                    record.get("extra", {}).get("performance_issue", False) or
                    record.get("extra", {}).get("event_type") == "performance_warning"
                )
            )
            
        except Exception as e:
            print(f"Error adding performance handler: {e}")
    
    def _add_request_handler(self) -> None:
        """Add request/response log handler."""
        try:
            access_log_path = self.directories["access"] / "access_{time:YYYY-MM-DD}.log"
            
            logger.add(
                str(access_log_path),
                level="INFO",
                format=LogFormats.REQUEST_FORMAT,
                rotation=self.settings.rotation_size,
                retention=self.settings.retention_time,
                compression=self.settings.compression,
                enqueue=self.settings.async_logging,
                serialize=True,
                filter=lambda record: record.get("extra", {}).get("event_type") in [
                    "http_request", "http_response", "http_error"
                ]
            )
            
        except Exception as e:
            print(f"Error adding request handler: {e}")
    
    def _create_context_filter(self):
        """Create a filter that adds context information to log records."""
        def context_filter(record):
            # Add current context to the record
            context = get_current_context()
            if context:
                if "extra" not in record:
                    record["extra"] = {}
                record["extra"].update(context)
            
            # Mask sensitive data if enabled
            if self.masker and "extra" in record:
                record["extra"] = self.masker.mask_dict(record["extra"])
            
            # Sanitize message
            if "message" in record:
                record["message"] = self.sanitizer.sanitize_message(record["message"])
            
            return True
        
        return context_filter
    
    def get_logger(self, name: Optional[str] = None) -> "loguru.Logger":
        """
        Get a logger instance with optional name binding.
        
        Args:
            name: Optional logger name for identification
            
        Returns:
            Configured logger instance
        """
        if name:
            return logger.bind(logger_name=name)
        return logger
    
    def configure_for_environment(self, environment: str) -> None:
        """
        Reconfigure logger for specific environment.
        
        Args:
            environment: Environment name (development, staging, production)
        """
        self.settings = get_environment_config(environment)
        self._setup_logger()


class SpecializedLoggers:
    """Collection of specialized loggers for different purposes."""
    
    def __init__(self, enhanced_logger: EnhancedLogger):
        """
        Initialize specialized loggers.
        
        Args:
            enhanced_logger: Main enhanced logger instance
        """
        self.enhanced_logger = enhanced_logger
        self.masker = enhanced_logger.masker
    
    def get_api_logger(self) -> "loguru.Logger":
        """Get logger for API operations."""
        return logger.bind(
            logger_type="api",
            component="api"
        )
    
    def get_database_logger(self) -> "loguru.Logger":
        """Get logger for database operations."""
        return logger.bind(
            logger_type="database",
            component="database"
        )
    
    def get_auth_logger(self) -> "loguru.Logger":
        """Get logger for authentication operations."""
        return logger.bind(
            logger_type="auth",
            component="authentication"
        )
    
    def get_external_api_logger(self) -> "loguru.Logger":
        """Get logger for external API calls."""
        return logger.bind(
            logger_type="external_api",
            component="external_api"
        )
    
    def get_cache_logger(self) -> "loguru.Logger":
        """Get logger for cache operations."""
        return logger.bind(
            logger_type="cache",
            component="cache"
        )
    
    def get_task_logger(self) -> "loguru.Logger":
        """Get logger for background tasks."""
        return logger.bind(
            logger_type="task",
            component="background_task"
        )


# Global instances
_enhanced_logger: Optional[EnhancedLogger] = None
_specialized_loggers: Optional[SpecializedLoggers] = None


def setup_logging(
    environment: Optional[str] = None,
    settings: Optional[LoggingSettings] = None,
    log_level: Optional[str] = None,
    log_dir: Optional[str] = None
) -> EnhancedLogger:
    """
    Setup the comprehensive logging system.
    
    Args:
        environment: Environment name (development, staging, production)
        settings: Custom logging settings
        log_level: Override log level
        log_dir: Override log directory
        
    Returns:
        Configured enhanced logger instance
    """
    global _enhanced_logger, _specialized_loggers
    
    # Determine environment
    if not environment:
        environment = os.getenv("ENVIRONMENT", "development").lower()
    
    # Get environment-specific settings
    if not settings:
        settings = get_environment_config(environment)
    
    # Apply overrides
    if log_level:
        try:
            settings.log_level = LogLevel(log_level.upper())
        except ValueError:
            print(f"Invalid log level: {log_level}, using default")
    
    if log_dir:
        settings.log_base_dir = log_dir
    
    # Create enhanced logger
    _enhanced_logger = EnhancedLogger(settings)
    _specialized_loggers = SpecializedLoggers(_enhanced_logger)
    
    # Log initialization
    logger.info(
        f"Logging system initialized for environment: {environment}",
        extra={
            "environment": environment,
            "log_level": settings.log_level.value,
            "log_directory": settings.log_base_dir,
            "json_logging": settings.enable_json_logging,
            "async_logging": settings.async_logging
        }
    )
    
    return _enhanced_logger


def get_logger(name: Optional[str] = None) -> "loguru.Logger":
    """
    Get the main application logger.
    
    Args:
        name: Optional logger name
        
    Returns:
        Logger instance
    """
    if _enhanced_logger:
        return _enhanced_logger.get_logger(name)
    return logger


def get_specialized_loggers() -> Optional[SpecializedLoggers]:
    """Get specialized loggers collection."""
    return _specialized_loggers


def get_api_logger() -> "loguru.Logger":
    """Get API logger."""
    if _specialized_loggers:
        return _specialized_loggers.get_api_logger()
    return logger.bind(component="api")


def get_database_logger() -> "loguru.Logger":
    """Get database logger."""
    if _specialized_loggers:
        return _specialized_loggers.get_database_logger()
    return logger.bind(component="database")


def get_auth_logger() -> "loguru.Logger":
    """Get authentication logger."""
    if _specialized_loggers:
        return _specialized_loggers.get_auth_logger()
    return logger.bind(component="auth")


def get_external_api_logger() -> "loguru.Logger":
    """Get external API logger."""
    if _specialized_loggers:
        return _specialized_loggers.get_external_api_logger()
    return logger.bind(component="external_api")


# Backward compatibility - keep the original setup for existing code
def setup_logger() -> "loguru.Logger":
    """
    Legacy function for backward compatibility.
    
    Returns:
        Configured logger instance
    """
    if not _enhanced_logger:
        setup_logging()
    return logger


# Export the enhanced logger instance as the default logger
# This ensures all imports get the enhanced logger automatically
logger = logger  # Loguru logger instance (enhanced by auto-setup above)

# Make enhanced logger easily accessible
enhanced_logger = _enhanced_logger
specialized_loggers = _specialized_loggers


# Auto-setup enhanced logging by default
if not _enhanced_logger:
    try:
        # Initialize enhanced logging system by default
        environment = os.getenv("ENVIRONMENT", "development").lower()
        setup_logging(environment=environment)
        print(f"Enhanced logging system initialized for {environment} environment")
    except Exception as e:
        print(f"Error: Could not initialize enhanced logging system: {e}")
        print("Please check your logging configuration and dependencies.")
        # Re-raise the exception to prevent silent failures
        raise RuntimeError(f"Failed to initialize enhanced logging system: {e}") from e