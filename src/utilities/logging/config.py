"""
Logging Configuration for FastAPI Application

This module provides comprehensive logging configuration for different environments
with support for structured logging, multiple handlers, and proper rotation policies.
"""

import os
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger
from pydantic import BaseModel, Field


class LogLevel(str, Enum):
    """Enumeration of log levels."""
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Enumeration of log formats."""
    SIMPLE = "simple"
    DETAILED = "detailed"
    JSON = "json"


class LoggerConfig(BaseModel):
    """Configuration for individual logger handlers."""
    sink: Union[str, Any]
    level: LogLevel = LogLevel.INFO
    format: str = ""
    rotation: Optional[str] = None
    retention: Optional[str] = None
    compression: Optional[str] = None
    enqueue: bool = True
    serialize: bool = False
    backtrace: bool = False
    diagnose: bool = False
    colorize: bool = False
    filter: Optional[str] = None


class LoggingSettings(BaseModel):
    """Main logging configuration settings."""
    
    # Basic settings
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Global log level")
    log_format: LogFormat = Field(default=LogFormat.DETAILED, description="Log format type")
    
    # Directory settings
    log_base_dir: str = Field(default="logs", description="Base directory for log files")
    
    # File rotation settings
    rotation_size: str = Field(default="10 MB", description="Log file rotation size")
    rotation_time: str = Field(default="1 day", description="Log file rotation time")
    retention_time: str = Field(default="30 days", description="Log file retention time")
    compression: str = Field(default="gz", description="Log file compression format")
    
    # Feature flags
    enable_console_logging: bool = Field(default=True, description="Enable console logging")
    enable_file_logging: bool = Field(default=True, description="Enable file logging")
    enable_json_logging: bool = Field(default=False, description="Enable JSON structured logging")
    enable_error_file: bool = Field(default=True, description="Enable separate error log file")
    enable_security_logging: bool = Field(default=True, description="Enable security audit logging")
    enable_performance_logging: bool = Field(default=True, description="Enable performance logging")
    enable_request_logging: bool = Field(default=True, description="Enable request/response logging")
    
    # Environment-specific settings
    environment: str = Field(default="development", description="Environment name")
    debug_mode: bool = Field(default=False, description="Debug mode flag")
    
    # Advanced settings
    async_logging: bool = Field(default=True, description="Enable asynchronous logging")
    backtrace_enabled: bool = Field(default=True, description="Enable backtrace in logs")
    diagnose_enabled: bool = Field(default=True, description="Enable diagnosis in logs")
    colorize_console: bool = Field(default=True, description="Enable console colorization")
    
    # Correlation settings
    enable_correlation_id: bool = Field(default=True, description="Enable request correlation IDs")
    correlation_id_header: str = Field(default="X-Request-ID", description="Correlation ID header name")
    
    # Security settings
    mask_sensitive_data: bool = Field(default=True, description="Enable sensitive data masking")
    sensitive_fields: List[str] = Field(
        default=["password", "token", "secret", "key", "authorization"],
        description="List of sensitive field names to mask"
    )


class LogFormats:
    """Predefined log formats for different use cases."""
    
    SIMPLE = "{time} | {level} | {message}"
    
    DETAILED = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )
    
    JSON_CONSOLE = (
        "{{"
        '"timestamp": "{time:YYYY-MM-DD HH:mm:ss.SSS}", '
        '"level": "{level}", '
        '"logger": "{name}", '
        '"function": "{function}", '
        '"line": {line}, '
        '"message": "{message}"'
        "}}"
    )
    
    JSON_FILE = (
        "{{"
        '"timestamp": "{time:YYYY-MM-DD HH:mm:ss.SSS}", '
        '"level": "{level}", '
        '"logger": "{name}", '
        '"module": "{module}", '
        '"function": "{function}", '
        '"line": {line}, '
        '"process_id": {process.id}, '
        '"thread_id": {thread.id}, '
        '"message": "{message}", '
        '"exception": "{exception}"'
        "}}"
    )
    
    REQUEST_FORMAT = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>REQUEST</cyan> | "
        "<level>{message}</level>"
    )
    
    SECURITY_FORMAT = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<red>SECURITY</red> | "
        "<level>{message}</level>"
    )
    
    PERFORMANCE_FORMAT = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<magenta>PERFORMANCE</magenta> | "
        "<level>{message}</level>"
    )


def get_log_format(format_type: LogFormat, environment: str = "development") -> str:
    """
    Get the appropriate log format based on type and environment.
    
    Args:
        format_type: The desired format type
        environment: The current environment
        
    Returns:
        The formatted log string
    """
    if environment.lower() in ["production", "prod"]:
        return LogFormats.JSON_FILE if format_type == LogFormat.JSON else LogFormats.SIMPLE
    
    format_map = {
        LogFormat.SIMPLE: LogFormats.SIMPLE,
        LogFormat.DETAILED: LogFormats.DETAILED,
        LogFormat.JSON: LogFormats.JSON_CONSOLE
    }
    
    return format_map.get(format_type, LogFormats.DETAILED)


def create_log_directories(base_dir: str) -> Dict[str, Path]:
    """
    Create logging directory structure.
    
    Args:
        base_dir: Base directory for logs
        
    Returns:
        Dictionary mapping log types to their directory paths
    """
    base_path = Path(base_dir)
    
    directories = {
        "app": base_path / "app",
        "access": base_path / "access", 
        "error": base_path / "error",
        "security": base_path / "security",
        "performance": base_path / "performance",
        "debug": base_path / "debug"
    }
    
    # Create all directories
    for dir_path in directories.values():
        dir_path.mkdir(parents=True, exist_ok=True)
    
    return directories


def get_environment_config(environment: str) -> LoggingSettings:
    """
    Get logging configuration based on environment.
    
    Args:
        environment: Environment name (development, staging, production)
        
    Returns:
        LoggingSettings configured for the environment
    """
    base_config = LoggingSettings()
    
    if environment.lower() in ["production", "prod"]:
        return LoggingSettings(
            log_level=LogLevel.INFO,
            log_format=LogFormat.JSON,
            enable_json_logging=True,
            enable_console_logging=False,
            debug_mode=False,
            backtrace_enabled=False,
            diagnose_enabled=False,
            colorize_console=False,
            rotation_size="50 MB",
            retention_time="90 days"
        )
    elif environment.lower() in ["staging", "stage"]:
        return LoggingSettings(
            log_level=LogLevel.INFO,
            log_format=LogFormat.DETAILED,
            enable_json_logging=True,
            debug_mode=False,
            retention_time="30 days"
        )
    else:  # development, local
        return LoggingSettings(
            log_level=LogLevel.DEBUG,
            log_format=LogFormat.DETAILED,
            debug_mode=True,
            retention_time="7 days"
        )