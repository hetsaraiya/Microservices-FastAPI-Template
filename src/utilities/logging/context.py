"""
Logging Context Management

This module provides context management for logging, including correlation IDs,
request tracking, and contextual information for distributed tracing.
"""

import asyncio
import uuid
from contextvars import ContextVar
from typing import Any, Dict, Optional, Union
from datetime import datetime, timezone

from fastapi import Request
from loguru import logger


# Context variables for tracking request-specific information
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
session_id_var: ContextVar[Optional[str]] = ContextVar('session_id', default=None)
request_start_time_var: ContextVar[Optional[datetime]] = ContextVar('request_start_time', default=None)
request_path_var: ContextVar[Optional[str]] = ContextVar('request_path', default=None)
request_method_var: ContextVar[Optional[str]] = ContextVar('request_method', default=None)
client_ip_var: ContextVar[Optional[str]] = ContextVar('client_ip', default=None)
user_agent_var: ContextVar[Optional[str]] = ContextVar('user_agent', default=None)


class CorrelationIdGenerator:
    """Generator for creating correlation IDs."""
    
    @staticmethod
    def generate() -> str:
        """Generate a new correlation ID."""
        return str(uuid.uuid4())
    
    @staticmethod
    def generate_short() -> str:
        """Generate a shorter correlation ID for logs."""
        return str(uuid.uuid4())[:8]
    
    @staticmethod
    def generate_with_prefix(prefix: str = "req") -> str:
        """Generate correlation ID with a prefix."""
        return f"{prefix}-{str(uuid.uuid4())[:8]}"


class LoggingContext:
    """Context manager for logging with correlation IDs and request information."""
    
    def __init__(self, 
                 correlation_id: Optional[str] = None,
                 user_id: Optional[str] = None,
                 session_id: Optional[str] = None,
                 **extra_context):
        """
        Initialize logging context.
        
        Args:
            correlation_id: Correlation ID for the request
            user_id: User ID if authenticated
            session_id: Session ID if available
            **extra_context: Additional context information
        """
        self.correlation_id = correlation_id or CorrelationIdGenerator.generate()
        self.user_id = user_id
        self.session_id = session_id
        self.extra_context = extra_context
        self.start_time = datetime.now(timezone.utc)
        
        # Store original values for cleanup
        self._original_correlation_id = None
        self._original_user_id = None
        self._original_session_id = None
        self._original_start_time = None
    
    def __enter__(self):
        """Enter the context manager."""
        # Store original values
        self._original_correlation_id = correlation_id_var.get()
        self._original_user_id = user_id_var.get()
        self._original_session_id = session_id_var.get()
        self._original_start_time = request_start_time_var.get()
        
        # Set new values
        correlation_id_var.set(self.correlation_id)
        user_id_var.set(self.user_id)
        session_id_var.set(self.session_id)
        request_start_time_var.set(self.start_time)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager."""
        # Restore original values
        correlation_id_var.set(self._original_correlation_id)
        user_id_var.set(self._original_user_id)
        session_id_var.set(self._original_session_id)
        request_start_time_var.set(self._original_start_time)
    
    async def __aenter__(self):
        """Async enter the context manager."""
        return self.__enter__()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async exit the context manager."""
        return self.__exit__(exc_type, exc_val, exc_tb)
    
    def get_context(self) -> Dict[str, Any]:
        """Get current context as dictionary."""
        context = {
            "correlation_id": self.correlation_id,
            "start_time": self.start_time.isoformat(),
        }
        
        if self.user_id:
            context["user_id"] = self.user_id
        if self.session_id:
            context["session_id"] = self.session_id
        
        context.update(self.extra_context)
        return context


class RequestContext:
    """Context manager specifically for HTTP requests."""
    
    def __init__(self, request: Request, correlation_id: Optional[str] = None):
        """
        Initialize request context.
        
        Args:
            request: FastAPI Request object
            correlation_id: Optional correlation ID
        """
        self.request = request
        self.correlation_id = correlation_id or self._extract_correlation_id(request)
        self.start_time = datetime.now(timezone.utc)
        
        # Store original values
        self._original_values = {}
    
    def _extract_correlation_id(self, request: Request) -> str:
        """Extract correlation ID from request headers or generate new one."""
        # Try to get from various header names
        header_names = [
            "X-Request-ID", "X-Correlation-ID", "X-Trace-ID", 
            "Request-ID", "Correlation-ID", "Trace-ID"
        ]
        
        for header_name in header_names:
            correlation_id = request.headers.get(header_name)
            if correlation_id:
                return correlation_id
        
        # Generate new correlation ID
        return CorrelationIdGenerator.generate_with_prefix("req")
    
    def __enter__(self):
        """Enter the context manager."""
        # Store original values
        self._original_values = {
            'correlation_id': correlation_id_var.get(),
            'user_id': user_id_var.get(),
            'session_id': session_id_var.get(),
            'request_start_time': request_start_time_var.get(),
            'request_path': request_path_var.get(),
            'request_method': request_method_var.get(),
            'client_ip': client_ip_var.get(),
            'user_agent': user_agent_var.get(),
        }
        
        # Set new values
        correlation_id_var.set(self.correlation_id)
        request_start_time_var.set(self.start_time)
        request_path_var.set(str(self.request.url.path))
        request_method_var.set(self.request.method)
        
        # Extract client IP
        client_ip = self._get_client_ip()
        client_ip_var.set(client_ip)
        
        # Extract user agent
        user_agent = self.request.headers.get("User-Agent", "Unknown")
        user_agent_var.set(user_agent)
        
        # Try to extract user ID from request (if authenticated)
        user_id = self._extract_user_id()
        if user_id:
            user_id_var.set(user_id)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager."""
        # Restore original values
        for key, value in self._original_values.items():
            if key == 'correlation_id':
                correlation_id_var.set(value)
            elif key == 'user_id':
                user_id_var.set(value)
            elif key == 'session_id':
                session_id_var.set(value)
            elif key == 'request_start_time':
                request_start_time_var.set(value)
            elif key == 'request_path':
                request_path_var.set(value)
            elif key == 'request_method':
                request_method_var.set(value)
            elif key == 'client_ip':
                client_ip_var.set(value)
            elif key == 'user_agent':
                user_agent_var.set(value)
    
    def _get_client_ip(self) -> str:
        """Extract client IP from request headers."""
        # Check for forwarded headers first
        forwarded_headers = [
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP", 
            "CF-Connecting-IP", "True-Client-IP"
        ]
        
        for header in forwarded_headers:
            ip = self.request.headers.get(header)
            if ip:
                # Take the first IP if multiple are present
                return ip.split(',')[0].strip()
        
        # Fallback to direct client host
        if self.request.client:
            return self.request.client.host
        
        return "unknown"
    
    def _extract_user_id(self) -> Optional[str]:
        """Extract user ID from request (if authenticated)."""
        # This would typically extract from JWT token or session
        # For now, return None - to be implemented based on auth system
        return None
    
    def get_request_context(self) -> Dict[str, Any]:
        """Get current request context as dictionary."""
        return {
            "correlation_id": self.correlation_id,
            "start_time": self.start_time.isoformat(),
            "method": self.request.method,
            "path": str(self.request.url.path),
            "query_params": dict(self.request.query_params),
            "client_ip": self._get_client_ip(),
            "user_agent": self.request.headers.get("User-Agent", "Unknown"),
            "user_id": user_id_var.get(),
            "session_id": session_id_var.get(),
        }


def get_current_context() -> Dict[str, Any]:
    """Get current logging context."""
    context = {}
    
    correlation_id = correlation_id_var.get()
    if correlation_id:
        context["correlation_id"] = correlation_id
    
    user_id = user_id_var.get()
    if user_id:
        context["user_id"] = user_id
    
    session_id = session_id_var.get()
    if session_id:
        context["session_id"] = session_id
    
    request_path = request_path_var.get()
    if request_path:
        context["request_path"] = request_path
    
    request_method = request_method_var.get()
    if request_method:
        context["request_method"] = request_method
    
    client_ip = client_ip_var.get()
    if client_ip:
        context["client_ip"] = client_ip
    
    start_time = request_start_time_var.get()
    if start_time:
        context["request_start_time"] = start_time.isoformat()
        context["request_duration"] = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    return context


def bind_context(**context) -> None:
    """Bind additional context to the current logger."""
    current_context = get_current_context()
    current_context.update(context)
    logger.bind(**current_context)


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID."""
    return correlation_id_var.get()


def set_correlation_id(correlation_id: str) -> None:
    """Set correlation ID for current context."""
    correlation_id_var.set(correlation_id)


def get_user_id() -> Optional[str]:
    """Get current user ID."""
    return user_id_var.get()


def set_user_id(user_id: str) -> None:
    """Set user ID for current context."""
    user_id_var.set(user_id)


class PerformanceTimer:
    """Context manager for timing operations."""
    
    def __init__(self, operation_name: str, logger_instance=None):
        """
        Initialize performance timer.
        
        Args:
            operation_name: Name of the operation being timed
            logger_instance: Logger instance to use (defaults to main logger)
        """
        self.operation_name = operation_name
        self.logger = logger_instance or logger
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        """Start timing."""
        self.start_time = datetime.now(timezone.utc)
        correlation_id = get_correlation_id()
        self.logger.debug(
            f"Started operation: {self.operation_name}",
            extra={"correlation_id": correlation_id, "operation": self.operation_name}
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and log results."""
        self.end_time = datetime.now(timezone.utc)
        duration = (self.end_time - self.start_time).total_seconds()
        
        correlation_id = get_correlation_id()
        log_data = {
            "correlation_id": correlation_id,
            "operation": self.operation_name,
            "duration_seconds": duration,
            "duration_ms": duration * 1000,
        }
        
        if exc_type:
            log_data["error"] = True
            log_data["exception_type"] = exc_type.__name__
            self.logger.error(
                f"Operation failed: {self.operation_name} - Duration: {duration:.3f}s",
                extra=log_data
            )
        else:
            self.logger.info(
                f"Completed operation: {self.operation_name} - Duration: {duration:.3f}s",
                extra=log_data
            )
    
    async def __aenter__(self):
        """Async enter for timing."""
        return self.__enter__()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async exit for timing."""
        return self.__exit__(exc_type, exc_val, exc_tb)