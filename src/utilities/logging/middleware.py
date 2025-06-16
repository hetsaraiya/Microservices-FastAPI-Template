"""
Logging Middleware for FastAPI Application

This module provides comprehensive middleware for logging HTTP requests and responses,
including performance monitoring, error tracking, and security event detection.
"""

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

from .context import RequestContext, get_correlation_id
from .formatters import SensitiveDataMasker, LogSanitizer


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for comprehensive request/response logging."""
    
    def __init__(self,
                 app,
                 log_requests: bool = True,
                 log_responses: bool = True,
                 log_request_body: bool = False,
                 log_response_body: bool = False,
                 log_headers: bool = True,
                 mask_sensitive_data: bool = True,
                 max_body_size: int = 10000,
                 exclude_paths: Optional[List[str]] = None,
                 exclude_methods: Optional[List[str]] = None,
                 performance_threshold_ms: float = 1000.0):
        """
        Initialize request logging middleware.
        
        Args:
            app: FastAPI application instance
            log_requests: Whether to log incoming requests
            log_responses: Whether to log outgoing responses
            log_request_body: Whether to log request body content
            log_response_body: Whether to log response body content
            log_headers: Whether to log request/response headers
            mask_sensitive_data: Whether to mask sensitive data
            max_body_size: Maximum body size to log (bytes)
            exclude_paths: List of paths to exclude from logging
            exclude_methods: List of HTTP methods to exclude from logging
            performance_threshold_ms: Performance threshold for warnings (milliseconds)
        """
        super().__init__(app)
        self.log_requests = log_requests
        self.log_responses = log_responses
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.log_headers = log_headers
        self.mask_sensitive_data = mask_sensitive_data
        self.max_body_size = max_body_size
        self.exclude_paths = set(exclude_paths or [])
        self.exclude_methods = set(exclude_methods or [])
        self.performance_threshold_ms = performance_threshold_ms
        
        # Initialize utilities
        self.masker = SensitiveDataMasker() if mask_sensitive_data else None
        self.sanitizer = LogSanitizer()
        
        # Default excluded paths for health checks, etc.
        self.exclude_paths.update(["/health", "/metrics", "/favicon.ico"])
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and response with logging."""
        # Check if this request should be logged
        if self._should_exclude_request(request):
            return await call_next(request)
        
        # Start request context and timing
        start_time = time.time()
        
        with RequestContext(request) as req_context:
            correlation_id = req_context.correlation_id
            
            # Log incoming request
            if self.log_requests:
                await self._log_request(request, correlation_id)
            
            # Process request
            try:
                # Capture request body if needed
                request_body = None
                if self.log_request_body:
                    request_body = await self._capture_request_body(request)
                
                # Call the next middleware/endpoint
                response = await call_next(request)
                
                # Calculate processing time
                process_time_ms = (time.time() - start_time) * 1000
                
                # Log response
                if self.log_responses:
                    await self._log_response(
                        request, response, correlation_id, 
                        process_time_ms, request_body
                    )
                
                # Performance monitoring
                if process_time_ms > self.performance_threshold_ms:
                    await self._log_performance_warning(
                        request, response, correlation_id, process_time_ms
                    )
                
                # Add correlation ID to response headers
                response.headers["X-Request-ID"] = correlation_id
                
                return response
                
            except Exception as e:
                # Log error
                process_time_ms = (time.time() - start_time) * 1000
                await self._log_error(request, e, correlation_id, process_time_ms)
                
                # Create error response if none exists
                if not isinstance(e, Exception):
                    return JSONResponse(
                        status_code=500,
                        content={"error": "Internal server error"},
                        headers={"X-Request-ID": correlation_id}
                    )
                
                raise
    
    def _should_exclude_request(self, request: Request) -> bool:
        """Check if request should be excluded from logging."""
        path = request.url.path
        method = request.method
        
        return (
            path in self.exclude_paths or
            method in self.exclude_methods or
            any(excluded in path for excluded in self.exclude_paths)
        )
    
    async def _log_request(self, request: Request, correlation_id: str) -> None:
        """Log incoming request details."""
        try:
            # Basic request info
            log_data = {
                "correlation_id": correlation_id,
                "event_type": "http_request",
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_ip": self._get_client_ip(request),
                "user_agent": request.headers.get("User-Agent", "Unknown"),
                "content_type": request.headers.get("Content-Type"),
                "content_length": request.headers.get("Content-Length"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            # Add headers if enabled
            if self.log_headers:
                headers = dict(request.headers)
                if self.masker:
                    headers = self.masker.mask_dict(headers)
                log_data["headers"] = headers
            
            # Mask sensitive data in query params
            if self.masker and log_data["query_params"]:
                log_data["query_params"] = self.masker.mask_dict(log_data["query_params"])
            
            logger.bind(**log_data).info(
                f"REQUEST {request.method} {request.url.path} from {log_data['client_ip']}"
            )
            
        except Exception as e:
            logger.error(f"Error logging request: {str(e)}")
    
    async def _log_response(self,
                           request: Request,
                           response: Response,
                           correlation_id: str,
                           process_time_ms: float,
                           request_body: Optional[bytes] = None) -> None:
        """Log outgoing response details."""
        try:
            # Basic response info
            log_data = {
                "correlation_id": correlation_id,
                "event_type": "http_response",
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time_ms": process_time_ms,
                "response_headers": dict(response.headers) if self.log_headers else None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            # Add request body if captured
            if request_body and self.log_request_body:
                try:
                    if len(request_body) <= self.max_body_size:
                        # Try to parse as JSON
                        try:
                            body_data = json.loads(request_body.decode('utf-8'))
                            if self.masker:
                                body_data = self.masker.mask_dict(body_data)
                            log_data["request_body"] = body_data
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # Log as string if not JSON
                            body_str = request_body.decode('utf-8', errors='replace')
                            if self.masker:
                                body_str = self.masker.mask_string(body_str)
                            log_data["request_body"] = body_str[:self.max_body_size]
                    else:
                        log_data["request_body"] = f"[BODY TOO LARGE: {len(request_body)} bytes]"
                except Exception:
                    log_data["request_body"] = "[UNABLE TO DECODE BODY]"
            
            # Determine log level based on status code
            if response.status_code >= 500:
                log_level = "ERROR"
            elif response.status_code >= 400:
                log_level = "WARNING" 
            else:
                log_level = "INFO"
            
            logger.bind(**log_data).log(
                log_level,
                f"RESPONSE {request.method} {request.url.path} - "
                f"Status: {response.status_code} - Time: {process_time_ms:.2f}ms"
            )
            
        except Exception as e:
            logger.error(f"Error logging response: {str(e)}")
    
    async def _log_error(self,
                        request: Request,
                        error: Exception,
                        correlation_id: str,
                        process_time_ms: float) -> None:
        """Log request processing errors."""
        try:
            import traceback
            
            log_data = {
                "correlation_id": correlation_id,
                "event_type": "http_error",
                "method": request.method,
                "path": request.url.path,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "process_time_ms": process_time_ms,
                "traceback": traceback.format_exc(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            logger.bind(**log_data).error(
                f"ERROR {request.method} {request.url.path} - "
                f"{type(error).__name__}: {str(error)} - Time: {process_time_ms:.2f}ms"
            )
            
        except Exception as e:
            logger.error(f"Error logging error: {str(e)}")
    
    async def _log_performance_warning(self,
                                     request: Request,
                                     response: Response,
                                     correlation_id: str,
                                     process_time_ms: float) -> None:
        """Log performance warnings for slow requests."""
        try:
            log_data = {
                "correlation_id": correlation_id,
                "event_type": "performance_warning",
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time_ms": process_time_ms,
                "threshold_ms": self.performance_threshold_ms,
                "performance_issue": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            logger.bind(**log_data).warning(
                f"SLOW REQUEST {request.method} {request.url.path} - "
                f"Time: {process_time_ms:.2f}ms (threshold: {self.performance_threshold_ms}ms)"
            )
            
        except Exception as e:
            logger.error(f"Error logging performance warning: {str(e)}")
    
    
    async def _capture_request_body(self, request: Request) -> Optional[bytes]:
        """Capture request body for logging."""
        try:
            # Only capture if content length is reasonable
            content_length = request.headers.get("Content-Length")
            if content_length and int(content_length) > self.max_body_size:
                return None
            
            # Read body
            body = await request.body()
            
            # Reconstruct request with body (for downstream processing)
            async def receive():
                return {"type": "http.request", "body": body}
            
            request._receive = receive
            return body
            
        except Exception as e:
            logger.error(f"Error capturing request body: {str(e)}")
            return None
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers."""
        # Check for forwarded headers first
        forwarded_headers = [
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
            "CF-Connecting-IP", "True-Client-IP"
        ]
        
        for header in forwarded_headers:
            ip = request.headers.get(header)
            if ip:
                return ip.split(',')[0].strip()
        
        if request.client:
            return request.client.host
        
        return "unknown"


class ErrorLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware specifically for error logging and handling."""
    
    def __init__(self, app, include_traceback: bool = True, mask_sensitive: bool = True):
        """
        Initialize error logging middleware.
        
        Args:
            app: FastAPI application instance
            include_traceback: Whether to include full traceback in logs
            mask_sensitive: Whether to mask sensitive data in error logs
        """
        super().__init__(app)
        self.include_traceback = include_traceback
        self.masker = SensitiveDataMasker() if mask_sensitive else None
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with error logging."""
        try:
            return await call_next(request)
        except Exception as e:
            await self._log_unhandled_error(request, e)
            
            # Return generic error response
            correlation_id = get_correlation_id() or "unknown"
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "correlation_id": correlation_id
                },
                headers={"X-Request-ID": correlation_id}
            )
    
    async def _log_unhandled_error(self, request: Request, error: Exception) -> None:
        """Log unhandled application errors."""
        try:
            import traceback
            
            correlation_id = get_correlation_id() or "unknown"
            
            log_data = {
                "correlation_id": correlation_id,
                "event_type": "unhandled_error",
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "error_type": type(error).__name__,
                "error_message": str(error),
                "client_ip": self._get_client_ip(request),
                "user_agent": request.headers.get("User-Agent", "Unknown"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            if self.include_traceback:
                log_data["traceback"] = traceback.format_exc()
            
            # Mask sensitive data
            if self.masker:
                log_data["query_params"] = self.masker.mask_dict(log_data["query_params"])
            
            logger.bind(**log_data).error(
                f"UNHANDLED ERROR {request.method} {request.url.path} - "
                f"{type(error).__name__}: {str(error)}"
            )
            
        except Exception as e:
            logger.error(f"Error logging unhandled error: {str(e)}")
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers."""
        forwarded_headers = [
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
            "CF-Connecting-IP", "True-Client-IP"
        ]
        
        for header in forwarded_headers:
            ip = request.headers.get(header)
            if ip:
                return ip.split(',')[0].strip()
        
        if request.client:
            return request.client.host
        
        return "unknown"