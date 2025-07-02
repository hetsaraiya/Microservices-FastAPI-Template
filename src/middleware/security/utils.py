"""
Security Utilities Module

This module contains utility functions used across the security middleware.
"""

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qs, urlparse

from fastapi import Request
from fastapi.responses import JSONResponse


class SecurityUtils:
    """Utility class for common security operations."""
    
    @staticmethod
    def get_client_ip(request: Request) -> str:
        """
        Extract client IP from request headers, checking various proxy headers.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address as string
        """
        forwarded_headers = [
            "X-Forwarded-For", 
            "X-Real-IP", 
            "X-Client-IP",
            "CF-Connecting-IP", 
            "True-Client-IP",
            "X-Forwarded",
            "Forwarded-For",
            "Forwarded"
        ]
        
        for header in forwarded_headers:
            ip = request.headers.get(header)
            if ip:
                # Handle comma-separated IPs (X-Forwarded-For)
                first_ip = ip.split(',')[0].strip()
                if SecurityUtils.is_valid_ip(first_ip):
                    return first_ip
        
        # Fallback to request client
        if request.client and request.client.host:
            return request.client.host
        
        return "unknown"
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Basic IP address validation.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if IP appears valid, False otherwise
        """
        if not ip or ip == "unknown":
            return False
        
        # Basic IPv4 validation
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        # Basic IPv6 validation (simplified)
        if ':' in ip:
            return len(ip.split(':')) >= 3
        
        return False
    
    @staticmethod
    def extract_request_data(request: Request) -> dict:
        """
        Extract relevant data from request for security analysis.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Dictionary containing extracted request data
        """
        path = request.url.path.lower()
        query = str(request.url.query).lower() if request.url.query else ""
        user_agent = request.headers.get("User-Agent", "")
        
        return {
            "path": path,
            "query": query,
            "full_url": f"{path}?{query}" if query else path,
            "user_agent": user_agent,
            "method": request.method,
            "content_type": request.headers.get("Content-Type", ""),
            "content_length": request.headers.get("Content-Length"),
            "referer": request.headers.get("Referer", ""),
            "origin": request.headers.get("Origin", "")
        }
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string for safe logging and processing.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        
        # Remove control characters
        sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "... [truncated]"
        
        return sanitized
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP address is in private range.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is private, False otherwise
        """
        if not SecurityUtils.is_valid_ip(ip):
            return False
        
        try:
            parts = [int(part) for part in ip.split('.')]
            
            # Private IP ranges
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.0.0.0/8 (localhost)
            if parts[0] == 127:
                return True
                
        except (ValueError, IndexError):
            pass
        
        return False


class ResponseBuilder:
    """Builder class for creating standardized security responses."""
    
    @staticmethod
    def create_blocked_response(message: str = "Request blocked", 
                              status_code: int = 403,
                              additional_headers: Optional[dict] = None) -> JSONResponse:
        """
        Create a standardized blocked request response.
        
        Args:
            message: Error message to return
            status_code: HTTP status code
            additional_headers: Additional headers to include
            
        Returns:
            JSONResponse object
        """
        content = {
            "error": "Forbidden" if status_code == 403 else "Blocked", 
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "code": "SECURITY_BLOCK"
        }
        
        headers = additional_headers or {}
        
        return JSONResponse(
            status_code=status_code,
            content=content,
            headers=headers
        )
    
    @staticmethod
    def create_rate_limit_response(retry_after: int = 60,
                                 requests_limit: int = 60,
                                 time_window: str = "1 minute") -> JSONResponse:
        """
        Create a standardized rate limit exceeded response.
        
        Args:
            retry_after: Seconds to wait before retry
            requests_limit: Number of requests allowed
            time_window: Time window description
            
        Returns:
            JSONResponse object
        """
        content = {
            "error": "Too Many Requests",
            "message": f"Rate limit exceeded. Maximum {requests_limit} requests per {time_window}",
            "retry_after": retry_after,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "code": "RATE_LIMIT_EXCEEDED"
        }
        
        headers = {
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": str(requests_limit),
            "X-RateLimit-Window": time_window
        }
        
        return JSONResponse(
            status_code=429,
            content=content,
            headers=headers
        )
    
    @staticmethod
    def create_attack_response(attack_type: str = "malicious_request") -> JSONResponse:
        """
        Create a response for detected attacks.
        
        Args:
            attack_type: Type of attack detected
            
        Returns:
            JSONResponse object
        """
        return ResponseBuilder.create_blocked_response(
            message="Malicious request detected and blocked",
            additional_headers={"X-Security-Block-Reason": attack_type}
        )