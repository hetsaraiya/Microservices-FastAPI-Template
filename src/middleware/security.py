"""
Security Middleware for FastAPI Application

This module provides comprehensive security monitoring and protection middleware,
including attack detection, rate limiting, and security event logging.
"""

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field


class SecurityEventType(str, Enum):
    """Types of security events."""
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    INVALID_INPUT = "invalid_input"
    MALICIOUS_PAYLOAD = "malicious_payload"
    IP_BLOCKED = "ip_blocked"
    CSRF_ATTEMPT = "csrf_attempt"


class SecurityEventSeverity(str, Enum):
    """Severity levels for security events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""
    requests_per_minute: int = Field(default=60, description="Maximum requests per minute")
    requests_per_hour: int = Field(default=1000, description="Maximum requests per hour")
    burst_limit: int = Field(default=10, description="Maximum burst requests")
    window_size_minutes: int = Field(default=1, description="Time window in minutes")
    block_duration_minutes: int = Field(default=15, description="Block duration in minutes")


class AttackPatterns(BaseModel):
    """Configuration for attack pattern detection."""
    sql_injection_patterns: List[str] = Field(default_factory=lambda: [
        "union select", "drop table", "delete from", "insert into",
        "'or'1'='1", "' or 1=1", "admin'--", "' union select",
        "exec(", "execute(", "sp_", "xp_", "@@version",
        "information_schema", "sys.tables", "sys.columns"
    ])
    
    xss_patterns: List[str] = Field(default_factory=lambda: [
        "<script", "javascript:", "onload=", "onerror=", "onclick=",
        "eval(", "document.cookie", "window.location", "alert(",
        "confirm(", "prompt(", "innerHTML", "outerHTML"
    ])
    
    path_traversal_patterns: List[str] = Field(default_factory=lambda: [
        "../", "..\\", "%2e%2e%2f", "%2e%2e%5c", "....//",
        "..\\..\\", "..%2f..%2f", "..%5c..%5c"
    ])
    
    suspicious_user_agents: List[str] = Field(default_factory=lambda: [
        "sqlmap", "nikto", "nmap", "burp", "zap", "dirb", "gobuster",
        "wpscan", "curl", "wget", "python-requests", "masscan",
        "nessus", "openvas", "acunetix", "w3af"
    ])


class SecurityConfig(BaseModel):
    """Configuration for security middleware."""
    enable_attack_detection: bool = Field(default=True, description="Enable attack pattern detection")
    enable_rate_limiting: bool = Field(default=True, description="Enable rate limiting")
    enable_ip_blocking: bool = Field(default=True, description="Enable IP blocking")
    enable_user_agent_filtering: bool = Field(default=True, description="Enable user agent filtering")
    
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    attack_patterns: AttackPatterns = Field(default_factory=AttackPatterns)
    
    blocked_ips: Set[str] = Field(default_factory=set, description="List of blocked IP addresses")
    whitelist_ips: Set[str] = Field(default_factory=set, description="List of whitelisted IP addresses")
    
    max_request_size_mb: float = Field(default=10.0, description="Maximum request size in MB")
    block_empty_user_agents: bool = Field(default=False, description="Block requests with empty user agents")
    
    exclude_paths: Set[str] = Field(default_factory=lambda: {
        "/health", "/metrics", "/favicon.ico", "/robots.txt"
    }, description="Paths to exclude from security monitoring")


class SecurityEventLogger:
    """Logger for security events."""
    
    def __init__(self):
        """Initialize security event logger."""
        self.logger = logger.bind(component="security", security_event=True)
    
    def log_security_event(self,
                          event_type: SecurityEventType,
                          severity: SecurityEventSeverity,
                          message: str,
                          client_ip: str,
                          user_agent: Optional[str] = None,
                          path: Optional[str] = None,
                          payload: Optional[str] = None,
                          additional_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a security event."""
        event_data = {
            "event_type": event_type.value,
            "severity": severity.value,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "path": path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        if payload:
            # Sanitize and limit payload size for logging
            sanitized_payload = payload[:500] + "..." if len(payload) > 500 else payload
            event_data["payload"] = sanitized_payload
        
        if additional_data:
            event_data.update(additional_data)
        
        # Remove None values
        event_data = {k: v for k, v in event_data.items() if v is not None}
        
        # Log with appropriate level
        log_level = self._get_log_level(severity)
        self.logger.bind(**event_data).log(log_level, f"SECURITY EVENT: {message}")
    
    def _get_log_level(self, severity: SecurityEventSeverity) -> str:
        """Convert severity to log level."""
        severity_map = {
            SecurityEventSeverity.LOW: "INFO",
            SecurityEventSeverity.MEDIUM: "WARNING", 
            SecurityEventSeverity.HIGH: "ERROR",
            SecurityEventSeverity.CRITICAL: "CRITICAL"
        }
        return severity_map.get(severity, "WARNING")


class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for FastAPI."""
    
    def __init__(self, app, config: Optional[SecurityConfig] = None):
        """
        Initialize security middleware.
        
        Args:
            app: FastAPI application instance
            config: Security configuration
        """
        super().__init__(app)
        self.config = config or SecurityConfig()
        self.event_logger = SecurityEventLogger()
        
        # Rate limiting storage
        self._rate_limit_storage: Dict[str, deque] = defaultdict(deque)
        self._blocked_ips: Dict[str, datetime] = {}
        
        # Attack detection counters
        self._attack_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        logger.info("Security middleware initialized", extra={
            "attack_detection": self.config.enable_attack_detection,
            "rate_limiting": self.config.enable_rate_limiting,
            "ip_blocking": self.config.enable_ip_blocking
        })
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through security checks."""
        # Skip security checks for excluded paths
        if self._should_exclude_path(request.url.path):
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        
        # Check if IP is whitelisted
        if client_ip in self.config.whitelist_ips:
            return await call_next(request)
        
        # Security checks
        security_response = await self._perform_security_checks(request, client_ip, user_agent)
        if security_response:
            return security_response
        
        # Process request if all security checks pass
        return await call_next(request)
    
    async def _perform_security_checks(self, 
                                     request: Request, 
                                     client_ip: str, 
                                     user_agent: str) -> Optional[Response]:
        """Perform all security checks and return response if blocked."""
        
        # 1. Check if IP is blocked
        if self.config.enable_ip_blocking and self._is_ip_blocked(client_ip):
            self.event_logger.log_security_event(
                event_type=SecurityEventType.IP_BLOCKED,
                severity=SecurityEventSeverity.HIGH,
                message=f"Blocked IP {client_ip} attempted access",
                client_ip=client_ip,
                user_agent=user_agent,
                path=request.url.path
            )
            return self._create_blocked_response("IP blocked due to security violations")
        
        # 2. Rate limiting check
        if self.config.enable_rate_limiting and self._check_rate_limit(client_ip, request.url.path):
            self.event_logger.log_security_event(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=SecurityEventSeverity.MEDIUM,
                message=f"Rate limit exceeded for IP {client_ip}",
                client_ip=client_ip,
                user_agent=user_agent,
                path=request.url.path,
                additional_data={
                    "rate_limit": self.config.rate_limit.requests_per_minute,
                    "window": "1 minute"
                }
            )
            return self._create_rate_limit_response()
        
        # 3. User agent filtering
        if self.config.enable_user_agent_filtering and self._is_suspicious_user_agent(user_agent):
            self.event_logger.log_security_event(
                event_type=SecurityEventType.SUSPICIOUS_USER_AGENT,
                severity=SecurityEventSeverity.MEDIUM,
                message=f"Suspicious user agent detected: {user_agent}",
                client_ip=client_ip,
                user_agent=user_agent,
                path=request.url.path
            )
            self._increment_attack_counter(client_ip, "suspicious_user_agent")
        
        # 4. Attack pattern detection
        if self.config.enable_attack_detection:
            attack_response = await self._detect_attacks(request, client_ip, user_agent)
            if attack_response:
                return attack_response
        
        # 5. Request size validation
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                size_mb = int(content_length) / (1024 * 1024)
                if size_mb > self.config.max_request_size_mb:
                    self.event_logger.log_security_event(
                        event_type=SecurityEventType.INVALID_INPUT,
                        severity=SecurityEventSeverity.MEDIUM,
                        message=f"Request size {size_mb:.2f}MB exceeds limit",
                        client_ip=client_ip,
                        user_agent=user_agent,
                        path=request.url.path
                    )
                    return self._create_blocked_response("Request too large")
            except ValueError:
                pass
        
        return None  # All checks passed
    
    async def _detect_attacks(self, 
                            request: Request, 
                            client_ip: str, 
                            user_agent: str) -> Optional[Response]:
        """Detect various attack patterns."""
        path = request.url.path.lower()
        query = str(request.url.query).lower() if request.url.query else ""
        
        # Combine path and query for analysis
        full_url = f"{path}?{query}" if query else path
        
        # SQL Injection Detection
        for pattern in self.config.attack_patterns.sql_injection_patterns:
            if pattern in full_url:
                self.event_logger.log_security_event(
                    event_type=SecurityEventType.SQL_INJECTION_ATTEMPT,
                    severity=SecurityEventSeverity.HIGH,
                    message=f"SQL injection attempt detected from {client_ip}",
                    client_ip=client_ip,
                    user_agent=user_agent,
                    path=request.url.path,
                    payload=full_url,
                    additional_data={"detected_pattern": pattern}
                )
                self._increment_attack_counter(client_ip, "sql_injection")
                return self._create_blocked_response("Malicious request detected")
        
        # XSS Detection
        for pattern in self.config.attack_patterns.xss_patterns:
            if pattern in full_url:
                self.event_logger.log_security_event(
                    event_type=SecurityEventType.XSS_ATTEMPT,
                    severity=SecurityEventSeverity.HIGH,
                    message=f"XSS attempt detected from {client_ip}",
                    client_ip=client_ip,
                    user_agent=user_agent,
                    path=request.url.path,
                    payload=full_url,
                    additional_data={"detected_pattern": pattern}
                )
                self._increment_attack_counter(client_ip, "xss")
                return self._create_blocked_response("Malicious request detected")
        
        # Path Traversal Detection
        for pattern in self.config.attack_patterns.path_traversal_patterns:
            if pattern in path:
                self.event_logger.log_security_event(
                    event_type=SecurityEventType.PATH_TRAVERSAL_ATTEMPT,
                    severity=SecurityEventSeverity.HIGH,
                    message=f"Path traversal attempt detected from {client_ip}",
                    client_ip=client_ip,
                    user_agent=user_agent,
                    path=request.url.path,
                    payload=path,
                    additional_data={"detected_pattern": pattern}
                )
                self._increment_attack_counter(client_ip, "path_traversal")
                return self._create_blocked_response("Malicious request detected")
        
        return None
    
    def _check_rate_limit(self, client_ip: str, path: str) -> bool:
        """Check if client IP exceeds rate limit."""
        current_time = time.time()
        window_start = current_time - (self.config.rate_limit.window_size_minutes * 60)
        
        # Clean old entries
        requests = self._rate_limit_storage[client_ip]
        while requests and requests[0] < window_start:
            requests.popleft()
        
        # Check rate limit
        if len(requests) >= self.config.rate_limit.requests_per_minute:
            # Block IP temporarily
            self._blocked_ips[client_ip] = datetime.now() + timedelta(
                minutes=self.config.rate_limit.block_duration_minutes
            )
            return True
        
        # Add current request
        requests.append(current_time)
        return False
    
    def _is_ip_blocked(self, client_ip: str) -> bool:
        """Check if IP is currently blocked."""
        if client_ip in self.config.blocked_ips:
            return True
        
        if client_ip in self._blocked_ips:
            if datetime.now() > self._blocked_ips[client_ip]:
                # Block expired, remove it
                del self._blocked_ips[client_ip]
                return False
            return True
        
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious."""
        if not user_agent and self.config.block_empty_user_agents:
            return True
        
        user_agent_lower = user_agent.lower()
        for suspicious_agent in self.config.attack_patterns.suspicious_user_agents:
            if suspicious_agent in user_agent_lower:
                return True
        
        return False
    
    def _increment_attack_counter(self, client_ip: str, attack_type: str) -> None:
        """Increment attack counter for IP and potentially block it."""
        self._attack_counters[client_ip][attack_type] += 1
        
        # Block IP if too many attacks
        total_attacks = sum(self._attack_counters[client_ip].values())
        if total_attacks >= 5:  # Configurable threshold
            self._blocked_ips[client_ip] = datetime.now() + timedelta(hours=1)
            self.event_logger.log_security_event(
                event_type=SecurityEventType.IP_BLOCKED,
                severity=SecurityEventSeverity.CRITICAL,
                message=f"IP {client_ip} blocked due to multiple attack attempts",
                client_ip=client_ip,
                additional_data={
                    "total_attacks": total_attacks,
                    "attack_breakdown": dict(self._attack_counters[client_ip])
                }
            )
    
    def _should_exclude_path(self, path: str) -> bool:
        """Check if path should be excluded from security monitoring."""
        return path in self.config.exclude_paths
    
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
    
    def _create_blocked_response(self, message: str = "Request blocked") -> Response:
        """Create a blocked request response."""
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden", 
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    def _create_rate_limit_response(self) -> Response:
        """Create a rate limit exceeded response."""
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "message": "Rate limit exceeded",
                "retry_after": self.config.rate_limit.window_size_minutes * 60,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            headers={"Retry-After": str(self.config.rate_limit.window_size_minutes * 60)}
        )
    
    def add_blocked_ip(self, ip: str) -> None:
        """Manually add IP to blocked list."""
        self.config.blocked_ips.add(ip)
        logger.info(f"IP {ip} added to blocked list")
    
    def remove_blocked_ip(self, ip: str) -> None:
        """Remove IP from blocked list."""
        self.config.blocked_ips.discard(ip)
        if ip in self._blocked_ips:
            del self._blocked_ips[ip]
        logger.info(f"IP {ip} removed from blocked list")
    
    def add_whitelist_ip(self, ip: str) -> None:
        """Add IP to whitelist."""
        self.config.whitelist_ips.add(ip)
        logger.info(f"IP {ip} added to whitelist")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        current_time = datetime.now()
        active_blocks = sum(
            1 for block_time in self._blocked_ips.values() 
            if current_time < block_time
        )
        
        return {
            "blocked_ips": len(self.config.blocked_ips),
            "temporarily_blocked_ips": active_blocks,
            "whitelisted_ips": len(self.config.whitelist_ips),
            "attack_counters": dict(self._attack_counters),
            "rate_limit_config": self.config.rate_limit.dict()
        }