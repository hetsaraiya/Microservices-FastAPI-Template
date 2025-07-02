"""
Main Security Middleware Module

This module provides the main SecurityMiddleware class that orchestrates all security components.
"""

from typing import Any, Callable, Dict, Optional
from fastapi import Request, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware

from .config import SecurityConfig
from .detectors import AttackDetector, IPFilter, RateLimiter, UserAgentFilter
from .enums import SecurityEventSeverity, SecurityEventType
from .logger import SecurityEventLogger
from .utils import ResponseBuilder, SecurityUtils


class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware orchestrating all security components."""
    
    def __init__(self, app, config: Optional[SecurityConfig] = None):
        """
        Initialize security middleware.
        
        Args:
            app: FastAPI application instance
            config: Security configuration
        """
        super().__init__(app)
        self.config = config or SecurityConfig()
        
        # Initialize components
        self.event_logger = SecurityEventLogger()
        self.attack_detector = AttackDetector(self.config.attack_patterns)
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        self.ip_filter = IPFilter(
            self.config.blocked_ips,
            self.config.whitelist_ips,
            self.config.attack_threshold,
            self.config.temporary_block_hours
        )
        self.user_agent_filter = UserAgentFilter(
            self.config.attack_patterns,
            self.config.block_empty_user_agents
        )
        
        logger.info("Security middleware initialized", extra={
            "attack_detection": self.config.enable_attack_detection,
            "rate_limiting": self.config.enable_rate_limiting,
            "ip_blocking": self.config.enable_ip_blocking,
            "user_agent_filtering": self.config.enable_user_agent_filtering
        })
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through security checks."""
        # Skip security checks for excluded paths
        if self._should_exclude_path(request.url.path):
            return await call_next(request)
        
        client_ip = SecurityUtils.get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        
        # Check if IP is whitelisted (skip all other checks)
        if self.ip_filter.is_whitelisted(client_ip):
            return await call_next(request)
        
        # Perform security checks
        security_response = await self._perform_security_checks(request, client_ip, user_agent)
        if security_response:
            return security_response
        
        # All security checks passed, process the request
        return await call_next(request)
    
    async def _perform_security_checks(self, 
                                     request: Request, 
                                     client_ip: str, 
                                     user_agent: str) -> Optional[Response]:
        """Perform all security checks and return response if blocked."""
        
        # 1. IP Blocking Check
        if self.config.enable_ip_blocking:
            blocked_response = self._check_ip_blocking(request, client_ip, user_agent)
            if blocked_response:
                return blocked_response
        
        # 2. Rate Limiting Check
        if self.config.enable_rate_limiting:
            rate_limit_response = self._check_rate_limiting(request, client_ip, user_agent)
            if rate_limit_response:
                return rate_limit_response
        
        # 3. User Agent Filtering Check
        if self.config.enable_user_agent_filtering:
            user_agent_response = self._check_user_agent(request, client_ip, user_agent)
            if user_agent_response:
                return user_agent_response
        
        # 4. Request Size Validation
        size_response = self._check_request_size(request, client_ip, user_agent)
        if size_response:
            return size_response
        
        # 5. Attack Pattern Detection
        if self.config.enable_attack_detection:
            attack_response = await self._check_attack_patterns(request, client_ip, user_agent)
            if attack_response:
                return attack_response
        
        return None  # All checks passed
    
    def _check_ip_blocking(self, request: Request, client_ip: str, user_agent: str) -> Optional[Response]:
        """Check IP blocking rules."""
        is_blocked, reason = self.ip_filter.is_blocked(client_ip)
        
        if is_blocked:
            self.event_logger.log_ip_block(
                client_ip=client_ip,
                reason=reason or "blocked_ip",
                block_duration=None
            )
            
            return ResponseBuilder.create_blocked_response(
                message=f"IP blocked: {reason}",
                additional_headers={"X-Block-Reason": reason or "blocked"}
            )
        
        return None
    
    def _check_rate_limiting(self, request: Request, client_ip: str, user_agent: str) -> Optional[Response]:
        """Check rate limiting rules."""
        is_limited, limit_info = self.rate_limiter.is_rate_limited(client_ip, request.url.path)
        
        if is_limited:
            retry_after = limit_info.get("retry_after", 60)
            limit = limit_info.get("limit", self.config.rate_limit.requests_per_minute)
            window = limit_info.get("window", f"{self.config.rate_limit.window_size_minutes} minute(s)")
            
            self.event_logger.log_rate_limit_exceeded(
                client_ip=client_ip,
                user_agent=user_agent,
                path=request.url.path,
                requests_count=limit,
                time_window=window
            )
            
            return ResponseBuilder.create_rate_limit_response(
                retry_after=retry_after,
                requests_limit=limit,
                time_window=window
            )
        
        return None
    
    def _check_user_agent(self, request: Request, client_ip: str, user_agent: str) -> Optional[Response]:
        """Check user agent filtering rules."""
        is_suspicious, details = self.user_agent_filter.is_suspicious(user_agent, client_ip)
        
        if is_suspicious:
            severity = SecurityEventSeverity.HIGH if details.get("severity") == "high" else SecurityEventSeverity.MEDIUM
            
            self.event_logger.log_security_event(
                event_type=SecurityEventType.SUSPICIOUS_USER_AGENT,
                severity=severity,
                message=f"Suspicious user agent detected: {details.get('reason', 'unknown')}",
                client_ip=client_ip,
                user_agent=user_agent,
                path=request.url.path,
                additional_data=details
            )
            
            # Record attack for potential IP blocking
            self.ip_filter.add_attack(client_ip, "suspicious_user_agent")
            
            # Only block for high severity
            if details.get("severity") == "high":
                return ResponseBuilder.create_attack_response("suspicious_user_agent")
        
        return None
    
    def _check_request_size(self, request: Request, client_ip: str, user_agent: str) -> Optional[Response]:
        """Check request size limits."""
        content_length = request.headers.get("Content-Length")
        
        if content_length:
            try:
                size_mb = int(content_length) / (1024 * 1024)
                if size_mb > self.config.max_request_size_mb:
                    self.event_logger.log_security_event(
                        event_type=SecurityEventType.INVALID_INPUT,
                        severity=SecurityEventSeverity.MEDIUM,
                        message=f"Request size {size_mb:.2f}MB exceeds limit of {self.config.max_request_size_mb}MB",
                        client_ip=client_ip,
                        user_agent=user_agent,
                        path=request.url.path,
                        additional_data={"size_mb": size_mb, "limit_mb": self.config.max_request_size_mb}
                    )
                    
                    return ResponseBuilder.create_blocked_response(
                        message="Request too large",
                        additional_headers={"X-Block-Reason": "request_too_large"}
                    )
            except ValueError:
                pass
        
        return None
    
    async def _check_attack_patterns(self, request: Request, client_ip: str, user_agent: str) -> Optional[Response]:
        """Check for attack patterns in the request."""
        detected_attacks = self.attack_detector.detect_attacks(request)
        
        for attack in detected_attacks:
            attack_type = attack.get("attack_type")
            event_type = attack.get("event_type")
            detected_pattern = attack.get("detected_pattern")
            payload = attack.get("payload")
            confidence = attack.get("confidence", 0.7)
            
            # Log the attack
            severity = SecurityEventSeverity.HIGH if confidence >= 0.8 else SecurityEventSeverity.MEDIUM
            
            self.event_logger.log_attack_attempt(
                attack_type=attack_type,
                client_ip=client_ip,
                user_agent=user_agent,
                path=request.url.path,
                detected_pattern=detected_pattern,
                payload=payload
            )
            
            # Record attack for IP tracking
            self.ip_filter.add_attack(client_ip, attack_type)
            
            # Block the request
            return ResponseBuilder.create_attack_response(attack_type)
        
        return None
    
    def _should_exclude_path(self, path: str) -> bool:
        """Check if path should be excluded from security monitoring."""
        return path in self.config.exclude_paths
    
    # Management methods
    def add_blocked_ip(self, ip: str) -> None:
        """Manually add IP to blocked list."""
        self.ip_filter.add_permanent_block(ip)
        logger.info(f"IP {ip} added to blocked list")
    
    def remove_blocked_ip(self, ip: str) -> None:
        """Remove IP from blocked list."""
        self.ip_filter.remove_permanent_block(ip)
        self.ip_filter.unblock_temporary(ip)
        logger.info(f"IP {ip} removed from blocked list")
    
    def add_whitelist_ip(self, ip: str) -> None:
        """Add IP to whitelist."""
        self.ip_filter.add_whitelist(ip)
        logger.info(f"IP {ip} added to whitelist")
    
    def remove_whitelist_ip(self, ip: str) -> None:
        """Remove IP from whitelist."""
        self.ip_filter.remove_whitelist(ip)
        logger.info(f"IP {ip} removed from whitelist")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get comprehensive security statistics."""
        return {
            "ip_filter": self.ip_filter.get_blocked_ips_info(),
            "rate_limiter": self.rate_limiter.get_statistics(),
            "user_agent_filter": self.user_agent_filter.get_user_agent_stats(),
            "attack_detection": {
                "enabled": self.config.enable_attack_detection,
                "patterns_loaded": len(self.config.attack_patterns.sql_injection_patterns) +
                                 len(self.config.attack_patterns.xss_patterns) +
                                 len(self.config.attack_patterns.path_traversal_patterns)
            },
            "top_attackers": self.ip_filter.get_top_attackers(10),
            "suspicious_user_agents": self.user_agent_filter.get_suspicious_agents(10)
        }
    
    def cleanup_old_data(self) -> None:
        """Clean up old data from all components."""
        self.rate_limiter.cleanup_old_entries()
        self.ip_filter.cleanup_old_data()
        self.user_agent_filter.cleanup_old_data()
        logger.info("Security middleware data cleanup completed")
