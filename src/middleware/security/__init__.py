"""
Security Middleware Package

This package provides comprehensive security middleware for FastAPI applications.

Components:
- SecurityMiddleware: Main middleware class
- AttackDetector: Detects various attack patterns
- RateLimiter: Implements rate limiting with sliding windows
- IPFilter: Manages IP blocking and whitelisting
- UserAgentFilter: Analyzes and filters user agents
- SecurityEventLogger: Structured security event logging
- SecurityConfig: Configuration management

Usage:
    from src.middleware.security import SecurityMiddleware, SecurityConfig
    
    config = SecurityConfig(
        enable_attack_detection=True,
        enable_rate_limiting=True,
        enable_ip_blocking=True
    )
    
    app.add_middleware(SecurityMiddleware, config=config)
"""

from .config import SecurityConfig, RateLimitConfig, AttackPatterns
from .enums import (
    SecurityEventType, 
    SecurityEventSeverity, 
    AttackType, 
    BlockReason
)
from .logger import SecurityEventLogger
from .middleware import SecurityMiddleware
from .utils import SecurityUtils, ResponseBuilder
from .detectors import (
    AttackDetector,
    IPFilter,
    RateLimiter,
    UserAgentFilter
)

__version__ = "1.0.0"

__all__ = [
    # Main middleware
    "SecurityMiddleware",
    
    # Configuration
    "SecurityConfig",
    "RateLimitConfig", 
    "AttackPatterns",
    
    # Enums
    "SecurityEventType",
    "SecurityEventSeverity",
    "AttackType",
    "BlockReason",
    
    # Components
    "SecurityEventLogger",
    "SecurityUtils",
    "ResponseBuilder",
    
    # Detectors
    "AttackDetector",
    "IPFilter",
    "RateLimiter",
    "UserAgentFilter"
]
