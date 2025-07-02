"""
Security Enums Module

This module contains all enumeration classes used in the security middleware.
"""

from enum import Enum


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


class AttackType(str, Enum):
    """Types of detected attacks."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    MALICIOUS_PAYLOAD = "malicious_payload"


class BlockReason(str, Enum):
    """Reasons for blocking requests."""
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    IP_BLOCKED = "ip_blocked"
    MALICIOUS_REQUEST = "malicious_request"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    REQUEST_TOO_LARGE = "request_too_large"
    ATTACK_DETECTED = "attack_detected"
