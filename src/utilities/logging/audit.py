"""
Security Audit Logging

This module provides specialized logging for security events, authentication
attempts, authorization failures, and other security-related activities.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from fastapi import Request
from loguru import logger

from .context import get_correlation_id, get_current_context
from .formatters import SensitiveDataMasker


class SecurityEventType(str, Enum):
    """Types of security events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_CREATION = "token_creation"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOCATION = "token_revocation"
    AUTHORIZATION_SUCCESS = "authorization_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_SUCCESS = "password_reset_success"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_HIJACK_ATTEMPT = "session_hijack_attempt"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_ATTEMPT = "csrf_attempt"


class SecurityEventSeverity(str, Enum):
    """Severity levels for security events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAuditLogger:
    """Specialized logger for security audit events."""
    
    def __init__(self, logger_instance=None):
        """
        Initialize security audit logger.
        
        Args:
            logger_instance: Logger instance to use
        """
        self.logger = logger_instance or logger
        self.masker = SensitiveDataMasker()
    
    def log_security_event(self,
                          event_type: SecurityEventType,
                          severity: SecurityEventSeverity,
                          message: str,
                          user_id: Optional[str] = None,
                          client_ip: Optional[str] = None,
                          user_agent: Optional[str] = None,
                          resource: Optional[str] = None,
                          additional_data: Optional[Dict[str, Any]] = None,
                          request: Optional[Request] = None) -> None:
        """
        Log a security event with structured data.
        
        Args:
            event_type: Type of security event
            severity: Severity level of the event
            message: Human-readable message
            user_id: ID of the user involved (if applicable)
            client_ip: Client IP address
            user_agent: User agent string
            resource: Resource being accessed/modified
            additional_data: Additional event-specific data
            request: FastAPI Request object (if available)
        """
        # Get context information
        correlation_id = get_correlation_id() or "no-correlation"
        context = get_current_context()
        
        # Extract information from request if provided
        if request:
            client_ip = client_ip or self._get_client_ip(request)
            user_agent = user_agent or request.headers.get("User-Agent", "Unknown")
        
        # Build audit log entry
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": event_type.value,
            "severity": severity.value,
            "message": message,
            "security_event": True,
            "user_id": user_id or context.get("user_id"),
            "client_ip": client_ip or context.get("client_ip"),
            "user_agent": user_agent or context.get("user_agent"),
            "resource": resource,
            "session_id": context.get("session_id"),
            "request_path": context.get("request_path"),
            "request_method": context.get("request_method"),
        }
        
        # Add additional data if provided
        if additional_data:
            # Mask sensitive data in additional_data
            masked_data = self.masker.mask_dict(additional_data)
            audit_entry["additional_data"] = masked_data
        
        # Remove None values
        audit_entry = {k: v for k, v in audit_entry.items() if v is not None}
        
        # Log with appropriate level based on severity
        log_level = self._get_log_level(severity)
        self.logger.bind(**audit_entry).log(log_level, f"SECURITY: {message}")
    
    def log_authentication_success(self,
                                 user_id: str,
                                 login_method: str = "password",
                                 client_ip: Optional[str] = None,
                                 user_agent: Optional[str] = None,
                                 request: Optional[Request] = None) -> None:
        """Log successful authentication."""
        self.log_security_event(
            event_type=SecurityEventType.LOGIN_SUCCESS,
            severity=SecurityEventSeverity.LOW,
            message=f"User {user_id} successfully authenticated via {login_method}",
            user_id=user_id,
            client_ip=client_ip,
            user_agent=user_agent,
            additional_data={"login_method": login_method},
            request=request
        )
    
    def log_authentication_failure(self,
                                 username: str,
                                 reason: str,
                                 client_ip: Optional[str] = None,
                                 user_agent: Optional[str] = None,
                                 request: Optional[Request] = None) -> None:
        """Log failed authentication attempt."""
        self.log_security_event(
            event_type=SecurityEventType.LOGIN_FAILURE,
            severity=SecurityEventSeverity.MEDIUM,
            message=f"Authentication failed for user {username}: {reason}",
            client_ip=client_ip,
            user_agent=user_agent,
            additional_data={
                "attempted_username": username,
                "failure_reason": reason
            },
            request=request
        )
    
    def log_authorization_failure(self,
                                user_id: str,
                                resource: str,
                                required_permission: str,
                                client_ip: Optional[str] = None,
                                request: Optional[Request] = None) -> None:
        """Log authorization failure."""
        self.log_security_event(
            event_type=SecurityEventType.AUTHORIZATION_FAILURE,
            severity=SecurityEventSeverity.MEDIUM,
            message=f"User {user_id} denied access to {resource}",
            user_id=user_id,
            client_ip=client_ip,
            resource=resource,
            additional_data={"required_permission": required_permission},
            request=request
        )
    
    def log_suspicious_activity(self,
                              description: str,
                              severity: SecurityEventSeverity = SecurityEventSeverity.HIGH,
                              user_id: Optional[str] = None,
                              client_ip: Optional[str] = None,
                              indicators: Optional[List[str]] = None,
                              request: Optional[Request] = None) -> None:
        """Log suspicious activity."""
        additional_data = {}
        if indicators:
            additional_data["indicators"] = indicators
        
        self.log_security_event(
            event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
            severity=severity,
            message=f"Suspicious activity detected: {description}",
            user_id=user_id,
            client_ip=client_ip,
            additional_data=additional_data,
            request=request
        )
    
    def log_rate_limit_exceeded(self,
                              client_ip: str,
                              endpoint: str,
                              limit: int,
                              window_seconds: int,
                              user_id: Optional[str] = None,
                              request: Optional[Request] = None) -> None:
        """Log rate limit violations."""
        self.log_security_event(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity=SecurityEventSeverity.MEDIUM,
            message=f"Rate limit exceeded for {endpoint} from {client_ip}",
            user_id=user_id,
            client_ip=client_ip,
            resource=endpoint,
            additional_data={
                "limit": limit,
                "window_seconds": window_seconds,
                "endpoint": endpoint
            },
            request=request
        )
    
    def log_data_access(self,
                       user_id: str,
                       resource: str,
                       operation: str,
                       record_count: Optional[int] = None,
                       client_ip: Optional[str] = None,
                       request: Optional[Request] = None) -> None:
        """Log data access events."""
        additional_data = {"operation": operation}
        if record_count is not None:
            additional_data["record_count"] = record_count
        
        self.log_security_event(
            event_type=SecurityEventType.DATA_ACCESS,
            severity=SecurityEventSeverity.LOW,
            message=f"User {user_id} accessed {resource} ({operation})",
            user_id=user_id,
            client_ip=client_ip,
            resource=resource,
            additional_data=additional_data,
            request=request
        )
    
    def log_data_modification(self,
                            user_id: str,
                            resource: str,
                            operation: str,
                            record_ids: Optional[List[str]] = None,
                            changes: Optional[Dict[str, Any]] = None,
                            client_ip: Optional[str] = None,
                            request: Optional[Request] = None) -> None:
        """Log data modification events."""
        additional_data = {"operation": operation}
        
        if record_ids:
            additional_data["affected_records"] = record_ids
        
        if changes:
            # Mask sensitive data in changes
            additional_data["changes"] = self.masker.mask_dict(changes)
        
        self.log_security_event(
            event_type=SecurityEventType.DATA_MODIFICATION,
            severity=SecurityEventSeverity.MEDIUM,
            message=f"User {user_id} modified {resource} ({operation})",
            user_id=user_id,
            client_ip=client_ip,
            resource=resource,
            additional_data=additional_data,
            request=request
        )
    
    def log_brute_force_attempt(self,
                              client_ip: str,
                              username: str,
                              attempt_count: int,
                              time_window_minutes: int,
                              request: Optional[Request] = None) -> None:
        """Log brute force attack attempts."""
        self.log_security_event(
            event_type=SecurityEventType.BRUTE_FORCE_ATTEMPT,
            severity=SecurityEventSeverity.HIGH,
            message=f"Brute force attack detected from {client_ip} targeting {username}",
            client_ip=client_ip,
            additional_data={
                "targeted_username": username,
                "attempt_count": attempt_count,
                "time_window_minutes": time_window_minutes
            },
            request=request
        )
    
    def log_injection_attempt(self,
                            attack_type: str,
                            payload: str,
                            client_ip: Optional[str] = None,
                            user_id: Optional[str] = None,
                            endpoint: Optional[str] = None,
                            request: Optional[Request] = None) -> None:
        """Log injection attack attempts (SQL, XSS, etc.)."""
        event_type_map = {
            "sql": SecurityEventType.SQL_INJECTION_ATTEMPT,
            "xss": SecurityEventType.XSS_ATTEMPT,
            "csrf": SecurityEventType.CSRF_ATTEMPT
        }
        
        event_type = event_type_map.get(attack_type.lower(), SecurityEventType.SUSPICIOUS_ACTIVITY)
        
        # Sanitize payload for logging (limit length and remove dangerous chars)
        sanitized_payload = payload[:200] + "..." if len(payload) > 200 else payload
        sanitized_payload = sanitized_payload.replace('\x00', '\\x00')
        
        self.log_security_event(
            event_type=event_type,
            severity=SecurityEventSeverity.HIGH,
            message=f"{attack_type.upper()} injection attempt detected",
            user_id=user_id,
            client_ip=client_ip,
            resource=endpoint,
            additional_data={
                "attack_type": attack_type,
                "payload_preview": sanitized_payload,
                "endpoint": endpoint
            },
            request=request
        )
    
    def log_password_change(self,
                          user_id: str,
                          initiated_by: str,
                          client_ip: Optional[str] = None,
                          request: Optional[Request] = None) -> None:
        """Log password change events."""
        self.log_security_event(
            event_type=SecurityEventType.PASSWORD_CHANGE,
            severity=SecurityEventSeverity.MEDIUM,
            message=f"Password changed for user {user_id}",
            user_id=user_id,
            client_ip=client_ip,
            additional_data={"initiated_by": initiated_by},
            request=request
        )
    
    def log_token_event(self,
                       event_type: SecurityEventType,
                       user_id: str,
                       token_type: str = "access",
                       client_ip: Optional[str] = None,
                       request: Optional[Request] = None) -> None:
        """Log token-related events."""
        event_messages = {
            SecurityEventType.TOKEN_CREATION: f"Token created for user {user_id}",
            SecurityEventType.TOKEN_REFRESH: f"Token refreshed for user {user_id}",
            SecurityEventType.TOKEN_REVOCATION: f"Token revoked for user {user_id}"
        }
        
        self.log_security_event(
            event_type=event_type,
            severity=SecurityEventSeverity.LOW,
            message=event_messages.get(event_type, f"Token event for user {user_id}"),
            user_id=user_id,
            client_ip=client_ip,
            additional_data={"token_type": token_type},
            request=request
        )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
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
    
    def _get_log_level(self, severity: SecurityEventSeverity) -> str:
        """Convert severity to log level."""
        severity_to_level = {
            SecurityEventSeverity.LOW: "INFO",
            SecurityEventSeverity.MEDIUM: "WARNING",
            SecurityEventSeverity.HIGH: "ERROR",
            SecurityEventSeverity.CRITICAL: "CRITICAL"
        }
        return severity_to_level.get(severity, "INFO")


# Global security audit logger instance
security_logger = SecurityAuditLogger()


# Convenience functions for common security events
def log_login_success(user_id: str, 
                     login_method: str = "password",
                     request: Optional[Request] = None) -> None:
    """Convenience function to log successful login."""
    security_logger.log_authentication_success(
        user_id=user_id,
        login_method=login_method,
        request=request
    )


def log_login_failure(username: str,
                     reason: str,
                     request: Optional[Request] = None) -> None:
    """Convenience function to log failed login."""
    security_logger.log_authentication_failure(
        username=username,
        reason=reason,
        request=request
    )


def log_access_denied(user_id: str,
                     resource: str,
                     required_permission: str,
                     request: Optional[Request] = None) -> None:
    """Convenience function to log access denied."""
    security_logger.log_authorization_failure(
        user_id=user_id,
        resource=resource,
        required_permission=required_permission,
        request=request
    )


def log_suspicious_behavior(description: str,
                           severity: SecurityEventSeverity = SecurityEventSeverity.HIGH,
                           request: Optional[Request] = None) -> None:
    """Convenience function to log suspicious behavior."""
    security_logger.log_suspicious_activity(
        description=description,
        severity=severity,
        request=request
    )


def log_rate_limit_violation(client_ip: str,
                           endpoint: str,
                           limit: int,
                           window_seconds: int,
                           request: Optional[Request] = None) -> None:
    """Convenience function to log rate limit violations."""
    security_logger.log_rate_limit_exceeded(
        client_ip=client_ip,
        endpoint=endpoint,
        limit=limit,
        window_seconds=window_seconds,
        request=request
    )