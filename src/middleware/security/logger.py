"""
Security Event Logger Module

This module handles logging of security events with appropriate formatting and severity levels.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from loguru import logger

from .enums import SecurityEventType, SecurityEventSeverity


class SecurityEventLogger:
    """Logger for security events with structured logging capabilities."""
    
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
        """
        Log a security event with structured data.
        
        Args:
            event_type: Type of security event
            severity: Severity level of the event
            message: Human-readable message
            client_ip: Client IP address
            user_agent: User agent string
            path: Request path
            payload: Request payload (will be sanitized)
            additional_data: Additional context data
        """
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
            sanitized_payload = self._sanitize_payload(payload)
            event_data["payload"] = sanitized_payload
        
        if additional_data:
            event_data.update(additional_data)
        
        # Remove None values
        event_data = {k: v for k, v in event_data.items() if v is not None}
        
        # Log with appropriate level
        log_level = self._get_log_level(severity)
        self.logger.bind(**event_data).log(log_level, f"SECURITY EVENT: {message}")
    
    def log_attack_attempt(self,
                          attack_type: str,
                          client_ip: str,
                          user_agent: str,
                          path: str,
                          detected_pattern: str,
                          payload: Optional[str] = None) -> None:
        """Log an attack attempt with specific attack details."""
        self.log_security_event(
            event_type=SecurityEventType.MALICIOUS_PAYLOAD,
            severity=SecurityEventSeverity.HIGH,
            message=f"{attack_type.upper()} attack attempt detected from {client_ip}",
            client_ip=client_ip,
            user_agent=user_agent,
            path=path,
            payload=payload,
            additional_data={
                "attack_type": attack_type,
                "detected_pattern": detected_pattern
            }
        )
    
    def log_ip_block(self,
                    client_ip: str,
                    reason: str,
                    block_duration: Optional[str] = None,
                    attack_count: Optional[int] = None) -> None:
        """Log IP blocking event."""
        additional_data = {"block_reason": reason}
        if block_duration:
            additional_data["block_duration"] = block_duration
        if attack_count:
            additional_data["attack_count"] = attack_count
            
        self.log_security_event(
            event_type=SecurityEventType.IP_BLOCKED,
            severity=SecurityEventSeverity.CRITICAL,
            message=f"IP {client_ip} blocked - {reason}",
            client_ip=client_ip,
            additional_data=additional_data
        )
    
    def log_rate_limit_exceeded(self,
                              client_ip: str,
                              user_agent: str,
                              path: str,
                              requests_count: int,
                              time_window: str) -> None:
        """Log rate limit exceeded event."""
        self.log_security_event(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity=SecurityEventSeverity.MEDIUM,
            message=f"Rate limit exceeded for IP {client_ip}",
            client_ip=client_ip,
            user_agent=user_agent,
            path=path,
            additional_data={
                "requests_count": requests_count,
                "time_window": time_window
            }
        )
    
    def _sanitize_payload(self, payload: str, max_length: int = 500) -> str:
        """
        Sanitize payload for safe logging.
        
        Args:
            payload: Original payload
            max_length: Maximum length to keep
            
        Returns:
            Sanitized payload string
        """
        if not payload:
            return ""
        
        # Remove potentially sensitive information
        sanitized = payload.replace('\n', '\\n').replace('\r', '\\r')
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "... [truncated]"
        
        return sanitized
    
    def _get_log_level(self, severity: SecurityEventSeverity) -> str:
        """
        Convert severity to log level.
        
        Args:
            severity: Security event severity
            
        Returns:
            Log level string
        """
        severity_map = {
            SecurityEventSeverity.LOW: "INFO",
            SecurityEventSeverity.MEDIUM: "WARNING", 
            SecurityEventSeverity.HIGH: "ERROR",
            SecurityEventSeverity.CRITICAL: "CRITICAL"
        }
        return severity_map.get(severity, "WARNING")
