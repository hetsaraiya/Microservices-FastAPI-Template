"""
Log Formatters and Data Processing Utilities

This module provides custom formatters for structured logging, sensitive data masking,
and log sanitization functions for the FastAPI application.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from loguru import logger


class SensitiveDataMasker:
    """Utility class for masking sensitive data in logs."""
    
    DEFAULT_SENSITIVE_FIELDS = [
        "password", "passwd", "secret", "token", "key", "authorization",
        "auth", "credential", "credentials", "api_key", "access_token",
        "refresh_token", "jwt", "bearer", "session", "cookie", "csrf",
        "ssn", "social_security", "credit_card", "card_number", "cvv",
        "pin", "otp", "private_key", "signature", "hash"
    ]
    
    SENSITIVE_PATTERNS = [
        # Email patterns
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', lambda m: f"{m.group()[:3]}***@{m.group().split('@')[1]}"),
        # Phone patterns
        (r'\b\d{3}-\d{3}-\d{4}\b', lambda m: "***-***-****"),
        (r'\b\(\d{3}\)\s*\d{3}-\d{4}\b', lambda m: "(***) ***-****"),
        # Credit card patterns
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', lambda m: "****-****-****-****"),
        # SSN patterns
        (r'\b\d{3}-\d{2}-\d{4}\b', lambda m: "***-**-****"),
        # IP Address patterns (optional, might be needed for debugging)
        # (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', lambda m: "***.***.***.**"),
        # JWT Token patterns
        (r'\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*\b', lambda m: "eyJ***.***.***.***"),
        # Bearer token patterns
        (r'\bBearer\s+[A-Za-z0-9-_.~+/]+=*', lambda m: "Bearer ***"),
        # API Key patterns
        (r'\b[A-Za-z0-9]{32,}\b', lambda m: f"{m.group()[:8]}***"),
    ]
    
    def __init__(self, sensitive_fields: Optional[List[str]] = None, mask_char: str = "*"):
        """
        Initialize the sensitive data masker.
        
        Args:
            sensitive_fields: List of field names to mask
            mask_char: Character to use for masking
        """
        self.sensitive_fields = set(
            (sensitive_fields or []) + self.DEFAULT_SENSITIVE_FIELDS
        )
        self.mask_char = mask_char
    
    def mask_dict(self, data: Dict[str, Any], max_depth: int = 10) -> Dict[str, Any]:
        """
        Recursively mask sensitive data in a dictionary.
        
        Args:
            data: Dictionary to mask
            max_depth: Maximum recursion depth to prevent infinite loops
            
        Returns:
            Dictionary with sensitive data masked
        """
        if max_depth <= 0:
            return data
        
        if not isinstance(data, dict):
            return data
        
        masked_data = {}
        for key, value in data.items():
            if self._is_sensitive_field(key):
                masked_data[key] = self._mask_value(value)
            elif isinstance(value, dict):
                masked_data[key] = self.mask_dict(value, max_depth - 1)
            elif isinstance(value, list):
                masked_data[key] = [
                    self.mask_dict(item, max_depth - 1) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                masked_data[key] = self._mask_string_patterns(str(value)) if isinstance(value, str) else value
        
        return masked_data
    
    def mask_string(self, text: str) -> str:
        """
        Mask sensitive patterns in a string.
        
        Args:
            text: String to mask
            
        Returns:
            String with sensitive patterns masked
        """
        return self._mask_string_patterns(text)
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field name is considered sensitive."""
        return field_name.lower() in self.sensitive_fields
    
    def _mask_value(self, value: Any) -> str:
        """Mask a sensitive value based on its type and length."""
        if value is None:
            return None
        
        str_value = str(value)
        if len(str_value) <= 3:
            return self.mask_char * len(str_value)
        elif len(str_value) <= 8:
            return str_value[:1] + self.mask_char * (len(str_value) - 2) + str_value[-1:]
        else:
            return str_value[:2] + self.mask_char * (len(str_value) - 4) + str_value[-2:]
    
    def _mask_string_patterns(self, text: str) -> str:
        """Apply pattern-based masking to a string."""
        masked_text = text
        for pattern, replacer in self.SENSITIVE_PATTERNS:
            masked_text = re.sub(pattern, replacer, masked_text)
        return masked_text


class JSONLogFormatter:
    """Custom JSON formatter for structured logging."""
    
    def __init__(self, 
                 include_extra: bool = True,
                 mask_sensitive: bool = True,
                 sensitive_fields: Optional[List[str]] = None):
        """
        Initialize the JSON formatter.
        
        Args:
            include_extra: Whether to include extra fields in JSON output
            mask_sensitive: Whether to mask sensitive data
            sensitive_fields: List of sensitive field names
        """
        self.include_extra = include_extra
        self.masker = SensitiveDataMasker(sensitive_fields) if mask_sensitive else None
    
    def format_record(self, record: Dict[str, Any]) -> str:
        """
        Format a log record as JSON.
        
        Args:
            record: Log record dictionary
            
        Returns:
            JSON formatted string
        """
        # Base record structure
        formatted_record = {
            "timestamp": record.get("time", datetime.utcnow()).isoformat(),
            "level": record.get("level", {}).get("name", "INFO"),
            "logger": record.get("name", "root"),
            "module": record.get("module", ""),
            "function": record.get("function", ""),
            "line": record.get("line", 0),
            "message": record.get("message", ""),
        }
        
        # Add process and thread info
        if "process" in record:
            formatted_record["process_id"] = record["process"].get("id")
        if "thread" in record:
            formatted_record["thread_id"] = record["thread"].get("id")
        
        # Add exception info if present
        if record.get("exception"):
            formatted_record["exception"] = {
                "type": record["exception"].get("type", ""),
                "value": record["exception"].get("value", ""),
                "traceback": record["exception"].get("traceback", "")
            }
        
        # Add extra fields if enabled
        if self.include_extra and "extra" in record:
            extra_data = record["extra"]
            if self.masker:
                extra_data = self.masker.mask_dict(extra_data)
            formatted_record["extra"] = extra_data
        
        # Mask sensitive data in the entire record
        if self.masker:
            formatted_record = self.masker.mask_dict(formatted_record)
        
        return json.dumps(formatted_record, default=str, ensure_ascii=False)


class LogSanitizer:
    """Utility class for sanitizing log messages and data."""
    
    DANGEROUS_PATTERNS = [
        # SQL injection patterns
        r'(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table|truncate\s+table)',
        # XSS patterns
        r'(?i)(<script|javascript:|onload=|onerror=)',
        # Path traversal patterns
        r'(\.\.\/|\.\.\\)',
        # Command injection patterns
        r'(?i)(;|\||&|\$\(|\`)',
    ]
    
    @classmethod
    def sanitize_message(cls, message: str, max_length: int = 10000) -> str:
        """
        Sanitize a log message by removing dangerous patterns and limiting length.
        
        Args:
            message: Message to sanitize
            max_length: Maximum message length
            
        Returns:
            Sanitized message
        """
        if not isinstance(message, str):
            message = str(message)
        
        # Limit message length
        if len(message) > max_length:
            message = message[:max_length] + "... [TRUNCATED]"
        
        # Remove dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            message = re.sub(pattern, "[REDACTED]", message)
        
        # Remove control characters except newlines and tabs
        message = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', message)
        
        return message
    
    @classmethod
    def sanitize_user_input(cls, data: Any) -> Any:
        """
        Sanitize user input data for logging.
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data
        """
        if isinstance(data, str):
            return cls.sanitize_message(data)
        elif isinstance(data, dict):
            return {k: cls.sanitize_user_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls.sanitize_user_input(item) for item in data]
        else:
            return data


class StructuredLogFormatter:
    """Enhanced formatter for structured logging with context."""
    
    def __init__(self, environment: str = "development"):
        """
        Initialize the structured formatter.
        
        Args:
            environment: Current environment
        """
        self.environment = environment
        self.masker = SensitiveDataMasker()
        self.sanitizer = LogSanitizer()
    
    def add_context(self, record: Dict[str, Any], **context) -> Dict[str, Any]:
        """
        Add contextual information to a log record.
        
        Args:
            record: Log record
            **context: Additional context to add
            
        Returns:
            Enhanced log record
        """
        if "extra" not in record:
            record["extra"] = {}
        
        # Add environment info
        record["extra"]["environment"] = self.environment
        
        # Add custom context
        for key, value in context.items():
            record["extra"][key] = value
        
        # Sanitize and mask the record
        record["message"] = self.sanitizer.sanitize_message(record.get("message", ""))
        record["extra"] = self.masker.mask_dict(record["extra"])
        
        return record


# Pre-configured formatters for different use cases
def get_console_formatter(environment: str = "development") -> str:
    """Get console formatter based on environment."""
    if environment.lower() in ["production", "prod"]:
        return (
            "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}"
        )
    else:
        return (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        )


def get_file_formatter(environment: str = "development") -> str:
    """Get file formatter based on environment."""
    if environment.lower() in ["production", "prod"]:
        return (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | "
            "PID:{process.id} | TID:{thread.id} | {message} | {exception}"
        )
    else:
        return (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | "
            "{message}"
        )


def get_json_formatter() -> JSONLogFormatter:
    """Get JSON formatter instance."""
    return JSONLogFormatter(
        include_extra=True,
        mask_sensitive=True
    )