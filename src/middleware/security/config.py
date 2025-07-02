"""
Security Configuration Module

This module contains all configuration classes and settings for the security middleware.
"""

from typing import List, Set
from pydantic import BaseModel, Field


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
    """Main configuration for security middleware."""
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
    
    attack_threshold: int = Field(default=5, description="Number of attacks before IP blocking")
    temporary_block_hours: int = Field(default=1, description="Hours to block IP after attacks")
