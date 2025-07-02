"""
Rate Limiting Module

This module handles rate limiting functionality with sliding window approach.
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from ..config import RateLimitConfig


class RateLimiter:
    """Rate limiter with sliding window implementation."""
    
    def __init__(self, config: RateLimitConfig):
        """
        Initialize rate limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config
        self._rate_limit_storage: Dict[str, deque] = defaultdict(deque)
        self._blocked_ips: Dict[str, datetime] = {}
        self._burst_storage: Dict[str, deque] = defaultdict(deque)
    
    def is_rate_limited(self, client_ip: str, path: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if client IP is rate limited.
        
        Args:
            client_ip: Client IP address
            path: Request path
            
        Returns:
            Tuple of (is_limited, limit_info)
        """
        current_time = time.time()
        
        # Check if IP is currently blocked
        if self._is_temporarily_blocked(client_ip, current_time):
            return True, {
                "reason": "temporarily_blocked",
                "block_expires": self._blocked_ips[client_ip].isoformat(),
                "retry_after": int((self._blocked_ips[client_ip] - datetime.now()).total_seconds())
            }
        
        # Check burst limit
        if self._check_burst_limit(client_ip, current_time):
            self._block_ip_temporarily(client_ip)
            return True, {
                "reason": "burst_limit_exceeded",
                "limit": self.config.burst_limit,
                "window": "burst"
            }
        
        # Check minute-based rate limit
        if self._check_minute_limit(client_ip, current_time):
            self._block_ip_temporarily(client_ip)
            return True, {
                "reason": "rate_limit_exceeded",
                "limit": self.config.requests_per_minute,
                "window": f"{self.config.window_size_minutes} minute(s)",
                "retry_after": self.config.window_size_minutes * 60
            }
        
        # Add current request to tracking
        self._add_request(client_ip, current_time)
        
        return False, None
    
    def _check_minute_limit(self, client_ip: str, current_time: float) -> bool:
        """
        Check minute-based rate limit.
        
        Args:
            client_ip: Client IP address
            current_time: Current timestamp
            
        Returns:
            True if limit exceeded, False otherwise
        """
        window_start = current_time - (self.config.window_size_minutes * 60)
        
        # Clean old entries
        requests = self._rate_limit_storage[client_ip]
        while requests and requests[0] < window_start:
            requests.popleft()
        
        # Check limit
        return len(requests) >= self.config.requests_per_minute
    
    def _check_burst_limit(self, client_ip: str, current_time: float) -> bool:
        """
        Check burst limit (short-term high frequency).
        
        Args:
            client_ip: Client IP address
            current_time: Current timestamp
            
        Returns:
            True if burst limit exceeded, False otherwise
        """
        burst_window = 10  # 10 seconds burst window
        window_start = current_time - burst_window
        
        # Clean old entries
        burst_requests = self._burst_storage[client_ip]
        while burst_requests and burst_requests[0] < window_start:
            burst_requests.popleft()
        
        # Add current request to burst tracking
        burst_requests.append(current_time)
        
        # Check burst limit
        return len(burst_requests) > self.config.burst_limit
    
    def _add_request(self, client_ip: str, current_time: float) -> None:
        """
        Add request to rate limiting storage.
        
        Args:
            client_ip: Client IP address
            current_time: Current timestamp
        """
        self._rate_limit_storage[client_ip].append(current_time)
    
    def _block_ip_temporarily(self, client_ip: str) -> None:
        """
        Block IP temporarily.
        
        Args:
            client_ip: Client IP address to block
        """
        block_until = datetime.now() + timedelta(minutes=self.config.block_duration_minutes)
        self._blocked_ips[client_ip] = block_until
    
    def _is_temporarily_blocked(self, client_ip: str, current_time: float) -> bool:
        """
        Check if IP is temporarily blocked.
        
        Args:
            client_ip: Client IP address
            current_time: Current timestamp
            
        Returns:
            True if blocked, False otherwise
        """
        if client_ip not in self._blocked_ips:
            return False
        
        if datetime.now() > self._blocked_ips[client_ip]:
            # Block expired, remove it
            del self._blocked_ips[client_ip]
            return False
        
        return True
    
    def get_rate_limit_info(self, client_ip: str) -> Dict:
        """
        Get current rate limit information for client.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Dictionary with rate limit information
        """
        current_time = time.time()
        window_start = current_time - (self.config.window_size_minutes * 60)
        
        # Count requests in current window
        requests = self._rate_limit_storage[client_ip]
        current_requests = sum(1 for req_time in requests if req_time >= window_start)
        
        return {
            "limit": self.config.requests_per_minute,
            "remaining": max(0, self.config.requests_per_minute - current_requests),
            "reset_time": int(window_start + (self.config.window_size_minutes * 60)),
            "window_size_minutes": self.config.window_size_minutes,
            "is_blocked": self._is_temporarily_blocked(client_ip, current_time)
        }
    
    def unblock_ip(self, client_ip: str) -> bool:
        """
        Manually unblock an IP address.
        
        Args:
            client_ip: Client IP address to unblock
            
        Returns:
            True if IP was blocked and is now unblocked, False otherwise
        """
        if client_ip in self._blocked_ips:
            del self._blocked_ips[client_ip]
            return True
        return False
    
    def get_blocked_ips(self) -> Dict[str, str]:
        """
        Get list of currently blocked IPs.
        
        Returns:
            Dictionary mapping IP addresses to block expiration times
        """
        current_time = datetime.now()
        active_blocks = {}
        
        # Clean expired blocks and collect active ones
        expired_ips = []
        for ip, block_time in self._blocked_ips.items():
            if current_time > block_time:
                expired_ips.append(ip)
            else:
                active_blocks[ip] = block_time.isoformat()
        
        # Remove expired blocks
        for ip in expired_ips:
            del self._blocked_ips[ip]
        
        return active_blocks
    
    def cleanup_old_entries(self, max_age_hours: int = 24) -> None:
        """
        Clean up old entries to prevent memory leaks.
        
        Args:
            max_age_hours: Maximum age of entries to keep in hours
        """
        current_time = time.time()
        cutoff_time = current_time - (max_age_hours * 3600)
        
        # Clean rate limit storage
        for ip in list(self._rate_limit_storage.keys()):
            requests = self._rate_limit_storage[ip]
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            
            # Remove empty deques
            if not requests:
                del self._rate_limit_storage[ip]
        
        # Clean burst storage
        for ip in list(self._burst_storage.keys()):
            requests = self._burst_storage[ip]
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            
            # Remove empty deques
            if not requests:
                del self._burst_storage[ip]
    
    def get_statistics(self) -> Dict:
        """
        Get rate limiter statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "tracked_ips": len(self._rate_limit_storage),
            "blocked_ips": len(self.get_blocked_ips()),
            "config": {
                "requests_per_minute": self.config.requests_per_minute,
                "burst_limit": self.config.burst_limit,
                "block_duration_minutes": self.config.block_duration_minutes,
                "window_size_minutes": self.config.window_size_minutes
            }
        }
