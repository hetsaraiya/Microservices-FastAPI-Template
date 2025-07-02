"""
User Agent Filtering Module

This module handles user agent analysis and filtering for security purposes.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from ..config import AttackPatterns


class UserAgentFilter:
    """Filter and analyze user agents for security threats."""
    
    def __init__(self, patterns: AttackPatterns, block_empty_agents: bool = False):
        """
        Initialize user agent filter.
        
        Args:
            patterns: Attack patterns containing suspicious user agents
            block_empty_agents: Whether to block empty user agents
        """
        self.suspicious_patterns = patterns.suspicious_user_agents
        self.block_empty_agents = block_empty_agents
        
        # Track user agent statistics
        self._user_agent_stats: Dict[str, int] = defaultdict(int)
        self._suspicious_agents: Dict[str, List[datetime]] = defaultdict(list)
        
        # Common legitimate user agent patterns
        self.legitimate_patterns = [
            r"Mozilla/\d+\.\d+",  # Mozilla-based browsers
            r"Chrome/\d+\.\d+",   # Chrome
            r"Safari/\d+\.\d+",   # Safari
            r"Firefox/\d+\.\d+",  # Firefox
            r"Edge/\d+\.\d+",     # Edge
            r"Opera/\d+\.\d+",    # Opera
        ]
        
        # Compile patterns for performance
        self.legitimate_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.legitimate_patterns]
    
    def is_suspicious(self, user_agent: str, client_ip: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if user agent is suspicious.
        
        Args:
            user_agent: User agent string to analyze
            client_ip: Client IP address
            
        Returns:
            Tuple of (is_suspicious, suspicion_details)
        """
        if not user_agent:
            if self.block_empty_agents:
                return True, {
                    "reason": "empty_user_agent",
                    "severity": "medium",
                    "description": "Empty or missing user agent header"
                }
            return False, None
        
        # Track user agent usage
        self._user_agent_stats[user_agent] += 1
        
        # Check against known suspicious patterns
        suspicion_details = self._check_suspicious_patterns(user_agent)
        if suspicion_details:
            self._record_suspicious_activity(user_agent, client_ip)
            return True, suspicion_details
        
        # Check for automation indicators
        automation_details = self._check_automation_indicators(user_agent)
        if automation_details:
            self._record_suspicious_activity(user_agent, client_ip)
            return True, automation_details
        
        # Check for unusual patterns
        unusual_details = self._check_unusual_patterns(user_agent)
        if unusual_details:
            return True, unusual_details
        
        return False, None
    
    def _check_suspicious_patterns(self, user_agent: str) -> Optional[Dict]:
        """
        Check user agent against known suspicious patterns.
        
        Args:
            user_agent: User agent string
            
        Returns:
            Suspicion details if found, None otherwise
        """
        user_agent_lower = user_agent.lower()
        
        for pattern in self.suspicious_patterns:
            if pattern in user_agent_lower:
                return {
                    "reason": "known_suspicious_pattern",
                    "severity": "high",
                    "pattern": pattern,
                    "description": f"User agent contains suspicious pattern: {pattern}"
                }
        
        return None
    
    def _check_automation_indicators(self, user_agent: str) -> Optional[Dict]:
        """
        Check for automation/bot indicators in user agent.
        
        Args:
            user_agent: User agent string
            
        Returns:
            Suspicion details if automation detected, None otherwise
        """
        automation_indicators = [
            "bot", "crawler", "spider", "scraper", "automation",
            "headless", "selenium", "phantomjs", "puppeteer"
        ]
        
        user_agent_lower = user_agent.lower()
        
        for indicator in automation_indicators:
            if indicator in user_agent_lower:
                # Some bots are legitimate (search engines, etc.)
                if self._is_legitimate_bot(user_agent_lower):
                    return None
                
                return {
                    "reason": "automation_detected",
                    "severity": "medium",
                    "indicator": indicator,
                    "description": f"User agent indicates automation: {indicator}"
                }
        
        return None
    
    def _check_unusual_patterns(self, user_agent: str) -> Optional[Dict]:
        """
        Check for unusual patterns that might indicate malicious activity.
        
        Args:
            user_agent: User agent string
            
        Returns:
            Suspicion details if unusual patterns found, None otherwise
        """
        # Check for extremely short user agents (potential attack)
        if len(user_agent) < 10:
            return {
                "reason": "unusually_short",
                "severity": "low",
                "length": len(user_agent),
                "description": "User agent is unusually short"
            }
        
        # Check for extremely long user agents (potential attack)
        if len(user_agent) > 500:
            return {
                "reason": "unusually_long",
                "severity": "medium",
                "length": len(user_agent),
                "description": "User agent is unusually long"
            }
        
        # Check for suspicious characters
        if any(char in user_agent for char in ["<", ">", "script", "eval", "union", "select"]):
            return {
                "reason": "suspicious_characters",
                "severity": "high",
                "description": "User agent contains suspicious characters or keywords"
            }
        
        # Check if it looks like a legitimate browser
        if not self._looks_like_browser(user_agent):
            return {
                "reason": "non_browser_pattern",
                "severity": "low",
                "description": "User agent doesn't match common browser patterns"
            }
        
        return None
    
    def _is_legitimate_bot(self, user_agent: str) -> bool:
        """
        Check if user agent belongs to a legitimate bot.
        
        Args:
            user_agent: User agent string (lowercase)
            
        Returns:
            True if legitimate bot, False otherwise
        """
        legitimate_bots = [
            "googlebot", "bingbot", "slurp", "duckduckbot",
            "baiduspider", "yandexbot", "facebookexternalhit",
            "twitterbot", "linkedinbot", "whatsapp", "telegram"
        ]
        
        return any(bot in user_agent for bot in legitimate_bots)
    
    def _looks_like_browser(self, user_agent: str) -> bool:
        """
        Check if user agent looks like a legitimate browser.
        
        Args:
            user_agent: User agent string
            
        Returns:
            True if looks like browser, False otherwise
        """
        return any(regex.search(user_agent) for regex in self.legitimate_regex)
    
    def _record_suspicious_activity(self, user_agent: str, client_ip: str) -> None:
        """
        Record suspicious user agent activity.
        
        Args:
            user_agent: Suspicious user agent
            client_ip: Client IP address
        """
        key = f"{client_ip}:{user_agent[:100]}"  # Limit key size
        self._suspicious_agents[key].append(datetime.now())
        
        # Clean old entries
        cutoff_time = datetime.now() - timedelta(hours=24)
        self._suspicious_agents[key] = [
            timestamp for timestamp in self._suspicious_agents[key]
            if timestamp > cutoff_time
        ]
    
    def get_user_agent_stats(self) -> Dict:
        """
        Get user agent statistics.
        
        Returns:
            Dictionary with user agent statistics
        """
        # Get top user agents
        top_agents = sorted(
            self._user_agent_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]
        
        # Get suspicious activity count
        suspicious_count = sum(
            len(activities) for activities in self._suspicious_agents.values()
        )
        
        return {
            "total_unique_agents": len(self._user_agent_stats),
            "top_user_agents": [
                {"user_agent": agent[:100], "count": count}
                for agent, count in top_agents
            ],
            "suspicious_activity_count": suspicious_count,
            "suspicious_agent_count": len(self._suspicious_agents)
        }
    
    def get_suspicious_agents(self, limit: int = 10) -> List[Dict]:
        """
        Get list of most suspicious user agents.
        
        Args:
            limit: Maximum number of agents to return
            
        Returns:
            List of suspicious user agent information
        """
        suspicious_list = []
        
        for key, activities in self._suspicious_agents.items():
            if activities:  # Only include agents with recent activity
                parts = key.split(":", 1)
                if len(parts) == 2:
                    client_ip, user_agent = parts
                    suspicious_list.append({
                        "client_ip": client_ip,
                        "user_agent": user_agent,
                        "activity_count": len(activities),
                        "last_seen": max(activities).isoformat(),
                        "first_seen": min(activities).isoformat()
                    })
        
        # Sort by activity count
        suspicious_list.sort(key=lambda x: x["activity_count"], reverse=True)
        
        return suspicious_list[:limit]
    
    def is_rate_limited_agent(self, user_agent: str, client_ip: str, 
                            max_requests: int = 100) -> bool:
        """
        Check if user agent should be rate limited based on activity.
        
        Args:
            user_agent: User agent string
            client_ip: Client IP address
            max_requests: Maximum requests allowed in time window
            
        Returns:
            True if should be rate limited, False otherwise
        """
        key = f"{client_ip}:{user_agent[:100]}"
        
        if key in self._suspicious_agents:
            # Check activity in last hour
            cutoff_time = datetime.now() - timedelta(hours=1)
            recent_activity = [
                timestamp for timestamp in self._suspicious_agents[key]
                if timestamp > cutoff_time
            ]
            
            return len(recent_activity) > max_requests
        
        return False
    
    def cleanup_old_data(self, hours_back: int = 24) -> None:
        """
        Clean up old user agent data.
        
        Args:
            hours_back: Hours to keep data for
        """
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        # Clean suspicious agents data
        for key in list(self._suspicious_agents.keys()):
            self._suspicious_agents[key] = [
                timestamp for timestamp in self._suspicious_agents[key]
                if timestamp > cutoff_time
            ]
            
            # Remove empty entries
            if not self._suspicious_agents[key]:
                del self._suspicious_agents[key]
    
    def add_suspicious_pattern(self, pattern: str) -> None:
        """
        Add a new suspicious user agent pattern.
        
        Args:
            pattern: Pattern to add to suspicious list
        """
        if pattern not in self.suspicious_patterns:
            self.suspicious_patterns.append(pattern)
    
    def remove_suspicious_pattern(self, pattern: str) -> bool:
        """
        Remove a suspicious user agent pattern.
        
        Args:
            pattern: Pattern to remove from suspicious list
            
        Returns:
            True if pattern was removed, False if not found
        """
        if pattern in self.suspicious_patterns:
            self.suspicious_patterns.remove(pattern)
            return True
        return False
