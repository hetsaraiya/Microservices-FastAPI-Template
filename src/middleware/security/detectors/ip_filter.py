"""
IP Filtering Module

This module handles IP address filtering including blocking and whitelisting.
"""

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from ..enums import AttackType
from ..utils import SecurityUtils


class IPFilter:
    """IP filtering and blocking manager."""
    
    def __init__(self, 
                 blocked_ips: Set[str], 
                 whitelist_ips: Set[str],
                 attack_threshold: int = 5,
                 temporary_block_hours: int = 1):
        """
        Initialize IP filter.
        
        Args:
            blocked_ips: Set of permanently blocked IP addresses
            whitelist_ips: Set of whitelisted IP addresses
            attack_threshold: Number of attacks before temporary blocking
            temporary_block_hours: Hours to temporarily block after attacks
        """
        self.blocked_ips = blocked_ips
        self.whitelist_ips = whitelist_ips
        self.attack_threshold = attack_threshold
        self.temporary_block_hours = temporary_block_hours
        
        # Track attack attempts per IP
        self._attack_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._temporary_blocks: Dict[str, datetime] = {}
        
        # Track suspicious activity
        self._suspicious_activity: Dict[str, List[datetime]] = defaultdict(list)
    
    def is_blocked(self, client_ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP address is blocked.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Tuple of (is_blocked, reason)
        """
        # Check whitelist first
        if self.is_whitelisted(client_ip):
            return False, None
        
        # Check permanent blocks
        if client_ip in self.blocked_ips:
            return True, "permanently_blocked"
        
        # Check temporary blocks
        if self._is_temporarily_blocked(client_ip):
            return True, "temporarily_blocked"
        
        # Check IP ranges (if configured)
        if self._is_in_blocked_range(client_ip):
            return True, "ip_range_blocked"
        
        return False, None
    
    def is_whitelisted(self, client_ip: str) -> bool:
        """
        Check if IP address is whitelisted.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if whitelisted, False otherwise
        """
        if client_ip in self.whitelist_ips:
            return True
        
        # Check if it's a private IP (commonly whitelisted)
        if SecurityUtils.is_private_ip(client_ip):
            return True
        
        return False
    
    def add_attack(self, client_ip: str, attack_type: str) -> bool:
        """
        Record an attack attempt and potentially block the IP.
        
        Args:
            client_ip: Client IP address
            attack_type: Type of attack attempted
            
        Returns:
            True if IP was blocked as a result, False otherwise
        """
        if self.is_whitelisted(client_ip):
            return False
        
        # Increment attack counter
        self._attack_counters[client_ip][attack_type] += 1
        
        # Track suspicious activity timeline
        self._suspicious_activity[client_ip].append(datetime.now())
        
        # Clean old suspicious activity (older than 1 hour)
        self._clean_old_activity(client_ip)
        
        # Check if we should block this IP
        total_attacks = sum(self._attack_counters[client_ip].values())
        
        if total_attacks >= self.attack_threshold:
            self._block_temporarily(client_ip)
            return True
        
        return False
    
    def _block_temporarily(self, client_ip: str) -> None:
        """
        Block IP temporarily.
        
        Args:
            client_ip: Client IP address to block
        """
        block_until = datetime.now() + timedelta(hours=self.temporary_block_hours)
        self._temporary_blocks[client_ip] = block_until
    
    def _is_temporarily_blocked(self, client_ip: str) -> bool:
        """
        Check if IP is temporarily blocked.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if temporarily blocked, False otherwise
        """
        if client_ip not in self._temporary_blocks:
            return False
        
        if datetime.now() > self._temporary_blocks[client_ip]:
            # Block expired, remove it
            del self._temporary_blocks[client_ip]
            return False
        
        return True
    
    def _is_in_blocked_range(self, client_ip: str) -> bool:
        """
        Check if IP is in a blocked range (CIDR notation).
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if in blocked range, False otherwise
        """
        # This could be extended to support CIDR ranges
        # For now, just exact IP matching
        return False
    
    def add_permanent_block(self, client_ip: str) -> bool:
        """
        Add IP to permanent block list.
        
        Args:
            client_ip: Client IP address to block
            
        Returns:
            True if IP was added, False if already blocked
        """
        if client_ip in self.blocked_ips:
            return False
        
        self.blocked_ips.add(client_ip)
        
        # Remove from temporary blocks if present
        if client_ip in self._temporary_blocks:
            del self._temporary_blocks[client_ip]
        
        return True
    
    def remove_permanent_block(self, client_ip: str) -> bool:
        """
        Remove IP from permanent block list.
        
        Args:
            client_ip: Client IP address to unblock
            
        Returns:
            True if IP was removed, False if not in list
        """
        if client_ip in self.blocked_ips:
            self.blocked_ips.remove(client_ip)
            return True
        return False
    
    def add_whitelist(self, client_ip: str) -> bool:
        """
        Add IP to whitelist.
        
        Args:
            client_ip: Client IP address to whitelist
            
        Returns:
            True if IP was added, False if already whitelisted
        """
        if client_ip in self.whitelist_ips:
            return False
        
        self.whitelist_ips.add(client_ip)
        
        # Remove from blocks if present
        self.blocked_ips.discard(client_ip)
        if client_ip in self._temporary_blocks:
            del self._temporary_blocks[client_ip]
        
        return True
    
    def remove_whitelist(self, client_ip: str) -> bool:
        """
        Remove IP from whitelist.
        
        Args:
            client_ip: Client IP address to remove from whitelist
            
        Returns:
            True if IP was removed, False if not in whitelist
        """
        if client_ip in self.whitelist_ips:
            self.whitelist_ips.remove(client_ip)
            return True
        return False
    
    def unblock_temporary(self, client_ip: str) -> bool:
        """
        Remove IP from temporary block list.
        
        Args:
            client_ip: Client IP address to unblock
            
        Returns:
            True if IP was unblocked, False if not in list
        """
        if client_ip in self._temporary_blocks:
            del self._temporary_blocks[client_ip]
            return True
        return False
    
    def get_attack_stats(self, client_ip: str) -> Dict:
        """
        Get attack statistics for an IP.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Dictionary with attack statistics
        """
        return {
            "total_attacks": sum(self._attack_counters[client_ip].values()),
            "attack_breakdown": dict(self._attack_counters[client_ip]),
            "recent_activity_count": len(self._suspicious_activity[client_ip]),
            "is_blocked": self.is_blocked(client_ip)[0],
            "is_whitelisted": self.is_whitelisted(client_ip)
        }
    
    def _clean_old_activity(self, client_ip: str, hours_back: int = 1) -> None:
        """
        Clean old suspicious activity records.
        
        Args:
            client_ip: Client IP address
            hours_back: Hours to look back
        """
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        self._suspicious_activity[client_ip] = [
            activity for activity in self._suspicious_activity[client_ip]
            if activity > cutoff_time
        ]
    
    def get_blocked_ips_info(self) -> Dict:
        """
        Get information about blocked IPs.
        
        Returns:
            Dictionary with blocking information
        """
        current_time = datetime.now()
        
        # Clean expired temporary blocks
        expired_blocks = [
            ip for ip, block_time in self._temporary_blocks.items()
            if current_time > block_time
        ]
        
        for ip in expired_blocks:
            del self._temporary_blocks[ip]
        
        return {
            "permanent_blocks": list(self.blocked_ips),
            "temporary_blocks": {
                ip: block_time.isoformat()
                for ip, block_time in self._temporary_blocks.items()
            },
            "whitelist": list(self.whitelist_ips),
            "total_permanent": len(self.blocked_ips),
            "total_temporary": len(self._temporary_blocks),
            "total_whitelisted": len(self.whitelist_ips)
        }
    
    def cleanup_old_data(self, days_back: int = 7) -> None:
        """
        Clean up old attack counter data.
        
        Args:
            days_back: Days to keep data for
        """
        # Clean old suspicious activity
        cutoff_time = datetime.now() - timedelta(days=days_back)
        
        for ip in list(self._suspicious_activity.keys()):
            self._suspicious_activity[ip] = [
                activity for activity in self._suspicious_activity[ip]
                if activity > cutoff_time
            ]
            
            # Remove empty entries
            if not self._suspicious_activity[ip]:
                del self._suspicious_activity[ip]
    
    def get_top_attackers(self, limit: int = 10) -> List[Dict]:
        """
        Get top attacking IPs by attack count.
        
        Args:
            limit: Maximum number of IPs to return
            
        Returns:
            List of dictionaries with IP and attack information
        """
        attackers = []
        
        for ip, attacks in self._attack_counters.items():
            total_attacks = sum(attacks.values())
            if total_attacks > 0:
                attackers.append({
                    "ip": ip,
                    "total_attacks": total_attacks,
                    "attack_types": dict(attacks),
                    "is_blocked": self.is_blocked(ip)[0],
                    "recent_activity": len(self._suspicious_activity.get(ip, []))
                })
        
        # Sort by total attacks, descending
        attackers.sort(key=lambda x: x["total_attacks"], reverse=True)
        
        return attackers[:limit]
