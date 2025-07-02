"""
Security Management Module

This module provides management utilities for the security middleware.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from loguru import logger

from .config import SecurityConfig
from .detectors import AttackDetector, IPFilter, RateLimiter, UserAgentFilter
from .logger import SecurityEventLogger


class SecurityManager:
    """Manager class for security middleware operations and maintenance."""
    
    def __init__(self, middleware_instance):
        """
        Initialize security manager.
        
        Args:
            middleware_instance: SecurityMiddleware instance
        """
        self.middleware = middleware_instance
        self.config = middleware_instance.config
        self.ip_filter = middleware_instance.ip_filter
        self.rate_limiter = middleware_instance.rate_limiter
        self.user_agent_filter = middleware_instance.user_agent_filter
        self.event_logger = middleware_instance.event_logger
    
    async def run_maintenance(self) -> Dict:
        """
        Run maintenance tasks for all security components.
        
        Returns:
            Dictionary with maintenance results
        """
        logger.info("Starting security middleware maintenance")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "tasks": {}
        }
        
        # Clean up old rate limiting data
        try:
            self.rate_limiter.cleanup_old_entries()
            results["tasks"]["rate_limiter_cleanup"] = "completed"
        except Exception as e:
            results["tasks"]["rate_limiter_cleanup"] = f"failed: {str(e)}"
            logger.error(f"Rate limiter cleanup failed: {e}")
        
        # Clean up old IP filter data
        try:
            self.ip_filter.cleanup_old_data()
            results["tasks"]["ip_filter_cleanup"] = "completed"
        except Exception as e:
            results["tasks"]["ip_filter_cleanup"] = f"failed: {str(e)}"
            logger.error(f"IP filter cleanup failed: {e}")
        
        # Clean up old user agent data
        try:
            self.user_agent_filter.cleanup_old_data()
            results["tasks"]["user_agent_cleanup"] = "completed"
        except Exception as e:
            results["tasks"]["user_agent_cleanup"] = f"failed: {str(e)}"
            logger.error(f"User agent cleanup failed: {e}")
        
        logger.info("Security middleware maintenance completed", extra=results)
        return results
    
    def get_comprehensive_stats(self) -> Dict:
        """
        Get comprehensive statistics from all security components.
        
        Returns:
            Dictionary with detailed statistics
        """
        stats = {
            "timestamp": datetime.now().isoformat(),
            "security_middleware": {
                "version": "1.0.0",
                "config": {
                    "attack_detection_enabled": self.config.enable_attack_detection,
                    "rate_limiting_enabled": self.config.enable_rate_limiting,
                    "ip_blocking_enabled": self.config.enable_ip_blocking,
                    "user_agent_filtering_enabled": self.config.enable_user_agent_filtering
                }
            }
        }
        
        # IP Filter statistics
        try:
            stats["ip_filter"] = self.ip_filter.get_blocked_ips_info()
            stats["top_attackers"] = self.ip_filter.get_top_attackers(10)
        except Exception as e:
            stats["ip_filter"] = {"error": str(e)}
            logger.error(f"Failed to get IP filter stats: {e}")
        
        # Rate limiter statistics
        try:
            stats["rate_limiter"] = self.rate_limiter.get_statistics()
            stats["rate_limiter"]["blocked_ips"] = self.rate_limiter.get_blocked_ips()
        except Exception as e:
            stats["rate_limiter"] = {"error": str(e)}
            logger.error(f"Failed to get rate limiter stats: {e}")
        
        # User agent filter statistics
        try:
            stats["user_agent_filter"] = self.user_agent_filter.get_user_agent_stats()
            stats["suspicious_user_agents"] = self.user_agent_filter.get_suspicious_agents(10)
        except Exception as e:
            stats["user_agent_filter"] = {"error": str(e)}
            logger.error(f"Failed to get user agent filter stats: {e}")
        
        return stats
    
    def export_security_report(self) -> Dict:
        """
        Export a comprehensive security report.
        
        Returns:
            Dictionary with security report data
        """
        report = {
            "report_generated": datetime.now().isoformat(),
            "summary": {},
            "details": self.get_comprehensive_stats()
        }
        
        # Generate summary
        try:
            blocked_info = self.ip_filter.get_blocked_ips_info()
            rate_stats = self.rate_limiter.get_statistics()
            ua_stats = self.user_agent_filter.get_user_agent_stats()
            
            report["summary"] = {
                "total_blocked_ips": blocked_info.get("total_permanent", 0) + blocked_info.get("total_temporary", 0),
                "permanent_blocks": blocked_info.get("total_permanent", 0),
                "temporary_blocks": blocked_info.get("total_temporary", 0),
                "whitelisted_ips": blocked_info.get("total_whitelisted", 0),
                "tracked_ips_rate_limiting": rate_stats.get("tracked_ips", 0),
                "unique_user_agents": ua_stats.get("total_unique_agents", 0),
                "suspicious_user_agents": ua_stats.get("suspicious_agent_count", 0)
            }
        except Exception as e:
            report["summary"] = {"error": f"Failed to generate summary: {str(e)}"}
            logger.error(f"Failed to generate security report summary: {e}")
        
        return report
    
    def bulk_ip_operations(self, operations: List[Dict]) -> Dict:
        """
        Perform bulk IP operations.
        
        Args:
            operations: List of operations, each with 'action', 'ip', and optional 'reason'
                       Actions: 'block', 'unblock', 'whitelist', 'remove_whitelist'
        
        Returns:
            Dictionary with operation results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "operations": [],
            "summary": {
                "total": len(operations),
                "successful": 0,
                "failed": 0
            }
        }
        
        for operation in operations:
            try:
                action = operation.get("action")
                ip = operation.get("ip")
                reason = operation.get("reason", "bulk_operation")
                
                if not action or not ip:
                    raise ValueError("Missing action or ip in operation")
                
                op_result = {"action": action, "ip": ip, "status": "failed"}
                
                if action == "block":
                    success = self.ip_filter.add_permanent_block(ip)
                    op_result["status"] = "success" if success else "already_blocked"
                    if success:
                        logger.info(f"Bulk operation: blocked IP {ip}, reason: {reason}")
                
                elif action == "unblock":
                    perm_success = self.ip_filter.remove_permanent_block(ip)
                    temp_success = self.ip_filter.unblock_temporary(ip)
                    success = perm_success or temp_success
                    op_result["status"] = "success" if success else "not_blocked"
                    if success:
                        logger.info(f"Bulk operation: unblocked IP {ip}")
                
                elif action == "whitelist":
                    success = self.ip_filter.add_whitelist(ip)
                    op_result["status"] = "success" if success else "already_whitelisted"
                    if success:
                        logger.info(f"Bulk operation: whitelisted IP {ip}")
                
                elif action == "remove_whitelist":
                    success = self.ip_filter.remove_whitelist(ip)
                    op_result["status"] = "success" if success else "not_whitelisted"
                    if success:
                        logger.info(f"Bulk operation: removed IP {ip} from whitelist")
                
                else:
                    op_result["error"] = f"Unknown action: {action}"
                
                if op_result["status"] == "success":
                    results["summary"]["successful"] += 1
                else:
                    results["summary"]["failed"] += 1
                
                results["operations"].append(op_result)
                
            except Exception as e:
                results["operations"].append({
                    "action": operation.get("action", "unknown"),
                    "ip": operation.get("ip", "unknown"),
                    "status": "error",
                    "error": str(e)
                })
                results["summary"]["failed"] += 1
                logger.error(f"Bulk operation failed: {e}")
        
        return results
    
    def update_attack_patterns(self, 
                             sql_patterns: Optional[List[str]] = None,
                             xss_patterns: Optional[List[str]] = None,
                             path_traversal_patterns: Optional[List[str]] = None,
                             suspicious_user_agents: Optional[List[str]] = None) -> Dict:
        """
        Update attack patterns in the configuration.
        
        Args:
            sql_patterns: New SQL injection patterns
            xss_patterns: New XSS patterns
            path_traversal_patterns: New path traversal patterns
            suspicious_user_agents: New suspicious user agent patterns
            
        Returns:
            Dictionary with update results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "updates": {}
        }
        
        try:
            if sql_patterns is not None:
                old_count = len(self.config.attack_patterns.sql_injection_patterns)
                self.config.attack_patterns.sql_injection_patterns = sql_patterns
                new_count = len(sql_patterns)
                results["updates"]["sql_injection_patterns"] = {
                    "old_count": old_count,
                    "new_count": new_count,
                    "status": "updated"
                }
            
            if xss_patterns is not None:
                old_count = len(self.config.attack_patterns.xss_patterns)
                self.config.attack_patterns.xss_patterns = xss_patterns
                new_count = len(xss_patterns)
                results["updates"]["xss_patterns"] = {
                    "old_count": old_count,
                    "new_count": new_count,
                    "status": "updated"
                }
            
            if path_traversal_patterns is not None:
                old_count = len(self.config.attack_patterns.path_traversal_patterns)
                self.config.attack_patterns.path_traversal_patterns = path_traversal_patterns
                new_count = len(path_traversal_patterns)
                results["updates"]["path_traversal_patterns"] = {
                    "old_count": old_count,
                    "new_count": new_count,
                    "status": "updated"
                }
            
            if suspicious_user_agents is not None:
                old_count = len(self.config.attack_patterns.suspicious_user_agents)
                self.config.attack_patterns.suspicious_user_agents = suspicious_user_agents
                new_count = len(suspicious_user_agents)
                results["updates"]["suspicious_user_agents"] = {
                    "old_count": old_count,
                    "new_count": new_count,
                    "status": "updated"
                }
                
                # Update user agent filter patterns
                self.user_agent_filter.suspicious_patterns = suspicious_user_agents
            
            # Recreate attack detector with new patterns
            self.middleware.attack_detector = AttackDetector(self.config.attack_patterns)
            
            logger.info("Attack patterns updated successfully", extra=results)
            
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Failed to update attack patterns: {e}")
        
        return results
    
    async def start_background_tasks(self):
        """Start background maintenance tasks."""
        logger.info("Starting security middleware background tasks")
        
        async def maintenance_loop():
            while True:
                try:
                    await asyncio.sleep(3600)  # Run every hour
                    await self.run_maintenance()
                except Exception as e:
                    logger.error(f"Background maintenance task failed: {e}")
        
        # Start the background task
        asyncio.create_task(maintenance_loop())
        logger.info("Background maintenance task started")
    
    def get_health_status(self) -> Dict:
        """
        Get health status of security middleware components.
        
        Returns:
            Dictionary with health status
        """
        status = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "components": {}
        }
        
        # Check each component
        try:
            # Rate limiter health
            rate_stats = self.rate_limiter.get_statistics()
            status["components"]["rate_limiter"] = {
                "status": "healthy",
                "tracked_ips": rate_stats.get("tracked_ips", 0)
            }
        except Exception as e:
            status["components"]["rate_limiter"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            status["overall_status"] = "degraded"
        
        try:
            # IP filter health
            ip_info = self.ip_filter.get_blocked_ips_info()
            status["components"]["ip_filter"] = {
                "status": "healthy",
                "blocked_ips": ip_info.get("total_permanent", 0) + ip_info.get("total_temporary", 0)
            }
        except Exception as e:
            status["components"]["ip_filter"] = {
                "status": "unhealthy", 
                "error": str(e)
            }
            status["overall_status"] = "degraded"
        
        try:
            # User agent filter health
            ua_stats = self.user_agent_filter.get_user_agent_stats()
            status["components"]["user_agent_filter"] = {
                "status": "healthy",
                "unique_agents": ua_stats.get("total_unique_agents", 0)
            }
        except Exception as e:
            status["components"]["user_agent_filter"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            status["overall_status"] = "degraded"
        
        return status
