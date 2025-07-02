"""
Attack Detection Module

This module contains attack pattern detection logic for various types of security threats.
"""

from typing import Dict, List, Optional, Tuple
from fastapi import Request

from ..config import AttackPatterns
from ..enums import AttackType, SecurityEventType
from ..utils import SecurityUtils


class AttackDetector:
    """Detector for various attack patterns in HTTP requests."""
    
    def __init__(self, patterns: AttackPatterns):
        """
        Initialize attack detector with patterns.
        
        Args:
            patterns: Attack patterns configuration
        """
        self.patterns = patterns
    
    def detect_attacks(self, request: Request) -> List[Dict]:
        """
        Detect various attack patterns in the request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            List of detected attacks with details
        """
        detected_attacks = []
        request_data = SecurityUtils.extract_request_data(request)
        
        # SQL Injection Detection
        sql_attack = self._detect_sql_injection(request_data)
        if sql_attack:
            detected_attacks.append(sql_attack)
        
        # XSS Detection
        xss_attack = self._detect_xss(request_data)
        if xss_attack:
            detected_attacks.append(xss_attack)
        
        # Path Traversal Detection
        path_attack = self._detect_path_traversal(request_data)
        if path_attack:
            detected_attacks.append(path_attack)
        
        return detected_attacks
    
    def _detect_sql_injection(self, request_data: Dict) -> Optional[Dict]:
        """
        Detect SQL injection attempts.
        
        Args:
            request_data: Extracted request data
            
        Returns:
            Attack details if detected, None otherwise
        """
        full_url = request_data.get("full_url", "")
        
        for pattern in self.patterns.sql_injection_patterns:
            if pattern in full_url:
                return {
                    "attack_type": AttackType.SQL_INJECTION.value,
                    "event_type": SecurityEventType.SQL_INJECTION_ATTEMPT.value,
                    "detected_pattern": pattern,
                    "payload": full_url,
                    "confidence": self._calculate_confidence(pattern, full_url, "sql")
                }
        
        return None
    
    def _detect_xss(self, request_data: Dict) -> Optional[Dict]:
        """
        Detect Cross-Site Scripting (XSS) attempts.
        
        Args:
            request_data: Extracted request data
            
        Returns:
            Attack details if detected, None otherwise
        """
        full_url = request_data.get("full_url", "")
        
        for pattern in self.patterns.xss_patterns:
            if pattern in full_url:
                return {
                    "attack_type": AttackType.XSS.value,
                    "event_type": SecurityEventType.XSS_ATTEMPT.value,
                    "detected_pattern": pattern,
                    "payload": full_url,
                    "confidence": self._calculate_confidence(pattern, full_url, "xss")
                }
        
        return None
    
    def _detect_path_traversal(self, request_data: Dict) -> Optional[Dict]:
        """
        Detect path traversal attempts.
        
        Args:
            request_data: Extracted request data
            
        Returns:
            Attack details if detected, None otherwise
        """
        path = request_data.get("path", "")
        
        for pattern in self.patterns.path_traversal_patterns:
            if pattern in path:
                return {
                    "attack_type": AttackType.PATH_TRAVERSAL.value,
                    "event_type": SecurityEventType.PATH_TRAVERSAL_ATTEMPT.value,
                    "detected_pattern": pattern,
                    "payload": path,
                    "confidence": self._calculate_confidence(pattern, path, "path_traversal")
                }
        
        return None
    
    def _calculate_confidence(self, pattern: str, payload: str, attack_type: str) -> float:
        """
        Calculate confidence score for detected attack.
        
        Args:
            pattern: Detected pattern
            payload: Request payload
            attack_type: Type of attack
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        # Base confidence
        confidence = 0.7
        
        # Increase confidence for more specific patterns
        if attack_type == "sql":
            if any(dangerous in pattern.lower() for dangerous in ["drop", "delete", "union", "exec"]):
                confidence += 0.2
        elif attack_type == "xss":
            if any(dangerous in pattern.lower() for dangerous in ["script", "javascript", "eval"]):
                confidence += 0.2
        elif attack_type == "path_traversal":
            if "../" in pattern or "..\\" in pattern:
                confidence += 0.2
        
        # Increase confidence for encoded patterns
        if any(encoded in payload for encoded in ["%2e", "%2f", "%5c"]):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def is_suspicious_payload(self, payload: str) -> bool:
        """
        Check if payload contains suspicious content.
        
        Args:
            payload: Request payload to analyze
            
        Returns:
            True if suspicious, False otherwise
        """
        if not payload:
            return False
        
        payload_lower = payload.lower()
        
        # Check for multiple attack indicators
        suspicious_indicators = [
            "union select", "drop table", "<script", "javascript:",
            "../", "eval(", "exec(", "document.cookie"
        ]
        
        found_indicators = sum(1 for indicator in suspicious_indicators if indicator in payload_lower)
        
        # Consider suspicious if multiple indicators found
        return found_indicators >= 2
    
    def get_attack_severity(self, attack_type: str, confidence: float) -> str:
        """
        Determine attack severity based on type and confidence.
        
        Args:
            attack_type: Type of attack detected
            confidence: Confidence score
            
        Returns:
            Severity level string
        """
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.7:
            if attack_type in [AttackType.SQL_INJECTION.value, AttackType.PATH_TRAVERSAL.value]:
                return "high"
            else:
                return "medium"
        else:
            return "low"
