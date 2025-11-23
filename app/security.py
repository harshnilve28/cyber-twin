"""
Security module for authentication, IP tracking, and threat detection.
This is the core cyber-defense logic.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from collections import defaultdict
import hashlib
import re

from app.config import settings
from app.models import IPStats, ThreatLevel, AttackType, ThreatEvent


class SecurityManager:
    """
    Manages security operations:
    - Tracks failed login attempts
    - Monitors suspicious IP behavior
    - Detects attack patterns
    - Manages IP blocking
    """
    
    def __init__(self):
        # In-memory storage (in production, use Redis or database)
        self.failed_logins: Dict[str, list] = defaultdict(list)  # IP -> list of timestamps
        self.ip_stats: Dict[str, IPStats] = {}  # IP -> IPStats
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> block_until timestamp
        self.request_counts: Dict[str, list] = defaultdict(list)  # IP -> list of request timestamps
        self.threat_events: list = []  # List of detected threats
        
    def check_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is currently blocked.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            True if IP is blocked, False otherwise
        """
        if ip_address not in self.blocked_ips:
            return False
            
        block_until = self.blocked_ips[ip_address]
        if datetime.utcnow() < block_until:
            return True
        else:
            # Block expired, remove it
            del self.blocked_ips[ip_address]
            if ip_address in self.ip_stats:
                self.ip_stats[ip_address].is_blocked = False
            return False
    
    def record_failed_login(self, ip_address: str, username: str) -> Tuple[bool, Optional[ThreatEvent]]:
        """
        Record a failed login attempt and check if IP should be blocked.
        
        Args:
            ip_address: The IP address of the failed login
            username: The username that failed
            
        Returns:
            Tuple of (should_block, threat_event)
        """
        current_time = datetime.utcnow()
        
        # Add to failed logins list
        self.failed_logins[ip_address].append(current_time)
        
        # Clean old entries (older than block duration)
        cutoff_time = current_time - timedelta(seconds=settings.login_block_duration_seconds)
        self.failed_logins[ip_address] = [
            ts for ts in self.failed_logins[ip_address] 
            if ts > cutoff_time
        ]
        
        # Update IP stats
        if ip_address not in self.ip_stats:
            self.ip_stats[ip_address] = IPStats(ip_address=ip_address)
        
        self.ip_stats[ip_address].failed_logins = len(self.failed_logins[ip_address])
        self.ip_stats[ip_address].last_seen = current_time
        
        # Check if threshold exceeded
        failed_count = len(self.failed_logins[ip_address])
        should_block = failed_count >= settings.max_failed_logins
        
        threat_event = None
        if should_block:
            # Block the IP
            block_until = current_time + timedelta(seconds=settings.login_block_duration_seconds)
            self.blocked_ips[ip_address] = block_until
            self.ip_stats[ip_address].is_blocked = True
            self.ip_stats[ip_address].block_until = block_until
            
            # Create threat event
            threat_event = ThreatEvent(
                threat_id=f"threat_{int(time.time())}_{hashlib.md5(ip_address.encode()).hexdigest()[:8]}",
                ip_address=ip_address,
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.BRUTE_FORCE,
                description=f"Brute force attack detected: {failed_count} failed login attempts from {ip_address}",
                metadata={
                    "username": username,
                    "failed_attempts": failed_count,
                    "block_duration_seconds": settings.login_block_duration_seconds
                }
            )
            self.threat_events.append(threat_event)
        
        return should_block, threat_event
    
    def record_successful_login(self, ip_address: str):
        """Reset failed login count for IP after successful login."""
        if ip_address in self.failed_logins:
            # Keep only recent failures (last hour)
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            self.failed_logins[ip_address] = [
                ts for ts in self.failed_logins[ip_address] 
                if ts > cutoff_time
            ]
    
    def record_request(self, ip_address: str) -> Optional[ThreatEvent]:
        """
        Record a request from an IP and check for suspicious behavior.
        
        Args:
            ip_address: The IP address making the request
            
        Returns:
            ThreatEvent if suspicious behavior detected, None otherwise
        """
        current_time = datetime.utcnow()
        
        # Track request timestamp
        self.request_counts[ip_address].append(current_time)
        
        # Clean old requests (outside time window)
        cutoff_time = current_time - timedelta(seconds=settings.suspicious_time_window_seconds)
        self.request_counts[ip_address] = [
            ts for ts in self.request_counts[ip_address]
            if ts > cutoff_time
        ]
        
        # Update IP stats
        if ip_address not in self.ip_stats:
            self.ip_stats[ip_address] = IPStats(ip_address=ip_address)
        
        request_count = len(self.request_counts[ip_address])
        self.ip_stats[ip_address].total_requests += 1
        self.ip_stats[ip_address].last_seen = current_time
        
        # Calculate suspicious score
        requests_per_second = request_count / settings.suspicious_time_window_seconds
        self.ip_stats[ip_address].suspicious_score = min(requests_per_second / 10.0, 1.0)
        
        # Check for suspicious behavior
        if request_count >= settings.suspicious_requests_threshold:
            threat_event = ThreatEvent(
                threat_id=f"threat_{int(time.time())}_{hashlib.md5(ip_address.encode()).hexdigest()[:8]}",
                ip_address=ip_address,
                threat_level=ThreatLevel.MEDIUM,
                attack_type=AttackType.SUSPICIOUS_IP,
                description=f"Suspicious activity: {request_count} requests in {settings.suspicious_time_window_seconds} seconds from {ip_address}",
                metadata={
                    "request_count": request_count,
                    "requests_per_second": requests_per_second,
                    "suspicious_score": self.ip_stats[ip_address].suspicious_score
                }
            )
            self.threat_events.append(threat_event)
            return threat_event
        
        return None
    
    def detect_attack_pattern(self, request_path: str, query_params: str, body: Optional[str] = None) -> Optional[ThreatEvent]:
        """
        Detect common attack patterns in requests.
        
        Args:
            request_path: The request path
            query_params: Query parameters as string
            body: Request body as string
            
        Returns:
            ThreatEvent if attack detected, None otherwise
        """
        # SQL Injection patterns
        sql_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bOR\b.*=.*)",
            r"(\bAND\b.*=.*)",
            r"('.*(--|#|\/\*))",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
        ]
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe[^>]*>",
        ]
        
        # Combine all input
        combined_input = f"{request_path} {query_params}"
        if body:
            combined_input += f" {body}"
        
        # Check for SQL injection
        for pattern in sql_patterns:
            if re.search(pattern, combined_input, re.IGNORECASE):
                threat_event = ThreatEvent(
                    threat_id=f"threat_{int(time.time())}_{hashlib.md5(combined_input.encode()).hexdigest()[:8]}",
                    ip_address="unknown",  # Will be set by caller
                    threat_level=ThreatLevel.HIGH,
                    attack_type=AttackType.SQL_INJECTION,
                    description=f"SQL injection attempt detected in request: {request_path}",
                    metadata={
                        "pattern": pattern,
                        "input": combined_input[:200]  # Limit length
                    }
                )
                return threat_event
        
        # Check for XSS
        for pattern in xss_patterns:
            if re.search(pattern, combined_input, re.IGNORECASE):
                threat_event = ThreatEvent(
                    threat_id=f"threat_{int(time.time())}_{hashlib.md5(combined_input.encode()).hexdigest()[:8]}",
                    ip_address="unknown",
                    threat_level=ThreatLevel.MEDIUM,
                    attack_type=AttackType.XSS,
                    description=f"XSS attempt detected in request: {request_path}",
                    metadata={
                        "pattern": pattern,
                        "input": combined_input[:200]
                    }
                )
                return threat_event
        
        return None
    
    def get_ip_stats(self, ip_address: str) -> Optional[IPStats]:
        """Get statistics for an IP address."""
        return self.ip_stats.get(ip_address)
    
    def get_blocked_ips(self) -> list:
        """Get list of currently blocked IP addresses."""
        current_time = datetime.utcnow()
        active_blocks = [
            ip for ip, block_until in self.blocked_ips.items()
            if current_time < block_until
        ]
        return active_blocks
    
    def get_recent_threats(self, limit: int = 100) -> list:
        """Get recent threat events."""
        return sorted(
            self.threat_events,
            key=lambda x: x.timestamp,
            reverse=True
        )[:limit]


# Global security manager instance
security_manager = SecurityManager()


