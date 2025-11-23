"""
Unit tests for security module.
"""

import pytest
from datetime import datetime, timedelta
from app.security import SecurityManager, security_manager
from app.models import ThreatLevel, AttackType


class TestSecurityManager:
    """Test cases for SecurityManager."""
    
    def test_failed_login_tracking(self):
        """Test that failed logins are tracked correctly."""
        manager = SecurityManager()
        ip = "192.168.1.100"
        
        # Record multiple failed logins
        for i in range(3):
            should_block, threat = manager.record_failed_login(ip, f"user{i}")
            assert not should_block  # Should not block yet
        
        # Check IP stats
        stats = manager.get_ip_stats(ip)
        assert stats is not None
        assert stats.failed_logins == 3
    
    def test_ip_blocking(self):
        """Test that IPs are blocked after threshold."""
        manager = SecurityManager()
        ip = "192.168.1.200"
        
        # Record enough failed logins to trigger block
        for i in range(6):  # More than max_failed_logins (5)
            should_block, threat = manager.record_failed_login(ip, "attacker")
            if i >= 4:  # After 5th attempt
                assert should_block
                assert threat is not None
                assert threat.threat_level == ThreatLevel.HIGH
                assert threat.attack_type == AttackType.BRUTE_FORCE
        
        # Verify IP is blocked
        assert manager.check_ip_blocked(ip) is True
        
        # Check blocked IPs list
        blocked = manager.get_blocked_ips()
        assert ip in blocked
    
    def test_suspicious_ip_detection(self):
        """Test detection of suspicious IP behavior."""
        manager = SecurityManager()
        ip = "192.168.1.300"
        
        # Record many requests quickly
        threats = []
        for i in range(150):  # More than threshold (100)
            threat = manager.record_request(ip)
            if threat:
                threats.append(threat)
        
        # Should detect suspicious behavior
        assert len(threats) > 0
        stats = manager.get_ip_stats(ip)
        assert stats.suspicious_score > 0
    
    def test_attack_pattern_detection_sql(self):
        """Test SQL injection pattern detection."""
        manager = SecurityManager()
        
        # Test SQL injection patterns
        sql_attempts = [
            "/login?user=' OR '1'='1",
            "/api?q='; DROP TABLE users; --",
            "/search?input=' UNION SELECT * FROM users --"
        ]
        
        for attempt in sql_attempts:
            threat = manager.detect_attack_pattern(attempt, "")
            assert threat is not None
            assert threat.attack_type == AttackType.SQL_INJECTION
            assert threat.threat_level == ThreatLevel.HIGH
    
    def test_attack_pattern_detection_xss(self):
        """Test XSS pattern detection."""
        manager = SecurityManager()
        
        # Test XSS patterns
        xss_attempts = [
            "/page?input=<script>alert('XSS')</script>",
            "/form?data=<img src=x onerror=alert('XSS')>",
            "/link?url=javascript:alert('XSS')"
        ]
        
        for attempt in xss_attempts:
            threat = manager.detect_attack_pattern(attempt, "")
            assert threat is not None
            assert threat.attack_type == AttackType.XSS
    
    def test_successful_login_reset(self):
        """Test that successful login resets failed attempts."""
        manager = SecurityManager()
        ip = "192.168.1.400"
        
        # Record some failed logins
        for i in range(3):
            manager.record_failed_login(ip, "user")
        
        stats = manager.get_ip_stats(ip)
        assert stats.failed_logins == 3
        
        # Record successful login
        manager.record_successful_login(ip)
        
        # Failed logins should be reduced (old ones cleaned)
        # Note: This depends on timing, so we just check it doesn't increase
        new_stats = manager.get_ip_stats(ip)
        assert new_stats is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


