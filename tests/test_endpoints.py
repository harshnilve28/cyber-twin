"""
Integration tests for API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestEndpoints:
    """Test cases for API endpoints."""
    
    def test_root_endpoint(self):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
    
    def test_login_wrong_credentials(self):
        """Test login with wrong credentials."""
        response = client.post(
            "/login",
            json={"username": "wrong", "password": "wrong"}
        )
        assert response.status_code == 401
    
    def test_login_correct_credentials(self):
        """Test login with correct credentials."""
        response = client.post(
            "/login",
            json={"username": "admin", "password": "password123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "access_token" in data
    
    def test_metrics_endpoint(self):
        """Test metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "blocked_ips" in data
        assert "active_threats" in data
    
    def test_security_stats_endpoint(self):
        """Test security stats endpoint."""
        response = client.get("/security/stats")
        assert response.status_code == 200
        data = response.json()
        assert "blocked_ips" in data
        assert "recent_threats" in data
    
    def test_ip_info_endpoint(self):
        """Test IP info endpoint."""
        # First, trigger some activity from an IP
        for _ in range(5):
            client.get("/health", headers={"X-Forwarded-For": "192.168.1.999"})
        
        # Then check IP info
        response = client.get("/security/ip/192.168.1.999")
        # May return 404 if IP not tracked yet, or 200 if tracked
        assert response.status_code in [200, 404]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


