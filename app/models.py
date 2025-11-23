"""
Data models for the application.
Defines the structure of data used throughout the system.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    """Types of detected attacks."""
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_IP = "suspicious_ip"
    UNKNOWN = "unknown"


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: Optional[str] = None
    token_type: str = "bearer"
    success: bool = False
    message: str = ""


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    uptime_seconds: float = 0.0


class ThreatEvent(BaseModel):
    """Represents a detected security threat."""
    threat_id: str
    ip_address: str
    threat_level: ThreatLevel
    attack_type: AttackType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    description: str
    metadata: dict = Field(default_factory=dict)
    remediated: bool = False
    remediation_action: Optional[str] = None


class IPStats(BaseModel):
    """Statistics for an IP address."""
    ip_address: str
    failed_logins: int = 0
    total_requests: int = 0
    suspicious_score: float = 0.0
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    is_blocked: bool = False
    block_until: Optional[datetime] = None


class MetricsResponse(BaseModel):
    """Metrics summary response."""
    total_requests: int
    failed_logins: int
    blocked_ips: int
    active_threats: int
    remediation_actions: int
    uptime_seconds: float


