"""
Main FastAPI application.
This is the entry point for the Cyber-Twins microservice.
"""

import time
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
import structlog

from app.config import settings
from app.models import (
    LoginRequest, LoginResponse, HealthResponse, 
    MetricsResponse, ThreatEvent
)
from app.security import security_manager
from app.metrics import (
    http_requests_total, http_request_duration_seconds,
    failed_logins_total, successful_logins_total,
    blocked_ips_current, active_threats,
    threats_detected_total, remediation_actions_total,
    get_uptime_seconds
)

# Configure structured logging
logger = structlog.get_logger()

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Self-Healing Cloud Infrastructure with Digital Twin Cyber Defense"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup Prometheus instrumentation
if settings.prometheus_enabled:
    instrumentator = Instrumentator()
    instrumentator.instrument(app).expose(app, endpoint=settings.metrics_path)


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    # Check for forwarded IP (when behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    # Check for real IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    Security middleware that:
    - Tracks requests per IP
    - Detects attack patterns
    - Blocks suspicious IPs
    - Records metrics
    """
    start_time = time.time()
    ip_address = get_client_ip(request)
    
    # Check if IP is blocked
    if security_manager.check_ip_blocked(ip_address):
        logger.warning("Blocked IP attempted access", ip=ip_address)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "IP address is blocked due to suspicious activity"}
        )
    
    # Record request for suspicious behavior detection
    threat_event = security_manager.record_request(ip_address)
    if threat_event:
        logger.warning("Suspicious activity detected", ip=ip_address, threat=threat_event.threat_id)
        threats_detected_total.labels(
            threat_level=threat_event.threat_level.value,
            attack_type=threat_event.attack_type.value
        ).inc()
        active_threats.inc()
    
    # Detect attack patterns in request
    query_string = str(request.query_params)
    body = None
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.body()
            body_str = body.decode('utf-8', errors='ignore')
        except:
            body_str = None
    else:
        body_str = None
    
    pattern_threat = security_manager.detect_attack_pattern(
        request.url.path,
        query_string,
        body_str
    )
    
    if pattern_threat:
        pattern_threat.ip_address = ip_address
        logger.warning("Attack pattern detected", ip=ip_address, attack_type=pattern_threat.attack_type.value)
        threats_detected_total.labels(
            threat_level=pattern_threat.threat_level.value,
            attack_type=pattern_threat.attack_type.value
        ).inc()
        active_threats.inc()
    
    # Process request
    response = await call_next(request)
    
    # Record metrics
    duration = time.time() - start_time
    http_requests_total.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    http_request_duration_seconds.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)
    
    return response


@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint - Welcome message.
    """
    return {
        "message": "Welcome to Cyber-Twins: Self-Healing Cloud Infrastructure",
        "version": settings.app_version,
        "endpoints": {
            "health": "/health",
            "login": "/login",
            "metrics": "/metrics",
            "docs": "/docs"
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint.
    Returns system health status and uptime.
    """
    uptime = get_uptime_seconds()
    
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        timestamp=datetime.utcnow(),
        uptime_seconds=uptime
    )


@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(login_request: LoginRequest, request: Request):
    """
    Login endpoint with security tracking.
    
    This endpoint:
    - Validates credentials (demo: accepts 'admin'/'password123')
    - Tracks failed login attempts
    - Blocks IPs after threshold
    - Records security metrics
    """
    ip_address = get_client_ip(request)
    
    # Demo authentication (in production, use proper auth)
    valid_username = "admin"
    valid_password = "password123"
    
    if login_request.username == valid_username and login_request.password == valid_password:
        # Successful login
        security_manager.record_successful_login(ip_address)
        successful_logins_total.inc()
        
        logger.info("Successful login", username=login_request.username, ip=ip_address)
        
        # In production, generate JWT token here
        return LoginResponse(
            access_token="demo-token-12345",  # Replace with real JWT
            token_type="bearer",
            success=True,
            message="Login successful"
        )
    else:
        # Failed login
        should_block, threat_event = security_manager.record_failed_login(
            ip_address,
            login_request.username
        )
        
        failed_logins_total.labels(ip_address=ip_address).inc()
        
        if should_block and threat_event:
            logger.warning("IP blocked due to failed logins", ip=ip_address, threat_id=threat_event.threat_id)
            blocked_ips_current.inc()
            threats_detected_total.labels(
                threat_level=threat_event.threat_level.value,
                attack_type=threat_event.attack_type.value
            ).inc()
            
            # Trigger remediation (in production, this would call remediation service)
            remediation_actions_total.labels(
                action_type="ip_block",
                status="triggered"
            ).inc()
        
        logger.warning("Failed login attempt", username=login_request.username, ip=ip_address)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )


@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """
    Custom metrics endpoint (in addition to Prometheus /metrics).
    Returns summary of security metrics.
    """
    uptime = get_uptime_seconds()
    blocked_ips = security_manager.get_blocked_ips()
    recent_threats = security_manager.get_recent_threats(limit=10)
    
    return MetricsResponse(
        total_requests=0,  # Would be calculated from Prometheus
        failed_logins=sum(len(attempts) for attempts in security_manager.failed_logins.values()),
        blocked_ips=len(blocked_ips),
        active_threats=len([t for t in recent_threats if not t.remediated]),
        remediation_actions=0,  # Would be calculated from Prometheus
        uptime_seconds=uptime
    )


@app.get("/security/stats", tags=["Security"])
async def security_stats():
    """
    Get security statistics.
    Shows IP stats, blocked IPs, and recent threats.
    """
    blocked_ips = security_manager.get_blocked_ips()
    recent_threats = security_manager.get_recent_threats(limit=50)
    
    return {
        "blocked_ips": blocked_ips,
        "blocked_count": len(blocked_ips),
        "total_tracked_ips": len(security_manager.ip_stats),
        "recent_threats": [
            {
                "threat_id": t.threat_id,
                "ip_address": t.ip_address,
                "threat_level": t.threat_level.value,
                "attack_type": t.attack_type.value,
                "timestamp": t.timestamp.isoformat(),
                "description": t.description,
                "remediated": t.remediated
            }
            for t in recent_threats
        ],
        "threat_count": len(recent_threats)
    }


@app.get("/security/ip/{ip_address}", tags=["Security"])
async def get_ip_info(ip_address: str):
    """
    Get information about a specific IP address.
    """
    ip_stats = security_manager.get_ip_stats(ip_address)
    
    if not ip_stats:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No data found for IP: {ip_address}"
        )
    
    return {
        "ip_address": ip_stats.ip_address,
        "failed_logins": ip_stats.failed_logins,
        "total_requests": ip_stats.total_requests,
        "suspicious_score": ip_stats.suspicious_score,
        "is_blocked": ip_stats.is_blocked,
        "first_seen": ip_stats.first_seen.isoformat(),
        "last_seen": ip_stats.last_seen.isoformat(),
        "block_until": ip_stats.block_until.isoformat() if ip_stats.block_until else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )


