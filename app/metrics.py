"""
Prometheus metrics collection and instrumentation.
Exposes metrics for monitoring security events and system health.
"""

from prometheus_client import Counter, Histogram, Gauge
import time

# HTTP Metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

# Security Metrics
failed_logins_total = Counter(
    'failed_logins_total',
    'Total number of failed login attempts',
    ['ip_address']
)

successful_logins_total = Counter(
    'successful_logins_total',
    'Total number of successful logins'
)

suspicious_ips_total = Counter(
    'suspicious_ips_total',
    'Total number of suspicious IPs detected',
    ['ip_address']
)

blocked_ips_total = Counter(
    'blocked_ips_total',
    'Total number of IP blocks',
    ['ip_address', 'reason']
)

threats_detected_total = Counter(
    'threats_detected_total',
    'Total number of threats detected',
    ['threat_level', 'attack_type']
)

# Remediation Metrics
remediation_actions_total = Counter(
    'remediation_actions_total',
    'Total number of remediation actions taken',
    ['action_type', 'status']
)

# System Metrics
active_connections = Gauge(
    'active_connections',
    'Number of active connections'
)

blocked_ips_current = Gauge(
    'blocked_ips_current',
    'Current number of blocked IP addresses'
)

active_threats = Gauge(
    'active_threats',
    'Current number of active threats'
)

# Application start time for uptime calculation
app_start_time = time.time()


def get_uptime_seconds() -> float:
    """Calculate application uptime in seconds."""
    return time.time() - app_start_time


