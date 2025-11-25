from fastapi import FastAPI, Request, HTTPException, Response
from pydantic import BaseModel
import time
import uvicorn

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Import the real security engine (Digital Twin enabled)
from app.security import security_manager

app = FastAPI(title="Cyber-Twins - Self Healing")


# ================================
# PROMETHEUS METRICS
# ================================
HTTP_REQ_TOTAL = Counter("http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
HTTP_REQ_LATENCY = Histogram("http_request_duration_seconds", "Request latency seconds", ["endpoint"])
FAILED_LOGINS = Counter("failed_logins_total", "Failed authentication attempts")
SUSPICIOUS_IPS = Counter("suspicious_ips_total", "Suspicious IPs detected")
REMEDIATIONS = Counter("remediation_actions_total", "Auto-remediation actions taken")


def record_request(endpoint: str, method: str, status: int, duration: float):
    HTTP_REQ_TOTAL.labels(method=method, endpoint=endpoint, status=str(status)).inc()
    HTTP_REQ_LATENCY.labels(endpoint=endpoint).observe(duration)


# ================================
# HEALTH CHECK
# ================================
@app.get("/health")
async def health():
    start = time.time()
    resp = {"status": "ok", "time": int(start)}
    duration = time.time() - start
    record_request("/health", "GET", 200, duration)
    return resp


# ================================
# LOGIN ROUTE (DIGITAL TWIN ENABLED)
# ================================
class LoginPayload(BaseModel):
    username: str
    password: str
    ip: str  # <-- we require IP in payload


@app.post("/login")
async def login(payload: LoginPayload, request: Request):
    start = time.time()

    client_ip = payload.ip  # use provided IP
    now = time.time()

    # -------------------------------------------
    # 1. CHECK IF IP ALREADY BLOCKED
    # -------------------------------------------
    if security_manager.check_ip_blocked(client_ip):
        FAILED_LOGINS.inc()
        SUSPICIOUS_IPS.inc()
        record_request("/login", "POST", 403, time.time() - start)

        raise HTTPException(status_code=403, detail="IP temporarily blocked by security engine")

    # -------------------------------------------
    # 2. VALIDATE PASSWORD (dummy)
    # -------------------------------------------
    correct_password = "changeme"

    if payload.password != correct_password:
        FAILED_LOGINS.inc()

        # record failed login & check brute-force
        should_block, threat_event = security_manager.record_failed_login(
            ip_address=client_ip,
            username=payload.username
        )

        if should_block and threat_event:
            # A threat was detected and synced to Digital Twin
            SUSPICIOUS_IPS.inc()
            REMEDIATIONS.inc()

            record_request("/login", "POST", 403, time.time() - start)

            return {
                "status": "blocked",
                "reason": "Too many failed login attempts",
                "threat_event": threat_event.dict() if hasattr(threat_event, "dict") else str(threat_event)
            }

        # else: normal failed login
        record_request("/login", "POST", 401, time.time() - start)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # -------------------------------------------
    # 3. SUCCESSFUL LOGIN
    # -------------------------------------------
    security_manager.record_successful_login(client_ip)

    record_request("/login", "POST", 200, time.time() - start)
    return {"detail": "login successful", "ip": client_ip}


# ================================
# METRICS ENDPOINT
# ================================
@app.get("/metrics")
async def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# ================================
# ENTRY POINT
# ================================
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
