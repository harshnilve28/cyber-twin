# app/main.py
from fastapi import FastAPI, Request, HTTPException, Response
from pydantic import BaseModel
import time
import uvicorn

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="Cyber-Twins - Self Healing")

# --- Prometheus metrics ---
HTTP_REQ_TOTAL = Counter("http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
HTTP_REQ_LATENCY = Histogram("http_request_duration_seconds", "Request latency seconds", ["endpoint"])
FAILED_LOGINS = Counter("failed_logins_total", "Failed authentication attempts")
SUSPICIOUS_IPS = Counter("suspicious_ips_total", "Suspicious IPs detected")
REMEDIATIONS = Counter("remediation_actions_total", "Auto-remediation actions taken")

# --- simple in-memory stores (for dev) ---
FAILED_ATTEMPTS = {}   # {ip: [timestamps]}
BLOCKED_IPS = {}      # {ip: unblock_epoch}

LOGIN_THRESHOLD = 5               # attempts
BLOCK_DURATION_SECONDS = 60 * 5   # 5 minutes

class LoginPayload(BaseModel):
    username: str
    password: str

def record_request(endpoint: str, method: str, status: int, duration: float):
    HTTP_REQ_TOTAL.labels(method=method, endpoint=endpoint, status=str(status)).inc()
    HTTP_REQ_LATENCY.labels(endpoint=endpoint).observe(duration)

@app.get("/health")
async def health():
    start = time.time()
    resp = {"status": "ok", "time": int(start)}
    duration = time.time() - start
    record_request("/health", "GET", 200, duration)
    return resp

@app.post("/login")
async def login(payload: LoginPayload, request: Request):
    start = time.time()
    client_ip = request.client.host if request.client else "unknown"

    # check blocked IP
    unblock_time = BLOCKED_IPS.get(client_ip)
    now = time.time()
    if unblock_time and now < unblock_time:
        FAILED_LOGINS.inc()
        SUSPICIOUS_IPS.inc()
        record_request("/login", "POST", 403, time.time()-start)
        raise HTTPException(status_code=403, detail="IP temporarily blocked")

    # Dummy auth check (replace with real lookup)
    correct_password = "changeme"
    if payload.password != correct_password:
        FAILED_LOGINS.inc()
        FAILED_ATTEMPTS.setdefault(client_ip, []).append(now)

        # prune attempts older than window
        window = 60 * 10
        FAILED_ATTEMPTS[client_ip] = [t for t in FAILED_ATTEMPTS[client_ip] if now - t < window]

        if len(FAILED_ATTEMPTS[client_ip]) >= LOGIN_THRESHOLD:
            BLOCKED_IPS[client_ip] = now + BLOCK_DURATION_SECONDS
            REMEDIATIONS.inc()
            SUSPICIOUS_IPS.inc()

        record_request("/login", "POST", 401, time.time()-start)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # success - reset attempts
    FAILED_ATTEMPTS.pop(client_ip, None)
    record_request("/login", "POST", 200, time.time()-start)
    return {"detail": "login successful"}

@app.get("/metrics")
async def metrics():
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# If you want to run via python -m app.main
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
