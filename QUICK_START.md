# ⚡ Quick Start Guide

Get up and running in 5 minutes!

## 🚀 Fastest Path to Running

### 1. Setup (One-time)
```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Application
```bash
python -m app.main
```

### 3. Test It
Open browser: http://localhost:8000

Or use curl:
```bash
# Health check
curl http://localhost:8000/health

# Login (demo credentials)
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}'
```

### 4. Test Security Features
```bash
# Simulate attacks
python scripts/threat_simulator.py --test brute-force
```

---

## 🐳 Docker Quick Start

```bash
# Build
docker build -t cyber-twins:latest .

# Run
docker run -p 8000:8000 cyber-twins:latest
```

---

## ☸️ Kubernetes Quick Start

```bash
# Start Minikube
minikube start

# Use Minikube Docker
eval $(minikube docker-env)

# Build image
docker build -t cyber-twins:latest .

# Deploy
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Access
minikube service cyber-twins-nodeport
```

---

## 📊 Monitoring Quick Start

```bash
# Deploy Prometheus
kubectl apply -f k8s/prometheus/

# Deploy Grafana
kubectl apply -f k8s/grafana/

# Access Grafana
kubectl port-forward svc/grafana-service 3000:3000
# Open http://localhost:3000 (admin/admin)
```

---

## ☁️ AWS Quick Start (Optional)

```bash
# Configure AWS
aws configure

# Setup Digital Twin
python aws/digital-twin/dynamodb_setup.py
python aws/digital-twin/s3_setup.py

# Start syncing threats
python aws/digital-twin/sync_threats.py --continuous
```

---

## 🎯 Key Endpoints

- `GET /` - Welcome message
- `GET /health` - Health check
- `POST /login` - Login (admin/password123)
- `GET /metrics` - Security metrics
- `GET /security/stats` - Detailed security stats
- `GET /security/ip/{ip}` - IP information

---

## 🔍 Common Commands

```bash
# View logs (if in K8s)
kubectl logs -l app=cyber-twins

# Check pods
kubectl get pods

# Test all endpoints
bash scripts/test_endpoints.sh

# Run threat simulation
python scripts/threat_simulator.py
```

---

**Need more details?** See [SETUP_GUIDE.md](SETUP_GUIDE.md) for comprehensive instructions.


