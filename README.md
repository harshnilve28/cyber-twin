# Self-Healing Cloud Infrastructure with Digital Twin Cyber Defense

## 🎯 Project Overview

This project implements a **self-healing cloud infrastructure** that uses **Digital Twin technology** for cyber defense. The system automatically detects, analyzes, and remediates security threats in real-time.

### Key Components:
1. **Python Microservice** (FastAPI) - Main application with security endpoints
2. **Cyber-Aware Logic** - Tracks failed logins, suspicious IPs, and attack patterns
3. **Docker Containerization** - Portable deployment
4. **Kubernetes Deployment** - Orchestrated container management
5. **Prometheus + Grafana** - Monitoring and visualization
6. **AWS Digital Twin** - DynamoDB + S3 for threat intelligence
7. **Automated Remediation** - Lambda functions and K8s controllers for auto-healing

---

## 📁 Project Structure

```
cyber-twins/
├── app/                          # Main application code
│   ├── __init__.py
│   ├── main.py                  # FastAPI application entry point
│   ├── models.py                # Data models (User, Threat, etc.)
│   ├── security.py              # Security logic (login, IP tracking)
│   ├── metrics.py               # Prometheus metrics collection
│   └── config.py                # Configuration management
├── k8s/                         # Kubernetes manifests
│   ├── deployment.yaml          # Application deployment
│   ├── service.yaml             # Service definition
│   ├── ingress.yaml             # Ingress configuration
│   ├── prometheus/              # Prometheus setup
│   │   ├── prometheus-config.yaml
│   │   └── prometheus-deployment.yaml
│   └── grafana/                 # Grafana setup
│       └── grafana-deployment.yaml
├── aws/                         # AWS integration
│   ├── digital-twin/            # Digital Twin scripts
│   │   ├── dynamodb_setup.py    # DynamoDB table creation
│   │   ├── s3_setup.py          # S3 bucket setup
│   │   └── sync_threats.py      # Sync threats to Digital Twin
│   ├── remediation/             # Auto-remediation
│   │   ├── lambda_function.py   # AWS Lambda remediation
│   │   └── k8s_controller.py    # Kubernetes controller
│   └── terraform/                # Infrastructure as Code (optional)
├── scripts/                     # Utility scripts
│   ├── setup.sh                 # Initial setup script
│   ├── deploy.sh                # Deployment script
│   ├── threat_simulator.py      # Simulate attacks for testing
│   └── test_endpoints.sh        # Test all endpoints
├── tests/                       # Test files
│   ├── test_security.py
│   └── test_endpoints.py
├── Dockerfile                   # Docker image definition
├── .dockerignore               # Docker ignore patterns
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
└── README.md                   # This file
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9+
- Docker Desktop
- Kubernetes (Minikube) installed
- kubectl configured
- AWS CLI configured (for AWS features)

### Step 1: Setup Python Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit .env with your settings
# Add AWS credentials, database URLs, etc.
```

### Step 3: Run Locally (Development)

```bash
# Start the application
python -m app.main

# Or use uvicorn directly
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Step 4: Test Endpoints

```bash
# Test health endpoint
curl http://localhost:8000/health

# Test login (will fail initially - that's expected for security)
curl -X POST http://localhost:8000/login -H "Content-Type: application/json" -d '{"username":"test","password":"wrong"}'

# View metrics
curl http://localhost:8000/metrics
```

### Step 5: Build Docker Image

```bash
# Build the image
docker build -t cyber-twins:latest .

# Run container locally
docker run -p 8000:8000 cyber-twins:latest
```

### Step 6: Deploy to Kubernetes (Minikube)

```bash
# Start Minikube
minikube start

# Apply Kubernetes manifests
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Check deployment status
kubectl get pods
kubectl get services

# Access the service
minikube service cyber-twins-service
```

### Step 7: Setup Monitoring (Prometheus + Grafana)

```bash
# Deploy Prometheus
kubectl apply -f k8s/prometheus/

# Deploy Grafana
kubectl apply -f k8s/grafana/

# Access Grafana (port-forward)
kubectl port-forward svc/grafana-service 3000:3000
# Open http://localhost:3000 (default: admin/admin)
```

### Step 8: Setup AWS Digital Twin

```bash
# Configure AWS credentials
aws configure

# Create DynamoDB table
python aws/digital-twin/dynamodb_setup.py

# Create S3 bucket
python aws/digital-twin/s3_setup.py

# Start syncing threats
python aws/digital-twin/sync_threats.py
```

---

## 🔒 Security Features

### 1. Failed Login Tracking
- Tracks failed login attempts per IP
- Implements exponential backoff
- Blocks IPs after threshold

### 2. Suspicious IP Detection
- Monitors request patterns
- Detects brute-force attempts
- Tracks geolocation anomalies

### 3. Attack Pattern Recognition
- SQL injection detection
- XSS pattern matching
- Rate limiting per endpoint

---

## 📊 Monitoring & Metrics

### Prometheus Metrics Exposed:
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency
- `failed_logins_total` - Failed authentication attempts
- `suspicious_ips_total` - Detected suspicious IPs
- `remediation_actions_total` - Auto-remediation actions taken

### Grafana Dashboards:
- Security Overview
- Attack Patterns
- Remediation Actions
- System Health

---

## 🔄 Auto-Remediation Flow

1. **Detection**: System detects threat (failed logins, suspicious IP)
2. **Analysis**: Threat data sent to Digital Twin (DynamoDB)
3. **Decision**: Remediation engine evaluates threat level
4. **Action**: 
   - Block IP (K8s NetworkPolicy)
   - Scale down affected pods
   - Trigger Lambda for AWS-level blocking
5. **Verification**: Monitor remediation success
6. **Learning**: Update Digital Twin with results

---

## 🧪 Testing

```bash
# Run unit tests
pytest tests/

# Run threat simulation
python scripts/threat_simulator.py

# Test all endpoints
bash scripts/test_endpoints.sh
```

---

## 🛠️ Troubleshooting

### Common Issues:

1. **Port already in use**
   ```bash
   # Find and kill process
   lsof -i :8000  # Linux/Mac
   netstat -ano | findstr :8000  # Windows
   ```

2. **Kubernetes pods not starting**
   ```bash
   kubectl describe pod <pod-name>
   kubectl logs <pod-name>
   ```

3. **Prometheus not scraping metrics**
   - Check service discovery configuration
   - Verify pod annotations for scraping

4. **AWS connection issues**
   ```bash
   aws sts get-caller-identity  # Verify credentials
   ```

---

## 📚 Learning Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Kubernetes Basics](https://kubernetes.io/docs/tutorials/)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [AWS Digital Twin](https://aws.amazon.com/iot-twinmaker/)

---

## 🤝 Contributing

This is a learning project. Feel free to:
- Add more security features
- Improve remediation logic
- Enhance monitoring dashboards
- Add more threat detection patterns

---

## 📝 License

MIT License - Feel free to use for learning and projects!

---

## 🎓 Next Steps

1. ✅ Complete basic setup
2. ✅ Test all endpoints
3. ✅ Deploy to Kubernetes
4. ✅ Setup monitoring
5. ✅ Integrate AWS Digital Twin
6. ✅ Test auto-remediation
7. 🚀 Deploy to production (EKS)

---

**Happy Learning! 🚀**


