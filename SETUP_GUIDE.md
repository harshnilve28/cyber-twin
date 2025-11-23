# 🚀 Cyber-Twins Setup Guide

## Step-by-Step Setup Instructions

This guide will walk you through setting up the entire Cyber-Twins system from scratch.

---

## 📋 Prerequisites

Before you begin, ensure you have:

1. **Python 3.9+** installed
   ```bash
   python3 --version
   ```

2. **Docker Desktop** installed (for containerization)
   ```bash
   docker --version
   ```

3. **Kubernetes (Minikube)** for local deployment
   ```bash
   minikube version
   kubectl version --client
   ```

4. **AWS CLI** (optional, for AWS features)
   ```bash
   aws --version
   ```

---

## 🎯 Step 1: Initial Setup

### 1.1 Clone/Navigate to Project
```bash
cd cyber-twins
```

### 1.2 Run Setup Script
```bash
# Linux/Mac
bash scripts/setup.sh

# Windows (PowerShell)
# Run setup.sh manually or use WSL
```

This script will:
- ✅ Create Python virtual environment
- ✅ Install all dependencies
- ✅ Create `.env` file from template
- ✅ Check for required tools

### 1.3 Activate Virtual Environment
```bash
# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 1.4 Configure Environment Variables
Edit `.env` file with your settings:
```bash
# Required for basic operation
SECRET_KEY=your-secret-key-here

# Optional: AWS configuration (for Digital Twin)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
```

---

## 🧪 Step 2: Test Locally

### 2.1 Start the Application
```bash
python -m app.main
```

Or using uvicorn directly:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 2.2 Test Endpoints
Open a new terminal and run:
```bash
bash scripts/test_endpoints.sh
```

Or test manually:
```bash
# Health check
curl http://localhost:8000/health

# Root endpoint
curl http://localhost:8000/

# Login (wrong credentials - should fail)
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"wrong"}'

# Login (correct credentials)
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}'
```

### 2.3 Run Threat Simulation
Test the security features:
```bash
python scripts/threat_simulator.py
```

This will simulate:
- 🔴 Brute force attacks
- 🔴 SQL injection attempts
- 🔴 XSS attacks
- 🔴 Rate limiting tests
- 🔴 Suspicious IP detection

---

## 🐳 Step 3: Docker Setup

### 3.1 Build Docker Image
```bash
docker build -t cyber-twins:latest .
```

### 3.2 Run Container
```bash
docker run -p 8000:8000 cyber-twins:latest
```

### 3.3 Verify
```bash
curl http://localhost:8000/health
```

---

## ☸️ Step 4: Kubernetes Deployment (Minikube)

### 4.1 Start Minikube
```bash
minikube start
```

### 4.2 Configure Docker for Minikube
```bash
eval $(minikube docker-env)
```

### 4.3 Build Image in Minikube
```bash
docker build -t cyber-twins:latest .
```

### 4.4 Deploy to Kubernetes
```bash
bash scripts/deploy.sh
```

Or manually:
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### 4.5 Check Deployment
```bash
kubectl get pods
kubectl get services
```

### 4.6 Access the Application
```bash
# Using Minikube service
minikube service cyber-twins-nodeport

# Or port-forward
kubectl port-forward svc/cyber-twins-service 8000:80
```

Then access: `http://localhost:8000`

---

## 📊 Step 5: Setup Monitoring (Prometheus + Grafana)

### 5.1 Deploy Prometheus
```bash
kubectl apply -f k8s/prometheus/prometheus-config.yaml
kubectl apply -f k8s/prometheus/prometheus-deployment.yaml
```

### 5.2 Deploy Grafana
```bash
kubectl apply -f k8s/grafana/grafana-deployment.yaml
```

### 5.3 Access Prometheus
```bash
kubectl port-forward svc/prometheus-service 9090:9090
```
Open: `http://localhost:9090`

### 5.4 Access Grafana
```bash
kubectl port-forward svc/grafana-service 3000:3000
```
Open: `http://localhost:3000`
- Username: `admin`
- Password: `admin` (change on first login)

### 5.5 Configure Grafana Data Source
1. Go to Configuration → Data Sources
2. Add Prometheus
3. URL: `http://prometheus-service:9090`
4. Save & Test

---

## ☁️ Step 6: AWS Digital Twin Setup (Optional)

### 6.1 Configure AWS Credentials
```bash
aws configure
```

Enter:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., `us-east-1`)
- Default output format (e.g., `json`)

### 6.2 Create DynamoDB Table
```bash
python aws/digital-twin/dynamodb_setup.py
```

This creates:
- Table: `cyber-twins-threats`
- GSI: `ip_address-index` for querying by IP

### 6.3 Create S3 Bucket
```bash
python aws/digital-twin/s3_setup.py
```

**Note:** S3 bucket names must be globally unique. If it fails, edit the script and change `BUCKET_NAME`.

### 6.4 Start Threat Sync
```bash
# Single sync
python aws/digital-twin/sync_threats.py

# Continuous sync (runs forever)
python aws/digital-twin/sync_threats.py --continuous

# Custom interval (every 30 seconds)
python aws/digital-twin/sync_threats.py --continuous --interval 30
```

---

## 🔧 Step 7: Automated Remediation

### 7.1 Kubernetes Controller (Local)

The K8s controller can run as a separate pod or locally:

```bash
# Make sure you have kubeconfig configured
export K8S_NAMESPACE=default
export APP_URL=http://cyber-twins-service:80

python aws/remediation/k8s_controller.py
```

This will:
- Watch for new threats
- Create NetworkPolicies to block IPs
- Update threat intelligence ConfigMap

### 7.2 AWS Lambda Function

To deploy the Lambda function:

1. **Package the function:**
```bash
cd aws/remediation
zip lambda_function.zip lambda_function.py
```

2. **Create Lambda function in AWS Console:**
   - Runtime: Python 3.11
   - Handler: `lambda_function.lambda_handler`
   - Environment variables:
     - `THREATS_TABLE`: `cyber-twins-threats`
     - `S3_BUCKET`: `cyber-twins-digital-twin`

3. **Configure trigger:**
   - DynamoDB Stream (on threats table)
   - Or EventBridge (custom events)

4. **Set IAM permissions:**
   - DynamoDB read/write
   - S3 write
   - WAF update (if using)
   - EC2 Security Group modify (if using)

---

## 🧪 Step 8: Testing the Full System

### 8.1 End-to-End Test

1. **Start the application:**
```bash
python -m app.main
```

2. **Run threat simulation:**
```bash
python scripts/threat_simulator.py --test brute-force
```

3. **Check security stats:**
```bash
curl http://localhost:8000/security/stats
```

4. **Verify IP blocking:**
```bash
# Try to access with blocked IP
curl -H "X-Forwarded-For: 192.168.1.100" http://localhost:8000/health
# Should return 403
```

5. **Check metrics:**
```bash
curl http://localhost:8000/metrics
```

### 8.2 Monitor in Grafana

1. Create dashboard with queries:
   - `failed_logins_total`
   - `blocked_ips_current`
   - `threats_detected_total`
   - `remediation_actions_total`

2. Set up alerts for:
   - High number of failed logins
   - Critical threats detected
   - Remediation failures

---

## 🐛 Troubleshooting

### Issue: Application won't start
```bash
# Check if port is in use
lsof -i :8000  # Linux/Mac
netstat -ano | findstr :8000  # Windows

# Check logs
python -m app.main  # Should show errors
```

### Issue: Kubernetes pods not starting
```bash
# Check pod status
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name>

# Check events
kubectl get events --sort-by='.lastTimestamp'
```

### Issue: Prometheus not scraping
```bash
# Check Prometheus targets
# Go to http://localhost:9090/targets

# Verify pod annotations
kubectl get pod <pod-name> -o yaml | grep prometheus
```

### Issue: AWS connection errors
```bash
# Verify credentials
aws sts get-caller-identity

# Check region
aws configure get region

# Test DynamoDB access
aws dynamodb list-tables
```

### Issue: Docker build fails
```bash
# Check Docker is running
docker ps

# Check Dockerfile syntax
docker build -t test . --no-cache
```

---

## 📚 Next Steps

1. **Customize Security Rules:**
   - Edit `app/security.py` to adjust thresholds
   - Modify `app/config.py` for different settings

2. **Add More Attack Patterns:**
   - Extend `detect_attack_pattern()` in `security.py`
   - Add new threat types in `models.py`

3. **Enhance Monitoring:**
   - Create custom Grafana dashboards
   - Set up alerting rules in Prometheus

4. **Production Deployment:**
   - Use EKS instead of Minikube
   - Set up CI/CD pipeline
   - Configure proper secrets management
   - Enable TLS/SSL

5. **Advanced Features:**
   - Integrate with SIEM systems
   - Add machine learning threat detection
   - Implement threat intelligence feeds

---

## 🎓 Learning Resources

- **FastAPI:** https://fastapi.tiangolo.com/
- **Kubernetes:** https://kubernetes.io/docs/tutorials/
- **Prometheus:** https://prometheus.io/docs/
- **AWS Digital Twin:** https://aws.amazon.com/iot-twinmaker/

---

## ✅ Checklist

- [ ] Python environment setup
- [ ] Application runs locally
- [ ] All endpoints tested
- [ ] Docker image built
- [ ] Kubernetes deployment working
- [ ] Prometheus scraping metrics
- [ ] Grafana dashboard configured
- [ ] AWS Digital Twin setup (optional)
- [ ] Threat simulation working
- [ ] Remediation tested

---

**Congratulations! 🎉 You've set up a complete self-healing cloud infrastructure with cyber defense!**


