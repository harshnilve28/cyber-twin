# 🏗️ System Architecture

## Overview

The Cyber-Twins system is a **self-healing cloud infrastructure** with **Digital Twin cyber defense**. It automatically detects, analyzes, and remediates security threats in real-time.

---

## 🎯 Core Components

### 1. **FastAPI Microservice** (`app/`)
The main application that:
- Exposes REST API endpoints
- Tracks security events (failed logins, suspicious IPs)
- Detects attack patterns (SQL injection, XSS, brute force)
- Exposes Prometheus metrics
- Blocks suspicious IPs automatically

**Key Files:**
- `app/main.py` - FastAPI application and endpoints
- `app/security.py` - Security logic and threat detection
- `app/metrics.py` - Prometheus metrics
- `app/models.py` - Data models

### 2. **Docker Containerization**
- Multi-stage Dockerfile for optimized image size
- Non-root user for security
- Health checks built-in
- Ready for Kubernetes deployment

### 3. **Kubernetes Orchestration** (`k8s/`)
- Deployment with 3 replicas for high availability
- Service for load balancing
- Ingress for external access
- Resource limits and security contexts

### 4. **Monitoring Stack**
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- Custom metrics for security events

### 5. **AWS Digital Twin** (`aws/digital-twin/`)
- **DynamoDB**: Real-time threat intelligence storage
- **S3**: Historical threat data and patterns
- Continuous sync from application to cloud

### 6. **Automated Remediation** (`aws/remediation/`)
- **AWS Lambda**: Cloud-level remediation (WAF, Security Groups)
- **K8s Controller**: Kubernetes-level remediation (NetworkPolicies)
- Automatic IP blocking and threat response

---

## 🔄 Data Flow

```
┌─────────────────┐
│   Client/User   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  FastAPI App    │◄─── Security Middleware
│  (Port 8000)    │     - IP Tracking
└────────┬────────┘     - Attack Detection
         │              - IP Blocking
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐  ┌──────────────┐
│Prometheus│  │Security Manager│
│Metrics  │  │(In-Memory)     │
└────────┘  └────────┬───────┘
                     │
                     ▼
            ┌─────────────────┐
            │ Threat Detected │
            └────────┬────────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
        ▼            ▼            ▼
┌─────────────┐ ┌──────────┐ ┌──────────────┐
│  DynamoDB   │ │    S3    │ │ K8s Controller│
│(Digital Twin)│ │(Storage) │ │(Remediation) │
└─────────────┘ └──────────┘ └──────────────┘
        │
        ▼
┌─────────────┐
│AWS Lambda   │
│(Remediation)│
└─────────────┘
```

---

## 🛡️ Security Architecture

### Threat Detection Layers

1. **Request Level**
   - IP tracking and rate limiting
   - Attack pattern detection (SQL, XSS)
   - Suspicious behavior analysis

2. **Application Level**
   - Failed login tracking
   - Session management
   - Authentication validation

3. **Infrastructure Level**
   - Kubernetes NetworkPolicies
   - AWS WAF rules
   - Security Group rules

### Remediation Flow

```
Threat Detected
    │
    ▼
Analyze Threat Level
    │
    ├─ HIGH/CRITICAL ──► Immediate Block
    │                      - K8s NetworkPolicy
    │                      - AWS WAF
    │                      - Security Group
    │
    ├─ MEDIUM ──────────► Monitor & Log
    │                      - Track behavior
    │                      - Update Digital Twin
    │
    └─ LOW ─────────────► Log Only
                           - Record in Digital Twin
```

---

## 📊 Monitoring Architecture

```
Application (Port 8000)
    │
    │ Exposes /metrics
    ▼
Prometheus (Port 9090)
    │
    │ Scrapes every 15s
    │ Stores metrics
    ▼
Grafana (Port 3000)
    │
    │ Queries Prometheus
    │ Visualizes dashboards
    ▼
Alerts & Notifications
```

**Key Metrics:**
- `http_requests_total` - Request count by endpoint
- `failed_logins_total` - Failed authentication attempts
- `blocked_ips_current` - Currently blocked IPs
- `threats_detected_total` - Threats by type and level
- `remediation_actions_total` - Remediation actions taken

---

## ☁️ AWS Integration

### Digital Twin Components

1. **DynamoDB Table** (`cyber-twins-threats`)
   - Real-time threat storage
   - Queryable by threat_id, IP, timestamp
   - GSI for IP-based queries

2. **S3 Bucket** (`cyber-twins-digital-twin`)
   - `/threats/` - Historical threat snapshots
   - `/remediation-logs/` - Remediation action logs
   - `/patterns/` - Threat pattern analysis
   - `/snapshots/` - System state snapshots

3. **Lambda Function**
   - Triggered by DynamoDB Streams
   - Performs automated remediation
   - Logs actions to S3

---

## 🔧 Kubernetes Architecture

```
┌─────────────────────────────────────┐
│         Kubernetes Cluster          │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   Cyber-Twins Deployment     │  │
│  │   (3 Replicas)               │  │
│  │   - cyber-twins-pod-1        │  │
│  │   - cyber-twins-pod-2        │  │
│  │   - cyber-twins-pod-3        │  │
│  └───────────┬──────────────────┘  │
│              │                      │
│  ┌───────────▼──────────────────┐  │
│  │   Service (LoadBalancer)      │  │
│  │   Port: 80 → 8000            │  │
│  └───────────┬──────────────────┘  │
│              │                      │
│  ┌───────────▼──────────────────┐  │
│  │   Ingress (nginx)             │  │
│  │   Rate Limiting               │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   Prometheus                 │  │
│  │   - Scrapes app metrics      │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   Grafana                    │  │
│  │   - Visualizes metrics        │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   K8s Remediation Controller │  │
│  │   - Watches threats           │  │
│  │   - Creates NetworkPolicies   │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

---

## 🔄 Self-Healing Flow

```
1. Threat Detected
   │
   ▼
2. Logged to Security Manager
   │
   ▼
3. Synced to Digital Twin (DynamoDB + S3)
   │
   ▼
4. Remediation Engine Evaluates
   │
   ├─ High/Critical Threat
   │   │
   │   ├─► K8s Controller
   │   │     - Create NetworkPolicy
   │   │     - Block IP at K8s level
   │   │
   │   └─► AWS Lambda
   │         - Update WAF
   │         - Modify Security Group
   │         - Send Notification
   │
   └─ Medium/Low Threat
       │
       └─► Monitor & Log
           - Track in Digital Twin
           - Update threat intelligence
           - Pattern analysis
```

---

## 📈 Scalability

### Horizontal Scaling
- Kubernetes deployment with 3+ replicas
- Load balanced via Service
- Stateless application design

### Vertical Scaling
- Resource limits in deployment
- Auto-scaling based on metrics (HPA)

### Data Scaling
- DynamoDB on-demand pricing
- S3 for long-term storage
- Prometheus retention policies

---

## 🔐 Security Best Practices

1. **Application Security**
   - Non-root container user
   - Read-only filesystem where possible
   - Security context in K8s

2. **Network Security**
   - NetworkPolicies for pod isolation
   - Ingress rate limiting
   - IP blocking at multiple layers

3. **Data Security**
   - S3 encryption enabled
   - DynamoDB encryption at rest
   - Secrets management (use K8s secrets in production)

4. **Monitoring Security**
   - Prometheus RBAC
   - Grafana authentication
   - Audit logging

---

## 🚀 Production Considerations

1. **Replace in-memory storage** with Redis or database
2. **Use proper authentication** (JWT, OAuth2)
3. **Enable TLS/SSL** for all endpoints
4. **Set up CI/CD pipeline** for deployments
5. **Configure proper secrets management**
6. **Set up alerting** in Prometheus/Grafana
7. **Use managed services** (RDS, ElastiCache)
8. **Implement backup strategies**
9. **Set up disaster recovery**
10. **Enable audit logging**

---

## 📚 Technology Stack

- **Language**: Python 3.11
- **Framework**: FastAPI
- **Container**: Docker
- **Orchestration**: Kubernetes
- **Monitoring**: Prometheus + Grafana
- **Cloud**: AWS (DynamoDB, S3, Lambda)
- **Security**: NetworkPolicies, WAF, Security Groups

---

This architecture provides a **resilient, scalable, and self-healing** security system that adapts to threats in real-time! 🛡️


