#!/bin/bash

# Deployment script for Cyber-Twins to Kubernetes
# This script builds the Docker image and deploys to Minikube

set -e  # Exit on error

IMAGE_NAME="cyber-twins"
IMAGE_TAG="${1:-latest}"
NAMESPACE="${2:-default}"

echo "=========================================="
echo "🚀 Cyber-Twins Deployment Script"
echo "=========================================="
echo "Image: $IMAGE_NAME:$IMAGE_TAG"
echo "Namespace: $NAMESPACE"
echo ""

# Check if Minikube is running
if command -v minikube &> /dev/null; then
    echo "☸️  Checking Minikube status..."
    if minikube status &> /dev/null; then
        echo "   ✅ Minikube is running"
        
        # Use Minikube's Docker daemon
        echo "   🔌 Configuring Docker to use Minikube..."
        eval $(minikube docker-env)
    else
        echo "   ⚠️  Minikube is not running. Starting Minikube..."
        minikube start
        eval $(minikube docker-env)
    fi
else
    echo "   ⚠️  Minikube not found. Using local Docker..."
fi

# Build Docker image
echo ""
echo "🐳 Building Docker image..."
docker build -t $IMAGE_NAME:$IMAGE_TAG .
echo "   ✅ Image built successfully"

# Apply Kubernetes manifests
echo ""
echo "☸️  Deploying to Kubernetes..."

# Create namespace if it doesn't exist
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Apply deployment
echo "   📦 Applying deployment..."
kubectl apply -f k8s/deployment.yaml -n $NAMESPACE

# Apply service
echo "   🌐 Applying service..."
kubectl apply -f k8s/service.yaml -n $NAMESPACE

# Wait for deployment
echo ""
echo "⏳ Waiting for deployment to be ready..."
kubectl rollout status deployment/cyber-twins -n $NAMESPACE --timeout=120s

# Get service URL
echo ""
echo "=========================================="
echo "✅ Deployment complete!"
echo "=========================================="
echo ""
echo "📊 Deployment status:"
kubectl get pods -n $NAMESPACE -l app=cyber-twins
kubectl get services -n $NAMESPACE -l app=cyber-twins

echo ""
echo "🌐 Access the application:"
if command -v minikube &> /dev/null; then
    echo "   minikube service cyber-twins-nodeport -n $NAMESPACE"
    echo "   Or use port-forward: kubectl port-forward svc/cyber-twins-service 8000:80 -n $NAMESPACE"
else
    echo "   kubectl port-forward svc/cyber-twins-service 8000:80 -n $NAMESPACE"
fi

echo ""
echo "📈 To deploy monitoring:"
echo "   kubectl apply -f k8s/prometheus/ -n $NAMESPACE"
echo "   kubectl apply -f k8s/grafana/ -n $NAMESPACE"


