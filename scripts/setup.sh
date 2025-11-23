#!/bin/bash

# Setup script for Cyber-Twins project
# This script helps set up the development environment

set -e  # Exit on error

echo "=========================================="
echo "🚀 Cyber-Twins Setup Script"
echo "=========================================="
echo ""

# Check Python version
echo "📋 Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Python version: $python_version"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.9+"
    exit 1
fi

# Create virtual environment
echo ""
echo "📦 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "   ✅ Virtual environment created"
else
    echo "   ℹ️  Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "🔌 Activating virtual environment..."
source venv/bin/activate || source venv/Scripts/activate  # Windows compatibility

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "📥 Installing dependencies..."
pip install -r requirements.txt
echo "   ✅ Dependencies installed"

# Create .env file if it doesn't exist
echo ""
echo "⚙️  Setting up environment variables..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "   ✅ Created .env from .env.example"
        echo "   ⚠️  Please edit .env with your configuration"
    else
        echo "   ⚠️  .env.example not found, skipping"
    fi
else
    echo "   ℹ️  .env file already exists"
fi

# Check Docker
echo ""
echo "🐳 Checking Docker..."
if command -v docker &> /dev/null; then
    docker_version=$(docker --version)
    echo "   ✅ Docker installed: $docker_version"
else
    echo "   ⚠️  Docker not found (optional for containerization)"
fi

# Check Kubernetes
echo ""
echo "☸️  Checking Kubernetes..."
if command -v kubectl &> /dev/null; then
    kubectl_version=$(kubectl version --client --short 2>&1)
    echo "   ✅ kubectl installed: $kubectl_version"
    
    if command -v minikube &> /dev/null; then
        echo "   ✅ Minikube found"
    else
        echo "   ⚠️  Minikube not found (optional for local K8s)"
    fi
else
    echo "   ⚠️  kubectl not found (optional for Kubernetes)"
fi

# Check AWS CLI
echo ""
echo "☁️  Checking AWS CLI..."
if command -v aws &> /dev/null; then
    aws_version=$(aws --version 2>&1)
    echo "   ✅ AWS CLI installed: $aws_version"
    echo "   ⚠️  Make sure to run 'aws configure' if not already done"
else
    echo "   ⚠️  AWS CLI not found (optional for AWS features)"
fi

echo ""
echo "=========================================="
echo "✅ Setup complete!"
echo "=========================================="
echo ""
echo "📚 Next steps:"
echo "   1. Activate virtual environment: source venv/bin/activate"
echo "   2. Edit .env file with your configuration"
echo "   3. Run the application: python -m app.main"
echo "   4. Test endpoints: bash scripts/test_endpoints.sh"
echo "   5. Run threat simulation: python scripts/threat_simulator.py"
echo ""


