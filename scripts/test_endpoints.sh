#!/bin/bash

# Test script for Cyber-Twins endpoints
# Tests all main endpoints and displays results

BASE_URL="${1:-http://localhost:8000}"

echo "=========================================="
echo "🧪 Testing Cyber-Twins Endpoints"
echo "=========================================="
echo "Base URL: $BASE_URL"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo -n "Testing $description... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo -e "${GREEN}✓${NC} (HTTP $http_code)"
        echo "  Response: $(echo "$body" | head -c 100)..."
    elif [ "$http_code" -eq 401 ] || [ "$http_code" -eq 403 ]; then
        echo -e "${YELLOW}⚠${NC} (HTTP $http_code - Expected for security)"
    else
        echo -e "${RED}✗${NC} (HTTP $http_code)"
        echo "  Error: $body"
    fi
    echo ""
}

# Test root endpoint
test_endpoint "GET" "/" "Root endpoint"

# Test health endpoint
test_endpoint "GET" "/health" "" "Health check"

# Test login with wrong credentials (should fail)
test_endpoint "POST" "/login" '{"username":"test","password":"wrong"}' "Login (wrong credentials)"

# Test login with correct credentials (demo)
test_endpoint "POST" "/login" '{"username":"admin","password":"password123"}' "Login (correct credentials)"

# Test metrics endpoint
test_endpoint "GET" "/metrics" "" "Metrics endpoint"

# Test security stats
test_endpoint "GET" "/security/stats" "" "Security statistics"

# Test Prometheus metrics
test_endpoint "GET" "/metrics" "" "Prometheus metrics"

echo "=========================================="
echo "✅ Endpoint testing complete!"
echo "=========================================="
echo ""
echo "💡 Tips:"
echo "  - Check /security/stats for threat information"
echo "  - View /metrics for Prometheus metrics"
echo "  - Run threat_simulator.py to test security features"


