"""
Threat Simulation Script

This script simulates various attack patterns to test the security system:
- Brute force login attempts
- Suspicious request patterns
- SQL injection attempts
- XSS attempts
- Rate limit testing

Use this to verify your security and remediation systems are working.
"""

import requests
import time
import random
import sys
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed


class ThreatSimulator:
    """Simulate various security threats for testing."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.results = []
    
    def test_brute_force(self, ip_address: str = None, num_attempts: int = 10) -> List[dict]:
        """
        Simulate brute force login attacks.
        
        Args:
            ip_address: IP to use (default: random)
            num_attempts: Number of failed login attempts
        """
        print(f"\n🔴 Simulating brute force attack ({num_attempts} attempts)...")
        
        results = []
        for i in range(num_attempts):
            try:
                response = requests.post(
                    f"{self.base_url}/login",
                    json={
                        "username": f"attacker{i}",
                        "password": "wrongpassword"
                    },
                    headers={"X-Forwarded-For": ip_address or f"192.168.1.{random.randint(100, 200)}"},
                    timeout=5
                )
                results.append({
                    "attempt": i + 1,
                    "status": response.status_code,
                    "blocked": response.status_code == 403
                })
                print(f"  Attempt {i+1}: Status {response.status_code}")
                time.sleep(0.5)  # Small delay between attempts
            except Exception as e:
                print(f"  Attempt {i+1}: Error - {e}")
                results.append({"attempt": i + 1, "error": str(e)})
        
        return results
    
    def test_sql_injection(self, num_attempts: int = 5) -> List[dict]:
        """Simulate SQL injection attacks."""
        print(f"\n🔴 Simulating SQL injection attacks ({num_attempts} attempts)...")
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "1' OR '1'='1' --"
        ]
        
        results = []
        for i, payload in enumerate(sql_payloads[:num_attempts]):
            try:
                # Try in query parameter
                response = requests.get(
                    f"{self.base_url}/login?user={payload}",
                    timeout=5
                )
                results.append({
                    "attempt": i + 1,
                    "payload": payload[:30],
                    "status": response.status_code,
                    "detected": "sql" in response.text.lower() or response.status_code == 403
                })
                print(f"  Attempt {i+1}: Payload '{payload[:30]}...' - Status {response.status_code}")
                time.sleep(0.3)
            except Exception as e:
                print(f"  Attempt {i+1}: Error - {e}")
        
        return results
    
    def test_xss(self, num_attempts: int = 5) -> List[dict]:
        """Simulate XSS attacks."""
        print(f"\n🔴 Simulating XSS attacks ({num_attempts} attempts)...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='evil.com'></iframe>",
            "<body onload=alert('XSS')>"
        ]
        
        results = []
        for i, payload in enumerate(xss_payloads[:num_attempts]):
            try:
                response = requests.get(
                    f"{self.base_url}/?input={payload}",
                    timeout=5
                )
                results.append({
                    "attempt": i + 1,
                    "payload": payload[:30],
                    "status": response.status_code,
                    "detected": response.status_code == 403
                })
                print(f"  Attempt {i+1}: Payload '{payload[:30]}...' - Status {response.status_code}")
                time.sleep(0.3)
            except Exception as e:
                print(f"  Attempt {i+1}: Error - {e}")
        
        return results
    
    def test_rate_limiting(self, requests_per_second: int = 50, duration_seconds: int = 5) -> dict:
        """
        Test rate limiting by sending many requests quickly.
        
        Args:
            requests_per_second: Target requests per second
            duration_seconds: How long to run the test
        """
        print(f"\n🔴 Testing rate limiting ({requests_per_second} req/s for {duration_seconds}s)...")
        
        total_requests = requests_per_second * duration_seconds
        successful = 0
        blocked = 0
        errors = 0
        
        def make_request():
            try:
                response = requests.get(f"{self.base_url}/health", timeout=2)
                if response.status_code == 200:
                    return "success"
                elif response.status_code == 403:
                    return "blocked"
                else:
                    return "error"
            except:
                return "error"
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=requests_per_second) as executor:
            futures = []
            for _ in range(total_requests):
                futures.append(executor.submit(make_request))
                time.sleep(1.0 / requests_per_second)  # Rate limit
            
            for future in as_completed(futures):
                result = future.result()
                if result == "success":
                    successful += 1
                elif result == "blocked":
                    blocked += 1
                else:
                    errors += 1
        
        elapsed = time.time() - start_time
        
        result = {
            "total_requests": total_requests,
            "successful": successful,
            "blocked": blocked,
            "errors": errors,
            "duration_seconds": elapsed,
            "actual_rps": total_requests / elapsed if elapsed > 0 else 0
        }
        
        print(f"  Results: {successful} successful, {blocked} blocked, {errors} errors")
        print(f"  Duration: {elapsed:.2f}s, Actual RPS: {result['actual_rps']:.2f}")
        
        return result
    
    def test_suspicious_ip(self, ip_address: str = "192.168.1.100", num_requests: int = 150) -> dict:
        """Test suspicious IP detection by sending many requests from one IP."""
        print(f"\n🔴 Testing suspicious IP detection ({num_requests} requests from {ip_address})...")
        
        blocked = False
        for i in range(num_requests):
            try:
                response = requests.get(
                    f"{self.base_url}/health",
                    headers={"X-Forwarded-For": ip_address},
                    timeout=2
                )
                if response.status_code == 403:
                    blocked = True
                    print(f"  IP blocked after {i+1} requests")
                    break
                if (i + 1) % 20 == 0:
                    print(f"  Sent {i+1} requests...")
                time.sleep(0.1)
            except Exception as e:
                print(f"  Error on request {i+1}: {e}")
        
        return {
            "ip_address": ip_address,
            "requests_sent": num_requests,
            "blocked": blocked
        }
    
    def check_security_stats(self) -> dict:
        """Check current security statistics."""
        try:
            response = requests.get(f"{self.base_url}/security/stats", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error checking stats: {e}")
        return {}
    
    def run_full_test_suite(self):
        """Run all threat simulation tests."""
        print("=" * 60)
        print("🚨 CYBER-TWINS THREAT SIMULATION SUITE")
        print("=" * 60)
        print(f"Target: {self.base_url}\n")
        
        # Initial stats
        print("📊 Initial Security Stats:")
        initial_stats = self.check_security_stats()
        print(f"  Blocked IPs: {initial_stats.get('blocked_count', 0)}")
        print(f"  Recent Threats: {initial_stats.get('threat_count', 0)}")
        
        # Run tests
        self.test_brute_force(num_attempts=7)
        time.sleep(2)
        
        self.test_sql_injection(num_attempts=5)
        time.sleep(2)
        
        self.test_xss(num_attempts=5)
        time.sleep(2)
        
        self.test_rate_limiting(requests_per_second=30, duration_seconds=3)
        time.sleep(2)
        
        self.test_suspicious_ip(num_requests=120)
        time.sleep(2)
        
        # Final stats
        print("\n📊 Final Security Stats:")
        final_stats = self.check_security_stats()
        print(f"  Blocked IPs: {final_stats.get('blocked_count', 0)}")
        print(f"  Recent Threats: {final_stats.get('threat_count', 0)}")
        
        print("\n" + "=" * 60)
        print("✅ Threat simulation complete!")
        print("=" * 60)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Simulate security threats for testing")
    parser.add_argument("--url", default="http://localhost:8000", help="Application URL")
    parser.add_argument("--test", choices=["brute-force", "sql", "xss", "rate-limit", "suspicious-ip", "all"],
                       default="all", help="Which test to run")
    
    args = parser.parse_args()
    
    simulator = ThreatSimulator(base_url=args.url)
    
    if args.test == "all":
        simulator.run_full_test_suite()
    elif args.test == "brute-force":
        simulator.test_brute_force()
    elif args.test == "sql":
        simulator.test_sql_injection()
    elif args.test == "xss":
        simulator.test_xss()
    elif args.test == "rate-limit":
        simulator.test_rate_limiting()
    elif args.test == "suspicious-ip":
        simulator.test_suspicious_ip()
    
    print("\n💡 Check /security/stats endpoint to see detected threats")


