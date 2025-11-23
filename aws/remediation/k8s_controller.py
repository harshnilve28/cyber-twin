"""
Kubernetes Controller for automated remediation.

This controller watches for threats and performs K8s-level remediation:
- Creates NetworkPolicies to block IPs
- Scales down affected pods
- Creates/updates ConfigMaps for threat intelligence
"""

import os
import time
import json
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from typing import Dict, List, Optional

# Kubernetes API
try:
    # Try in-cluster config first (when running in K8s)
    config.load_incluster_config()
except:
    # Fallback to kubeconfig (for local development)
    try:
        config.load_kube_config()
    except:
        print("⚠️  Could not load Kubernetes config")

v1 = client.CoreV1Api()
networking_v1 = client.NetworkingV1Api()
apps_v1 = client.AppsV1Api()


class K8sRemediationController:
    """Kubernetes controller for threat remediation."""
    
    def __init__(self, namespace: str = "default"):
        self.namespace = namespace
        self.blocked_ips = set()
    
    def create_network_policy(self, ip_address: str, threat_id: str) -> bool:
        """
        Create NetworkPolicy to block IP address.
        
        Args:
            ip_address: IP address to block
            threat_id: Associated threat ID
            
        Returns:
            True if successful
        """
        policy_name = f"block-ip-{ip_address.replace('.', '-')}"
        
        # Check if policy already exists
        try:
            existing = networking_v1.read_namespaced_network_policy(
                name=policy_name,
                namespace=self.namespace
            )
            print(f"ℹ️  NetworkPolicy {policy_name} already exists")
            return True
        except ApiException as e:
            if e.status != 404:
                print(f"❌ Error checking NetworkPolicy: {e}")
                return False
        
        # Create NetworkPolicy
        try:
            policy = client.V1NetworkPolicy(
                metadata=client.V1ObjectMeta(
                    name=policy_name,
                    namespace=self.namespace,
                    labels={
                        'app': 'cyber-twins',
                        'remediation': 'ip-block',
                        'threat-id': threat_id
                    }
                ),
                spec=client.V1NetworkPolicySpec(
                    pod_selector={},  # Apply to all pods
                    policy_types=['Ingress'],
                    ingress=[
                        client.V1NetworkPolicyIngressRule(
                            _from=[
                                client.V1NetworkPolicyPeer(
                                    ip_block=client.V1IPBlock(
                                        cidr=f"{ip_address}/32",
                                        except_=[]  # Block this specific IP
                                    )
                                )
                            ]
                        )
                    ]
                )
            )
            
            networking_v1.create_namespaced_network_policy(
                namespace=self.namespace,
                body=policy
            )
            
            print(f"✅ Created NetworkPolicy to block {ip_address}")
            self.blocked_ips.add(ip_address)
            return True
            
        except ApiException as e:
            print(f"❌ Error creating NetworkPolicy: {e}")
            return False
    
    def delete_network_policy(self, ip_address: str):
        """Delete NetworkPolicy for IP (unblock)."""
        policy_name = f"block-ip-{ip_address.replace('.', '-')}"
        
        try:
            networking_v1.delete_namespaced_network_policy(
                name=policy_name,
                namespace=self.namespace
            )
            print(f"✅ Deleted NetworkPolicy for {ip_address}")
            self.blocked_ips.discard(ip_address)
            return True
        except ApiException as e:
            if e.status == 404:
                print(f"ℹ️  NetworkPolicy {policy_name} not found")
                return True
            print(f"❌ Error deleting NetworkPolicy: {e}")
            return False
    
    def update_threat_intelligence_configmap(self, threats: List[Dict]):
        """
        Update ConfigMap with current threat intelligence.
        This allows pods to access threat data.
        """
        configmap_name = "cyber-twins-threat-intel"
        
        threat_data = {
            'blocked_ips': list(self.blocked_ips),
            'threats': threats[-100:],  # Last 100 threats
            'updated_at': time.time()
        }
        
        try:
            # Try to get existing ConfigMap
            try:
                existing = v1.read_namespaced_config_map(
                    name=configmap_name,
                    namespace=self.namespace
                )
                existing.data['threat-intel.json'] = json.dumps(threat_data, indent=2)
                v1.replace_namespaced_config_map(
                    name=configmap_name,
                    namespace=self.namespace,
                    body=existing
                )
            except ApiException as e:
                if e.status == 404:
                    # Create new ConfigMap
                    configmap = client.V1ConfigMap(
                        metadata=client.V1ObjectMeta(
                            name=configmap_name,
                            namespace=self.namespace
                        ),
                        data={
                            'threat-intel.json': json.dumps(threat_data, indent=2)
                        }
                    )
                    v1.create_namespaced_config_map(
                        namespace=self.namespace,
                        body=configmap
                    )
                else:
                    raise
            
            print(f"✅ Updated threat intelligence ConfigMap")
            return True
            
        except ApiException as e:
            print(f"❌ Error updating ConfigMap: {e}")
            return False
    
    def scale_deployment(self, deployment_name: str, replicas: int):
        """
        Scale a deployment (useful for isolating affected services).
        
        Args:
            deployment_name: Name of deployment
            replicas: Target number of replicas
        """
        try:
            deployment = apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace
            )
            
            deployment.spec.replicas = replicas
            apps_v1.replace_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace,
                body=deployment
            )
            
            print(f"✅ Scaled {deployment_name} to {replicas} replicas")
            return True
            
        except ApiException as e:
            print(f"❌ Error scaling deployment: {e}")
            return False
    
    def remediate_threat(self, threat: Dict) -> bool:
        """
        Perform K8s-level remediation for a threat.
        
        Args:
            threat: Threat event dictionary
            
        Returns:
            True if remediation successful
        """
        threat_id = threat.get('threat_id')
        threat_level = threat.get('threat_level', 'low')
        ip_address = threat.get('ip_address')
        
        print(f"\n🔧 K8s Remediation for threat: {threat_id}")
        
        success = True
        
        # Block IP if threat is high/critical
        if threat_level in ['high', 'critical'] and ip_address and ip_address != 'unknown':
            if not self.create_network_policy(ip_address, threat_id):
                success = False
        
        return success
    
    def watch_and_remediate(self, app_url: str = "http://cyber-twins-service:80"):
        """
        Watch for new threats and automatically remediate.
        This runs as a continuous loop.
        
        Args:
            app_url: URL of the application to monitor
        """
        print("🚀 Starting K8s remediation controller...")
        print(f"📊 Monitoring namespace: {self.namespace}")
        print(f"🌐 App URL: {app_url}\n")
        
        last_sync = 0
        
        try:
            while True:
                # Fetch threats from application
                # In production, this would use Kubernetes API or ConfigMap
                import requests
                try:
                    response = requests.get(f"{app_url}/security/stats", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        threats = data.get('recent_threats', [])
                        
                        # Process new threats
                        for threat in threats:
                            threat_id = threat.get('threat_id')
                            if threat_id and not threat.get('remediated'):
                                self.remediate_threat(threat)
                        
                        # Update threat intelligence ConfigMap
                        if threats:
                            self.update_threat_intelligence_configmap(threats)
                    
                except Exception as e:
                    print(f"⚠️  Error fetching threats: {e}")
                
                time.sleep(30)  # Check every 30 seconds
                
        except KeyboardInterrupt:
            print("\n\n🛑 Controller stopped by user")


if __name__ == "__main__":
    import sys
    
    namespace = os.environ.get('K8S_NAMESPACE', 'default')
    app_url = os.environ.get('APP_URL', 'http://cyber-twins-service:80')
    
    controller = K8sRemediationController(namespace=namespace)
    controller.watch_and_remediate(app_url=app_url)


