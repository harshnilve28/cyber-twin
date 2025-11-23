"""
Sync threat events to AWS Digital Twin (DynamoDB + S3).

This script continuously monitors the application for new threats
and syncs them to the Digital Twin for analysis and remediation.
"""

import boto3
import json
import time
from datetime import datetime
from typing import List, Dict
import requests
# Note: Import app.models only if running from project root
# from app.models import ThreatEvent  # Uncomment if needed

# Configuration
DYNAMODB_TABLE_NAME = "cyber-twins-threats"
S3_BUCKET_NAME = "cyber-twins-digital-twin"
REGION = "us-east-1"
APP_URL = "http://localhost:8000"  # Change to your app URL


class DigitalTwinSync:
    """Sync threats to AWS Digital Twin."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb', region_name=REGION)
        self.s3_client = boto3.client('s3', region_name=REGION)
        self.table = self.dynamodb.Table(DYNAMODB_TABLE_NAME)
        self.synced_threat_ids = set()  # Track already synced threats
    
    def fetch_threats_from_app(self) -> List[Dict]:
        """
        Fetch recent threats from the application.
        In production, this would use the app's API or database.
        """
        try:
            response = requests.get(f"{APP_URL}/security/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('recent_threats', [])
        except Exception as e:
            print(f"⚠️  Error fetching threats from app: {e}")
        return []
    
    def sync_to_dynamodb(self, threat: Dict) -> bool:
        """
        Sync a threat event to DynamoDB.
        
        Args:
            threat: Threat event dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert timestamp to ISO string if needed
            timestamp = threat.get('timestamp')
            if isinstance(timestamp, str):
                timestamp_str = timestamp
            else:
                timestamp_str = datetime.utcnow().isoformat()
            
            item = {
                'threat_id': threat['threat_id'],
                'timestamp': timestamp_str,
                'ip_address': threat['ip_address'],
                'threat_level': threat['threat_level'],
                'attack_type': threat['attack_type'],
                'description': threat['description'],
                'remediated': threat.get('remediated', False),
                'remediation_action': threat.get('remediation_action'),
                'metadata': json.dumps(threat.get('metadata', {})),
                'synced_at': datetime.utcnow().isoformat()
            }
            
            self.table.put_item(Item=item)
            print(f"✅ Synced threat {threat['threat_id']} to DynamoDB")
            return True
        except Exception as e:
            print(f"❌ Error syncing to DynamoDB: {e}")
            return False
    
    def sync_to_s3(self, threat: Dict) -> bool:
        """
        Store threat snapshot in S3 for historical analysis.
        
        Args:
            threat: Threat event dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            threat_id = threat['threat_id']
            timestamp = datetime.utcnow().strftime('%Y%m%d')
            
            # Store as JSON in S3
            key = f"threats/{timestamp}/{threat_id}.json"
            body = json.dumps(threat, indent=2, default=str)
            
            self.s3_client.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=key,
                Body=body,
                ContentType='application/json',
                Metadata={
                    'threat_id': threat_id,
                    'ip_address': threat['ip_address'],
                    'threat_level': threat['threat_level'],
                    'attack_type': threat['attack_type']
                }
            )
            print(f"✅ Stored threat {threat_id} snapshot in S3")
            return True
        except Exception as e:
            print(f"❌ Error syncing to S3: {e}")
            return False
    
    def create_threat_pattern(self, threats: List[Dict]) -> Dict:
        """
        Analyze threats to identify patterns.
        Store patterns in S3 for future reference.
        """
        if not threats:
            return {}
        
        # Simple pattern analysis
        ip_counts = {}
        attack_type_counts = {}
        
        for threat in threats:
            ip = threat.get('ip_address', 'unknown')
            attack_type = threat.get('attack_type', 'unknown')
            
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        
        pattern = {
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'total_threats': len(threats),
            'unique_ips': len(ip_counts),
            'top_ips': dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'attack_type_distribution': attack_type_counts,
            'time_window': {
                'start': threats[-1].get('timestamp') if threats else None,
                'end': threats[0].get('timestamp') if threats else None
            }
        }
        
        # Store pattern in S3
        try:
            pattern_key = f"patterns/{datetime.utcnow().strftime('%Y%m%d')}/pattern_{int(time.time())}.json"
            self.s3_client.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=pattern_key,
                Body=json.dumps(pattern, indent=2),
                ContentType='application/json'
            )
            print(f"✅ Stored threat pattern analysis")
        except Exception as e:
            print(f"⚠️  Warning storing pattern: {e}")
        
        return pattern
    
    def sync_cycle(self):
        """Perform one sync cycle."""
        print(f"\n🔄 Sync cycle at {datetime.utcnow().isoformat()}")
        
        # Fetch threats from application
        threats = self.fetch_threats_from_app()
        
        if not threats:
            print("ℹ️  No new threats to sync")
            return
        
        # Filter new threats
        new_threats = [
            t for t in threats
            if t['threat_id'] not in self.synced_threat_ids
        ]
        
        if not new_threats:
            print("ℹ️  No new threats (all already synced)")
            return
        
        print(f"📊 Found {len(new_threats)} new threats to sync")
        
        # Sync each threat
        for threat in new_threats:
            threat_id = threat['threat_id']
            
            # Sync to DynamoDB
            if self.sync_to_dynamodb(threat):
                self.synced_threat_ids.add(threat_id)
            
            # Sync to S3
            self.sync_to_s3(threat)
        
        # Create pattern analysis if we have multiple threats
        if len(new_threats) >= 5:
            self.create_threat_pattern(new_threats)
    
    def run_continuous(self, interval_seconds: int = 60):
        """
        Run continuous sync loop.
        
        Args:
            interval_seconds: How often to sync (default: 60 seconds)
        """
        print("🚀 Starting continuous Digital Twin sync...")
        print(f"⏱️  Sync interval: {interval_seconds} seconds")
        print(f"📊 DynamoDB Table: {DYNAMODB_TABLE_NAME}")
        print(f"📦 S3 Bucket: {S3_BUCKET_NAME}\n")
        
        try:
            while True:
                self.sync_cycle()
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n\n🛑 Sync stopped by user")


if __name__ == "__main__":
    import sys
    
    # Check if running in continuous mode
    continuous = '--continuous' in sys.argv or '-c' in sys.argv
    
    sync = DigitalTwinSync()
    
    if continuous:
        interval = 60
        if '--interval' in sys.argv:
            idx = sys.argv.index('--interval')
            if idx + 1 < len(sys.argv):
                interval = int(sys.argv[idx + 1])
        sync.run_continuous(interval_seconds=interval)
    else:
        # Single sync
        sync.sync_cycle()
        print("\n✅ Sync complete!")
        print("💡 Tip: Use --continuous flag to run continuously")

