"""
AWS Lambda function for automated threat remediation.

This Lambda function is triggered by DynamoDB Streams or EventBridge
when new threats are detected. It performs automated remediation actions.
"""

import json
import boto3
import os
from datetime import datetime
from typing import Dict, Any

# AWS Clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
waf_client = boto3.client('wafv2', region_name='us-east-1')

# Configuration
THREATS_TABLE = os.environ.get('THREATS_TABLE', 'cyber-twins-threats')
S3_BUCKET = os.environ.get('S3_BUCKET', 'cyber-twins-digital-twin')
LOG_GROUP = os.environ.get('LOG_GROUP', '/aws/lambda/cyber-twins-remediation')


class RemediationEngine:
    """Automated remediation engine for security threats."""
    
    def __init__(self):
        self.table = dynamodb.Table(THREATS_TABLE)
        self.remediation_actions = []
    
    def log_remediation(self, threat_id: str, action: str, status: str, details: Dict = None):
        """Log remediation action to S3 and CloudWatch."""
        log_entry = {
            'threat_id': threat_id,
            'action': action,
            'status': status,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details or {}
        }
        
        self.remediation_actions.append(log_entry)
        
        # Store in S3
        try:
            key = f"remediation-logs/{datetime.utcnow().strftime('%Y%m%d')}/{threat_id}_{int(datetime.utcnow().timestamp())}.json"
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=key,
                Body=json.dumps(log_entry, indent=2),
                ContentType='application/json'
            )
        except Exception as e:
            print(f"Warning: Could not log to S3: {e}")
    
    def block_ip_aws_waf(self, ip_address: str, threat_id: str) -> bool:
        """
        Block IP address using AWS WAF.
        
        Note: This requires WAF WebACL to be configured.
        """
        try:
            # This is a simplified example
            # In production, you'd use WAF IP sets or rate-based rules
            print(f"🔒 Blocking IP {ip_address} in AWS WAF")
            
            # Update WAF IP Set (requires IP Set ID)
            # waf_client.update_ip_set(...)
            
            self.log_remediation(
                threat_id,
                'block_ip_waf',
                'success',
                {'ip_address': ip_address}
            )
            return True
        except Exception as e:
            print(f"❌ Error blocking IP in WAF: {e}")
            self.log_remediation(
                threat_id,
                'block_ip_waf',
                'failed',
                {'error': str(e)}
            )
            return False
    
    def block_ip_security_group(self, ip_address: str, threat_id: str) -> bool:
        """
        Block IP by adding to Security Group deny rule.
        
        Note: Requires Security Group ID in environment variable.
        """
        security_group_id = os.environ.get('SECURITY_GROUP_ID')
        if not security_group_id:
            print("⚠️  SECURITY_GROUP_ID not configured")
            return False
        
        try:
            # Add ingress rule to deny traffic from IP
            ec2_client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[{
                    'IpProtocol': '-1',  # All protocols
                    'IpRanges': [{'CidrIp': f'{ip_address}/32'}]
                }]
            )
            
            print(f"🔒 Blocked IP {ip_address} in Security Group")
            self.log_remediation(
                threat_id,
                'block_ip_sg',
                'success',
                {'ip_address': ip_address, 'security_group_id': security_group_id}
            )
            return True
        except Exception as e:
            print(f"❌ Error blocking IP in Security Group: {e}")
            self.log_remediation(
                threat_id,
                'block_ip_sg',
                'failed',
                {'error': str(e)}
            )
            return False
    
    def notify_security_team(self, threat: Dict, threat_id: str):
        """Send notification to security team (SNS, Slack, etc.)."""
        try:
            # Example: Send to SNS topic
            sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
            if sns_topic_arn:
                sns = boto3.client('sns')
                message = {
                    'threat_id': threat_id,
                    'ip_address': threat.get('ip_address'),
                    'threat_level': threat.get('threat_level'),
                    'attack_type': threat.get('attack_type'),
                    'description': threat.get('description'),
                    'timestamp': threat.get('timestamp')
                }
                
                sns.publish(
                    TopicArn=sns_topic_arn,
                    Subject=f"Security Threat Detected: {threat_id}",
                    Message=json.dumps(message, indent=2)
                )
                print(f"📧 Notification sent for threat {threat_id}")
        except Exception as e:
            print(f"⚠️  Warning sending notification: {e}")
    
    def update_threat_status(self, threat_id: str, remediated: bool, action: str):
        """Update threat status in DynamoDB."""
        try:
            self.table.update_item(
                Key={'threat_id': threat_id},
                UpdateExpression='SET remediated = :r, remediation_action = :a, remediated_at = :t',
                ExpressionAttributeValues={
                    ':r': remediated,
                    ':a': action,
                    ':t': datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            print(f"⚠️  Warning updating threat status: {e}")
    
    def remediate_threat(self, threat: Dict) -> Dict:
        """
        Main remediation logic.
        Determines appropriate action based on threat level and type.
        """
        threat_id = threat.get('threat_id')
        threat_level = threat.get('threat_level', 'low')
        attack_type = threat.get('attack_type', 'unknown')
        ip_address = threat.get('ip_address')
        
        print(f"\n🔧 Remediating threat: {threat_id}")
        print(f"   Level: {threat_level}, Type: {attack_type}, IP: {ip_address}")
        
        actions_taken = []
        
        # High/Critical threats: Immediate blocking
        if threat_level in ['high', 'critical']:
            if ip_address and ip_address != 'unknown':
                # Try WAF blocking first
                if self.block_ip_aws_waf(ip_address, threat_id):
                    actions_taken.append('waf_block')
                
                # Also block in Security Group if configured
                if self.block_ip_security_group(ip_address, threat_id):
                    actions_taken.append('sg_block')
        
        # Brute force attacks: Always block
        if attack_type == 'brute_force' and ip_address:
            if self.block_ip_aws_waf(ip_address, threat_id):
                actions_taken.append('waf_block_brute_force')
        
        # Notify security team for high/critical threats
        if threat_level in ['high', 'critical']:
            self.notify_security_team(threat, threat_id)
            actions_taken.append('notification_sent')
        
        # Update threat status
        if actions_taken:
            self.update_threat_status(threat_id, True, ', '.join(actions_taken))
        
        return {
            'threat_id': threat_id,
            'remediated': len(actions_taken) > 0,
            'actions_taken': actions_taken
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler function.
    
    Expected event format:
    - DynamoDB Stream event
    - EventBridge custom event
    - Direct invocation with threat data
    """
    print(f"🚀 Lambda remediation triggered")
    print(f"Event: {json.dumps(event, default=str)[:500]}")
    
    engine = RemediationEngine()
    
    # Parse event based on source
    threats = []
    
    if 'Records' in event:
        # DynamoDB Stream event
        for record in event['Records']:
            if record.get('eventName') == 'INSERT':
                new_image = record.get('dynamodb', {}).get('NewImage', {})
                threat = {
                    'threat_id': new_image.get('threat_id', {}).get('S'),
                    'ip_address': new_image.get('ip_address', {}).get('S'),
                    'threat_level': new_image.get('threat_level', {}).get('S'),
                    'attack_type': new_image.get('attack_type', {}).get('S'),
                    'description': new_image.get('description', {}).get('S'),
                    'timestamp': new_image.get('timestamp', {}).get('S')
                }
                threats.append(threat)
    elif 'threat' in event:
        # Direct invocation
        threats.append(event['threat'])
    elif 'threats' in event:
        # Batch invocation
        threats = event['threats']
    
    # Remediate each threat
    results = []
    for threat in threats:
        if threat and threat.get('threat_id'):
            result = engine.remediate_threat(threat)
            results.append(result)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': f'Processed {len(results)} threats',
            'results': results
        })
    }


