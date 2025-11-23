"""
Setup DynamoDB table for Digital Twin threat intelligence storage.

This script creates a DynamoDB table to store threat events,
allowing the Digital Twin to maintain a real-time view of security threats.
"""

import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime

# Configuration
TABLE_NAME = "cyber-twins-threats"
REGION = "us-east-1"  # Change to your preferred region


def create_threats_table(dynamodb=None):
    """
    Create DynamoDB table for storing threat events.
    
    Table Structure:
    - threat_id (Partition Key): Unique identifier for each threat
    - timestamp (Sort Key): When the threat was detected
    - GSI: ip_address-index for querying by IP
    """
    if dynamodb is None:
        dynamodb = boto3.resource('dynamodb', region_name=REGION)
    
    table_schema = {
        'TableName': TABLE_NAME,
        'KeySchema': [
            {
                'AttributeName': 'threat_id',
                'KeyType': 'HASH'  # Partition key
            },
            {
                'AttributeName': 'timestamp',
                'KeyType': 'RANGE'  # Sort key
            }
        ],
        'AttributeDefinitions': [
            {
                'AttributeName': 'threat_id',
                'AttributeType': 'S'  # String
            },
            {
                'AttributeName': 'timestamp',
                'AttributeType': 'S'  # String (ISO format)
            },
            {
                'AttributeName': 'ip_address',
                'AttributeType': 'S'  # For GSI
            }
        ],
        'BillingMode': 'PAY_PER_REQUEST',  # On-demand pricing
        'GlobalSecondaryIndexes': [
            {
                'IndexName': 'ip_address-index',
                'KeySchema': [
                    {
                        'AttributeName': 'ip_address',
                        'KeyType': 'HASH'
                    },
                    {
                        'AttributeName': 'timestamp',
                        'KeyType': 'RANGE'
                    }
                ],
                'Projection': {
                    'ProjectionType': 'ALL'
                }
            }
        ],
        'Tags': [
            {
                'Key': 'Project',
                'Value': 'Cyber-Twins'
            },
            {
                'Key': 'Purpose',
                'Value': 'Digital-Twin-Threat-Intelligence'
            }
        ]
    }
    
    try:
        table = dynamodb.create_table(**table_schema)
        print(f"Creating table {TABLE_NAME}...")
        table.wait_until_exists()
        print(f"✅ Table {TABLE_NAME} created successfully!")
        return table
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"⚠️  Table {TABLE_NAME} already exists.")
            return dynamodb.Table(TABLE_NAME)
        else:
            print(f"❌ Error creating table: {e}")
            raise


def verify_table(table):
    """Verify table was created correctly."""
    print(f"\n📊 Table Status: {table.table_status}")
    print(f"📊 Item Count: {table.item_count}")
    print(f"📊 Table ARN: {table.table_arn}")


if __name__ == "__main__":
    print("🚀 Setting up DynamoDB table for Cyber-Twins Digital Twin...")
    print(f"Region: {REGION}")
    print(f"Table Name: {TABLE_NAME}\n")
    
    # Create table
    table = create_threats_table()
    
    # Verify
    verify_table(table)
    
    print("\n✅ DynamoDB setup complete!")
    print("\nNext steps:")
    print("1. Run sync_threats.py to start syncing threats")
    print("2. Configure IAM permissions for your application")


