"""
Setup S3 bucket for Digital Twin data storage.

This script creates an S3 bucket to store:
- Threat intelligence snapshots
- Historical attack patterns
- Remediation action logs
- Digital Twin state backups
"""

import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime

# Configuration
BUCKET_NAME = "cyber-twins-digital-twin"
REGION = "us-east-1"  # Change to your preferred region


def create_bucket(s3_client=None, region=None):
    """
    Create S3 bucket for Digital Twin data.
    
    Note: S3 bucket names must be globally unique.
    Consider adding a unique suffix (e.g., your AWS account ID).
    """
    if s3_client is None:
        s3_client = boto3.client('s3', region_name=region)
    
    try:
        if region == 'us-east-1':
            # us-east-1 doesn't need LocationConstraint
            s3_client.create_bucket(Bucket=BUCKET_NAME)
        else:
            s3_client.create_bucket(
                Bucket=BUCKET_NAME,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(f"✅ Bucket {BUCKET_NAME} created successfully!")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'BucketAlreadyExists':
            print(f"⚠️  Bucket {BUCKET_NAME} already exists.")
            return True
        elif error_code == 'BucketAlreadyOwnedByYou':
            print(f"⚠️  Bucket {BUCKET_NAME} already owned by you.")
            return True
        else:
            print(f"❌ Error creating bucket: {e}")
            return False


def configure_bucket(s3_client=None):
    """Configure bucket with security and lifecycle policies."""
    if s3_client is None:
        s3_client = boto3.client('s3', region_name=REGION)
    
    try:
        # Enable versioning
        s3_client.put_bucket_versioning(
            Bucket=BUCKET_NAME,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        print("✅ Versioning enabled")
        
        # Block public access
        s3_client.put_public_access_block(
            Bucket=BUCKET_NAME,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print("✅ Public access blocked")
        
        # Enable encryption
        s3_client.put_bucket_encryption(
            Bucket=BUCKET_NAME,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        print("✅ Encryption enabled")
        
        # Lifecycle policy (optional - archive old data)
        lifecycle_config = {
            'Rules': [
                {
                    'Id': 'ArchiveOldThreats',
                    'Status': 'Enabled',
                    'Prefix': 'threats/',
                    'Transitions': [
                        {
                            'Days': 90,
                            'StorageClass': 'GLACIER'
                        }
                    ]
                }
            ]
        }
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=BUCKET_NAME,
            LifecycleConfiguration=lifecycle_config
        )
        print("✅ Lifecycle policy configured")
        
        return True
    except ClientError as e:
        print(f"⚠️  Warning configuring bucket: {e}")
        return False


def create_folder_structure(s3_client=None):
    """Create initial folder structure in bucket."""
    if s3_client is None:
        s3_client = boto3.client('s3', region_name=REGION)
    
    folders = [
        'threats/',
        'remediation-logs/',
        'snapshots/',
        'patterns/'
    ]
    
    for folder in folders:
        try:
            s3_client.put_object(
                Bucket=BUCKET_NAME,
                Key=folder,
                Body=''
            )
            print(f"✅ Created folder: {folder}")
        except ClientError as e:
            print(f"⚠️  Warning creating folder {folder}: {e}")


if __name__ == "__main__":
    print("🚀 Setting up S3 bucket for Cyber-Twins Digital Twin...")
    print(f"Region: {REGION}")
    print(f"Bucket Name: {BUCKET_NAME}")
    print("\n⚠️  Note: S3 bucket names must be globally unique!")
    print("   If this fails, try adding a unique suffix to BUCKET_NAME\n")
    
    # Create bucket
    s3_client = boto3.client('s3', region_name=REGION)
    if create_bucket(s3_client, REGION):
        # Configure bucket
        configure_bucket(s3_client)
        
        # Create folder structure
        create_folder_structure(s3_client)
        
        print("\n✅ S3 setup complete!")
        print("\nNext steps:")
        print("1. Run sync_threats.py to start storing threat data")
        print("2. Configure IAM permissions for your application")
    else:
        print("\n❌ S3 setup failed. Please check the error above.")


