"""
Configuration management for the application.
Loads settings from environment variables with sensible defaults.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "Cyber-Twins"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Security
    secret_key: str = "change-this-secret-key-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Failed Login Protection
    max_failed_logins: int = 5
    login_block_duration_seconds: int = 3600  # 1 hour
    
    # Suspicious IP Detection
    suspicious_requests_threshold: int = 100
    suspicious_time_window_seconds: int = 300  # 5 minutes
    
    # AWS
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    # DynamoDB
    dynamodb_table_name: str = "cyber-twins-threats"
    dynamodb_region: str = "us-east-1"
    
    # S3
    s3_bucket_name: str = "cyber-twins-digital-twin"
    s3_region: str = "us-east-1"
    
    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    
    # Prometheus
    prometheus_enabled: bool = True
    metrics_path: str = "/metrics"
    
    # Kubernetes
    k8s_namespace: str = "default"
    k8s_cluster_name: str = "minikube"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()


