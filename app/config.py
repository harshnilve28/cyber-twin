from pydantic import BaseSettings


class Settings(BaseSettings):
    # security thresholds
    max_failed_logins: int = 5
    login_block_duration_seconds: int = 60

    suspicious_requests_threshold: int = 30
    suspicious_time_window_seconds: int = 10

    # AWS (loaded from .env automatically)
    AWS_REGION: str = "ap-south-1"
    DYNAMODB_TABLE_NAME: str = "CyberTwinThreats"
    S3_BUCKET_NAME: str = "nilve-cyber-twin-logs"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()
