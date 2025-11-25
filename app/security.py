"""
Security module for authentication, IP tracking, threat detection,
and Digital Twin sync (DynamoDB + S3).
"""

import boto3
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from collections import defaultdict
import hashlib
import re

from app.config import settings
from app.models import IPStats, ThreatLevel, AttackType, ThreatEvent


class SecurityManager:
    """
    Handles:
    - Failed login tracking
    - Suspicious behavior
    - SQLi / XSS detection
    - AWS Digital Twin sync (DDB + S3)
    """

    def __init__(self):

        # In-memory tracking
        self.failed_logins: Dict[str, list] = defaultdict(list)
        self.ip_stats: Dict[str, IPStats] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.request_counts: Dict[str, list] = defaultdict(list)
        self.threat_events: list = []

        # Do NOT initialize AWS here (Fix)
        self.dynamodb = None
        self.table = None
        self.s3 = None


    # ------------------------------------------------------------
    # LAZY AWS INITIALIZATION (SAFE)
    # ------------------------------------------------------------
    def init_aws(self):
        """Initialize AWS clients only once (first use)."""

        if self.dynamodb is None:
            self.dynamodb = boto3.resource(
                "dynamodb",
                region_name=settings.AWS_REGION
            )
            self.table = self.dynamodb.Table(settings.DYNAMODB_TABLE_NAME)

        if self.s3 is None:
            self.s3 = boto3.client(
                "s3",
                region_name=settings.AWS_REGION
            )


    # ------------------------------------------------------------
    # DIGITAL TWIN SYNC
    # ------------------------------------------------------------
    def sync_to_digital_twin(self, threat_event: ThreatEvent):
        """Upload event to DynamoDB + S3."""

        # SAFE: Initialize AWS now (not at import time)
        self.init_aws()

        event_dict = {
            "threat_id": threat_event.threat_id,
            "ip_address": threat_event.ip_address,
            "timestamp": datetime.utcnow().isoformat(),
            "threat_level": threat_event.threat_level.value,
            "attack_type": threat_event.attack_type.value,
            "description": threat_event.description,
            "metadata": json.dumps(threat_event.metadata),
        }

        # DynamoDB write
        self.table.put_item(Item=event_dict)

        # S3 log upload
        key = f"threats/{threat_event.ip_address}-{int(time.time())}.json"
        self.s3.put_object(
            Bucket=settings.S3_BUCKET_NAME,
            Key=key,
            Body=json.dumps(event_dict).encode("utf-8")
        )

        return event_dict


    # ------------------------------------------------------------
    # LOGIN FAILURE LOGIC
    # ------------------------------------------------------------
    def check_ip_blocked(self, ip_address: str) -> bool:
        if ip_address not in self.blocked_ips:
            return False

        if datetime.utcnow() < self.blocked_ips[ip_address]:
            return True

        del self.blocked_ips[ip_address]
        return False


    def record_failed_login(self, ip_address: str, username: str):
        now = datetime.utcnow()
        self.failed_logins[ip_address].append(now)

        cutoff = now - timedelta(seconds=settings.login_block_duration_seconds)
        self.failed_logins[ip_address] = [
            ts for ts in self.failed_logins[ip_address] if ts > cutoff
        ]

        count = len(self.failed_logins[ip_address])
        should_block = count >= settings.max_failed_logins

        if ip_address not in self.ip_stats:
            self.ip_stats[ip_address] = IPStats(ip_address=ip_address)

        self.ip_stats[ip_address].failed_logins = count
        self.ip_stats[ip_address].last_seen = now

        if should_block:
            block_until = now + timedelta(seconds=settings.login_block_duration_seconds)
            self.blocked_ips[ip_address] = block_until
            self.ip_stats[ip_address].is_blocked = True

            threat = ThreatEvent(
                threat_id=f"threat_{int(time.time())}",
                ip_address=ip_address,
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.BRUTE_FORCE,
                description=f"{count} failed login attempts",
                metadata={"username": username}
            )

            self.threat_events.append(threat)
            self.sync_to_digital_twin(threat)
            return True, threat

        return False, None


    # ------------------------------------------------------------
    # SUSPICIOUS REQUESTS
    # ------------------------------------------------------------
    def record_request(self, ip_address: str):
        now = datetime.utcnow()
        self.request_counts[ip_address].append(now)

        cutoff = now - timedelta(seconds=settings.suspicious_time_window_seconds)
        self.request_counts[ip_address] = [
            ts for ts in self.request_counts[ip_address] if ts > cutoff
        ]

        count = len(self.request_counts[ip_address])

        if count >= settings.suspicious_requests_threshold:
            threat = ThreatEvent(
                threat_id=f"threat_{int(time.time())}",
                ip_address=ip_address,
                threat_level=ThreatLevel.MEDIUM,
                attack_type=AttackType.SUSPICIOUS_IP,
                description="High request frequency detected",
                metadata={"count": count}
            )

            self.threat_events.append(threat)
            self.sync_to_digital_twin(threat)
            return threat

        return None


    # ------------------------------------------------------------
    # SQLi / XSS DETECTION
    # ------------------------------------------------------------
    def detect_attack_pattern(self, path, query, body=None):
        combined = f"{path} {query} {body or ''}"

        if "UNION SELECT" in combined.upper():
            threat = ThreatEvent(
                threat_id=f"threat_{int(time.time())}",
                ip_address="unknown",
                threat_level=ThreatLevel.HIGH,
                attack_type=AttackType.SQL_INJECTION,
                description="SQLi detected",
                metadata={"input": combined[:200]}
            )
            self.threat_events.append(threat)
            self.sync_to_digital_twin(threat)
            return threat

        if "<script" in combined.lower():
            threat = ThreatEvent(
                threat_id=f"threat_{int(time.time())}",
                ip_address="unknown",
                threat_level=ThreatLevel.MEDIUM,
                attack_type=AttackType.XSS,
                description="XSS detected",
                metadata={"input": combined[:200]}
            )
            self.threat_events.append(threat)
            self.sync_to_digital_twin(threat)
            return threat

        return None


# GLOBAL INSTANCE
security_manager = SecurityManager()
