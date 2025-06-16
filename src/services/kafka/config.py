from typing import Dict, List
from pydantic import BaseSettings
import os

class KafkaConfig(BaseSettings):
    bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    group_id: str = "user_service_group"
    auto_offset_reset: str = "latest"
    enable_auto_commit: bool = True
    auto_commit_interval_ms: int = 1000
    session_timeout_ms: int = 30000
    request_timeout_ms: int = 40000
    retry_backoff_ms: int = 100
    max_poll_records: int = 500
    
    # Security settings (if needed)
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: str = "PLAIN"
    sasl_username: str = ""
    sasl_password: str = ""
    
    class Config:
        env_prefix = "KAFKA_"

kafka_config = KafkaConfig()