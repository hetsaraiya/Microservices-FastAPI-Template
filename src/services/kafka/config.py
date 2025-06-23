from typing import Dict, List
from pydantic_settings import BaseSettings
import os
from src.config.manager import settings

class KafkaConfig(BaseSettings):
    bootstrap_servers: str = settings.KAFKA_BOOTSTRAP_SERVERS
    group_id: str = settings.KAFKA_GROUP_ID
    auto_offset_reset: str = settings.KAFKA_AUTO_OFFSET_RESET
    enable_auto_commit: bool = settings.KAFKA_ENABLE_AUTO_COMMIT
    auto_commit_interval_ms: int = 1000
    session_timeout_ms: int = settings.KAFKA_SESSION_TIMEOUT_MS
    request_timeout_ms: int = settings.KAFKA_REQUEST_TIMEOUT_MS
    retry_backoff_ms: int = settings.KAFKA_RETRY_BACKOFF_MS
    max_poll_records: int = 500
    
    # Security settings (if needed)
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: str = "PLAIN" 
    sasl_username: str = ""
    sasl_password: str = ""
    
    class Config:
        env_prefix = "KAFKA_"

kafka_config = KafkaConfig()