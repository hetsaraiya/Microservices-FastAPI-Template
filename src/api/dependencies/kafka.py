"""
Kafka dependency injection for API routes
"""
from fastapi import Request
from src.services.connections import get_kafka_from_app
from src.services.kafka.manager import KafkaManager


def get_kafka_manager(request: Request) -> KafkaManager:
    """
    Dependency to get Kafka manager from app state.
    
    Args:
        request: FastAPI request object
        
    Returns:
        KafkaManager: Kafka manager instance
        
    Raises:
        RuntimeError: If Kafka manager is not initialized
    """
    return get_kafka_from_app(request.app)
