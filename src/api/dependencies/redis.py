"""
Redis dependency injection for API routes
"""
from fastapi import Request
from src.services.connections import get_redis_from_app


def get_redis_client(request: Request):
    """
    Dependency to get Redis client from app state.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Redis client instance
        
    Raises:
        RuntimeError: If Redis client is not initialized
    """
    return get_redis_from_app(request.app)
