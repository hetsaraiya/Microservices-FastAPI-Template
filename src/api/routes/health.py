from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any
import asyncio

from src.services.connections import get_redis_from_app, get_kafka_from_app
from src.utilities.logging.logger import logger

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=Dict[str, Any])
async def health_check(request: Request) -> Dict[str, Any]:
    """
    Health check endpoint that verifies all service connections.
    
    Returns:
        Dict containing the health status of all services
    """
    health_status = {
        "status": "healthy",
        "services": {
            "database": "unknown",
            "redis": "unknown", 
            "kafka": "unknown"
        },
        "timestamp": None
    }
    
    try:
        import time
        health_status["timestamp"] = int(time.time())
        
        # Check database connection
        try:
            # Assuming database connection is stored in app state
            if hasattr(request.app.state, "database_engine"):
                health_status["services"]["database"] = "healthy"
            else:
                health_status["services"]["database"] = "disconnected"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            health_status["services"]["database"] = "unhealthy"
        
        # Check Redis connection
        try:
            if hasattr(request.app.state, "redis_available") and not request.app.state.redis_available:
                health_status["services"]["redis"] = "disabled"
            else:
                redis_client = get_redis_from_app(request.app)
                await asyncio.to_thread(redis_client.ping)
                health_status["services"]["redis"] = "healthy"
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            health_status["services"]["redis"] = "unhealthy"
        
        # Check Kafka connection
        try:
            if hasattr(request.app.state, "kafka_available") and not request.app.state.kafka_available:
                health_status["services"]["kafka"] = "disabled"
            else:
                kafka_manager = get_kafka_from_app(request.app)
                if kafka_manager._running:
                    health_status["services"]["kafka"] = "healthy"
                else:
                    health_status["services"]["kafka"] = "disconnected"
        except Exception as e:
            logger.error(f"Kafka health check failed: {e}")
            health_status["services"]["kafka"] = "unhealthy"
        
        # Overall status
        unhealthy_services = [
            service for service, status in health_status["services"].items() 
            if status in ["unhealthy", "disconnected"]
        ]
        
        if unhealthy_services:
            health_status["status"] = "degraded" if len(unhealthy_services) < len(health_status["services"]) else "unhealthy"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service health check failed")


@router.get("/redis", response_model=Dict[str, Any])
async def redis_health_check(request: Request) -> Dict[str, Any]:
    """
    Dedicated Redis health check endpoint.
    
    Returns:
        Dict containing Redis connection status and info
    """
    try:
        redis_client = get_redis_from_app(request.app)
        
        # Test connection with ping
        await asyncio.to_thread(redis_client.ping)
        
        # Get Redis info
        info = await asyncio.to_thread(redis_client.info)
        
        return {
            "status": "healthy",
            "service": "redis",
            "version": info.get("redis_version", "unknown"),
            "connected_clients": info.get("connected_clients", 0),
            "used_memory_human": info.get("used_memory_human", "unknown"),
            "timestamp": __import__('datetime').datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Redis health check failed: {str(e)}")


@router.get("/kafka", response_model=Dict[str, Any])
async def kafka_health_check(request: Request) -> Dict[str, Any]:
    """
    Dedicated Kafka health check endpoint.
    
    Returns:
        Dict containing Kafka connection status
    """
    try:
        kafka_manager = get_kafka_from_app(request.app)
        
        return {
            "status": "healthy" if kafka_manager._running else "disconnected",
            "service": "kafka",
            "running": kafka_manager._running,
            "producer_connected": kafka_manager.producer is not None,
            "consumers_count": len(kafka_manager.consumers),
            "timestamp": __import__('datetime').datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Kafka health check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Kafka health check failed: {str(e)}")
