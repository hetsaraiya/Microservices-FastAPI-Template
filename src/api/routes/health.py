from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional
import asyncio

from src.utilities.logging.logger import logger

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=Dict[str, Any])
async def health_check(
    request: Request
) -> Dict[str, Any]:
    """
    Health check endpoint that verifies database connection.
    
    Returns:
        Dict containing the health status of services
    """
    health_status = {
        "status": "healthy",
        "services": {
            "database": "unknown"
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
        
        # Overall status
        if health_status["services"]["database"] in ["unhealthy", "disconnected"]:
            health_status["status"] = "unhealthy"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service health check failed")



