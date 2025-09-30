"""
Example integration of Redis and Kafka connections in route handlers.

This file demonstrates how to use the Redis and Kafka connections
through dependency injection for cleaner and more testable code.
"""

from fastapi import APIRouter, Depends, Request, HTTPException, status
from typing import Dict, Any
import json
import uuid
from datetime import datetime

from src.api.dependencies.redis import get_redis_client
from src.api.dependencies.kafka import get_kafka_manager
from src.services.kafka.topics import KafkaTopics
from src.services.kafka.manager import KafkaManager
from src.utilities.logging.logger import logger

router = APIRouter(prefix="/example", tags=["example"])


@router.post("/cache-user/{user_id}")
async def cache_user_data(
    user_id: str,
    user_data: Dict[str, Any],
    redis_client=Depends(get_redis_client)
) -> Dict[str, str]:
    """
    Example: Cache user data in Redis using dependency injection.
    """
    try:
        # Create cache key
        cache_key = f"user:{user_id}"
        
        # Cache user data for 1 hour (3600 seconds)
        redis_client.setex(
            cache_key,
            3600,
            json.dumps(user_data, default=str)
        )
        
        logger.info(f"Cached user data for user_id: {user_id}")
        
        return {
            "message": "User data cached successfully",
            "cache_key": cache_key,
            "ttl": "3600 seconds"
        }
        
    except RuntimeError as e:
        # Redis not available
        logger.warning(f"Redis not available: {e}")
        raise HTTPException(
            status_code=503,
            detail="Cache service unavailable"
        )
    except Exception as e:
        logger.error(f"Failed to cache user data: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to cache user data"
        )


@router.get("/cache-user/{user_id}")
async def get_cached_user_data(
    user_id: str,
    redis_client=Depends(get_redis_client)
) -> Dict[str, Any]:
    """
    Example: Retrieve cached user data from Redis using dependency injection.
    """
    try:
        # Get cache key
        cache_key = f"user:{user_id}"
        
        # Get cached data
        cached_data = redis_client.get(cache_key)
        
        if cached_data:
            user_data = json.loads(cached_data)
            logger.info(f"Retrieved cached user data for user_id: {user_id}")
            
            return {
                "user_id": user_id,
                "data": user_data,
                "source": "cache"
            }
        else:
            raise HTTPException(
                status_code=404,
                detail="User data not found in cache"
            )
            
    except RuntimeError as e:
        # Redis not available
        logger.warning(f"Redis not available: {e}")
        raise HTTPException(
            status_code=503,
            detail="Cache service unavailable"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve cached user data: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve cached user data"
        )


@router.post("/publish-user-event")
async def publish_user_event(
    event_data: Dict[str, Any],
    kafka_manager: KafkaManager = Depends(get_kafka_manager)
) -> Dict[str, str]:
    """
    Example: Publish user event to Kafka using dependency injection.
    """
    try:
        # Add metadata to event
        event_data.update({
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "service": "user_management"
        })
        
        # Publish to Kafka topic
        await kafka_manager.publish_message(
            topic=KafkaTopics.USER_CREATED,
            key=event_data.get("user_id"),
            message=event_data
        )
        
        logger.info(f"Published user event: {event_data['event_id']}")
        
        return {
            "message": "Event published successfully",
            "event_id": event_data["event_id"],
            "topic": KafkaTopics.USER_CREATED
        }
        
    except RuntimeError as e:
        # Kafka not available
        logger.warning(f"Kafka not available: {e}")
        raise HTTPException(
            status_code=503,
            detail="Message queue service unavailable"
        )
    except Exception as e:
        logger.error(f"Failed to publish user event: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to publish user event"
        )


@router.get("/session-info")
async def get_session_info(
    request: Request,
    redis_client=Depends(get_redis_client)
) -> Dict[str, Any]:
    """
    Example: Get session information using Redis for session storage with dependency injection.
    """
    try:
        # Get session ID from headers or cookies (example)
        session_id = request.headers.get("X-Session-ID")
        
        if not session_id:
            raise HTTPException(
                status_code=400,
                detail="Session ID required"
            )
        
        # Get session data from Redis
        session_key = f"session:{session_id}"
        session_data = redis_client.get(session_key)
        
        if session_data:
            session_info = json.loads(session_data)
            
            # Update last accessed time
            session_info["last_accessed"] = datetime.utcnow().isoformat()
            redis_client.setex(
                session_key,
                3600,  # 1 hour TTL
                json.dumps(session_info, default=str)
            )
            
            return {
                "session_id": session_id,
                "session_data": session_info,
                "status": "active"
            }
        else:
            raise HTTPException(
                status_code=404,
                detail="Session not found or expired"
            )
            
    except RuntimeError as e:
        # Redis not available
        logger.warning(f"Redis not available: {e}")
        raise HTTPException(
            status_code=503,
            detail="Session service unavailable"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get session info: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get session info"
        )


# This would typically be registered in your main endpoints.py file
# router.include_router(router=example_router)
