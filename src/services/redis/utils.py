"""
Redis utility functions for common operations
"""

import json
import asyncio
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta

from src.services.redis.client import get_redis_client
from src.utilities.logging.logger import logger


class RedisUtils:
    """Utility class for common Redis operations"""
    
    def __init__(self):
        self.client = get_redis_client()
    
    async def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Store a JSON-serializable object in Redis
        
        Args:
            key: Redis key
            value: Value to store (will be JSON-serialized)
            ttl: Time to live in seconds
            
        Returns:
            bool: True if successful
        """
        try:
            json_value = json.dumps(value, default=str)
            if ttl:
                return await asyncio.to_thread(self.client.setex, key, ttl, json_value)
            else:
                return await asyncio.to_thread(self.client.set, key, json_value)
        except Exception as e:
            logger.error(f"Failed to set JSON in Redis: {e}")
            return False
    
    async def get_json(self, key: str) -> Optional[Any]:
        """
        Retrieve and JSON-deserialize a value from Redis
        
        Args:
            key: Redis key
            
        Returns:
            Deserialized value or None if not found
        """
        try:
            value = await asyncio.to_thread(self.client.get, key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Failed to get JSON from Redis: {e}")
            return None
    
    async def cache_user_session(self, user_id: str, session_data: Dict[str, Any], ttl: int = 3600) -> str:
        """
        Cache user session data
        
        Args:
            user_id: User ID
            session_data: Session data to cache
            ttl: Time to live in seconds (default: 1 hour)
            
        Returns:
            str: Session key
        """
        session_key = f"session:user:{user_id}"
        session_data.update({
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
        })
        
        await self.set_json(session_key, session_data, ttl)
        return session_key
    
    async def get_user_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user session data
        
        Args:
            user_id: User ID
            
        Returns:
            Session data or None if not found
        """
        session_key = f"session:user:{user_id}"
        return await self.get_json(session_key)
    
    async def cache_user_data(self, user_id: str, user_data: Dict[str, Any], ttl: int = 1800) -> bool:
        """
        Cache user data for quick access
        
        Args:
            user_id: User ID
            user_data: User data to cache
            ttl: Time to live in seconds (default: 30 minutes)
            
        Returns:
            bool: True if successful
        """
        cache_key = f"user:data:{user_id}"
        return await self.set_json(cache_key, user_data, ttl)
    
    async def get_cached_user_data(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached user data
        
        Args:
            user_id: User ID
            
        Returns:
            User data or None if not found
        """
        cache_key = f"user:data:{user_id}"
        return await self.get_json(cache_key)
    
    async def increment_counter(self, key: str, ttl: Optional[int] = None) -> int:
        """
        Increment a counter (useful for rate limiting, analytics, etc.)
        
        Args:
            key: Counter key
            ttl: Time to live in seconds
            
        Returns:
            int: New counter value
        """
        try:
            value = await asyncio.to_thread(self.client.incr, key)
            if ttl and value == 1:  # Set TTL only on first increment
                await asyncio.to_thread(self.client.expire, key, ttl)
            return value
        except Exception as e:
            logger.error(f"Failed to increment counter: {e}")
            return 0
    
    async def get_counter(self, key: str) -> int:
        """
        Get counter value
        
        Args:
            key: Counter key
            
        Returns:
            int: Counter value (0 if not found)
        """
        try:
            value = await asyncio.to_thread(self.client.get, key)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Failed to get counter: {e}")
            return 0
    
    async def add_to_set(self, key: str, *values: str) -> int:
        """
        Add values to a Redis set
        
        Args:
            key: Set key
            values: Values to add
            
        Returns:
            int: Number of values added
        """
        try:
            return await asyncio.to_thread(self.client.sadd, key, *values)
        except Exception as e:
            logger.error(f"Failed to add to set: {e}")
            return 0
    
    async def is_in_set(self, key: str, value: str) -> bool:
        """
        Check if value is in a Redis set
        
        Args:
            key: Set key
            value: Value to check
            
        Returns:
            bool: True if value is in set
        """
        try:
            return await asyncio.to_thread(self.client.sismember, key, value)
        except Exception as e:
            logger.error(f"Failed to check set membership: {e}")
            return False
    
    async def get_set_members(self, key: str) -> List[str]:
        """
        Get all members of a Redis set
        
        Args:
            key: Set key
            
        Returns:
            List[str]: Set members
        """
        try:
            members = await asyncio.to_thread(self.client.smembers, key)
            return list(members)
        except Exception as e:
            logger.error(f"Failed to get set members: {e}")
            return []
    
    async def delete_key(self, key: str) -> bool:
        """
        Delete a key from Redis
        
        Args:
            key: Key to delete
            
        Returns:
            bool: True if key was deleted
        """
        try:
            result = await asyncio.to_thread(self.client.delete, key)
            return result > 0
        except Exception as e:
            logger.error(f"Failed to delete key: {e}")
            return False
    
    async def key_exists(self, key: str) -> bool:
        """
        Check if a key exists in Redis
        
        Args:
            key: Key to check
            
        Returns:
            bool: True if key exists
        """
        try:
            return await asyncio.to_thread(self.client.exists, key) > 0
        except Exception as e:
            logger.error(f"Failed to check key existence: {e}")
            return False
    
    async def get_ttl(self, key: str) -> int:
        """
        Get time to live for a key
        
        Args:
            key: Key to check
            
        Returns:
            int: TTL in seconds (-1 if no TTL, -2 if key doesn't exist)
        """
        try:
            return await asyncio.to_thread(self.client.ttl, key)
        except Exception as e:
            logger.error(f"Failed to get TTL: {e}")
            return -2
