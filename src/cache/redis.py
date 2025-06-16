import json
import typing
import redis
import uuid  # Add this import
from functools import wraps
from pydantic import BaseModel
from src.config.manager import settings
from src.services import get_redis_client
from src.utilities.logging.logger import logger

# Add a custom JSON encoder to handle UUIDs and other special types
class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles special types like UUID."""
    
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if hasattr(obj, 'model_dump'):  # Pydantic v2
            return obj.model_dump()
        if hasattr(obj, 'dict') and callable(obj.dict):  # Pydantic v1
            return obj.dict()
        if hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        return super().default(obj)

class RedisManager:
    """
    Redis connection manager for handling Redis client operations.
    
    This class manages Redis connections and provides utility methods for
    working with Redis, including connection creation, key management,
    and serialization helpers.
    """
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one Redis connection manager exists."""
        if cls._instance is None:
            cls._instance = super(RedisManager, cls).__new__(cls)
            cls._instance._client = None
        return cls._instance
    
    def __init__(self):
        """Initialize the Redis connection manager."""
        # Only set up the client if it doesn't exist yet
        if self._client is None:
            self._setup_redis_client()
    
    def _setup_redis_client(self):
        """Set up the Redis client with configuration from settings."""
        self._client = get_redis_client()
    
    @property
    def client(self) -> redis.Redis:
        """
        Get the Redis client instance.
        
        Returns:
            redis.Redis: The Redis client instance.
            
        Raises:
            ConnectionError: If the Redis client is not connected.
        """
        if self._client is None:
            self._setup_redis_client()
            if self._client is None:
                raise ConnectionError("Redis client is not connected")
        return self._client
    
    async def close(self):
        """Close the Redis connection."""
        if self._client:
            logger.info("Closing Redis connection")
            self._client.close()
            self._client = None
    
    def set(self, key: str, value: typing.Any, expiration: int = None) -> bool:
        """
        Set a key-value pair in Redis with optional expiration.
        
        Args:
            key: The key to set.
            value: The value to set.
            expiration: Optional expiration time in seconds.
            
        Returns:
            bool: True if the key was set, False otherwise.
        """
        try:
            # Handle Pydantic models by converting to dict first
            if hasattr(value, 'model_dump'):  # New Pydantic v2.x method
                value = value.model_dump()
                logger.debug(f"Cache SET: Converting Pydantic v2 model to dict for key '{key}'")
            elif hasattr(value, 'dict') and callable(value.dict):  # Older Pydantic v1.x method
                value = value.dict()
                logger.debug(f"Cache SET: Converting Pydantic v1 model to dict for key '{key}'")
                
            # Serialize non-string values to JSON with our custom encoder
            if not isinstance(value, (str, bytes)):
                value = json.dumps(value, cls=CustomJSONEncoder)
                logger.debug(f"Cache SET: Serialized value to JSON for key '{key}'")
                
            # Use default expiration from settings if not specified
            if expiration is None:
                expiration = settings.REDIS_CACHE_EXPIRATION
                logger.debug(f"Cache SET: Using default expiration of {expiration}s for key '{key}'")
            else:
                logger.debug(f"Cache SET: Using custom expiration of {expiration}s for key '{key}'")
                
            result = self.client.set(key, value, ex=expiration)
            logger.info(f"Cache SET: Key '{key}' stored in Redis with TTL {expiration}s")
            return result
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Cache SET ERROR: Failed to store key '{key}': {str(e)}")
            return False
    
    def get(self, key: str, default: typing.Any = None) -> typing.Any:
        """
        Get a value from Redis by key.
        
        Args:
            key: The key to get.
            default: The default value to return if the key doesn't exist.
            
        Returns:
            The value from Redis, or the default value if the key doesn't exist.
        """
        try:
            value = self.client.get(key)
            if value is None:
                logger.debug(f"Cache MISS: Key '{key}' not found in Redis")
                return default
                
            logger.debug(f"Cache HIT: Key '{key}' found in Redis")
            
            # Try to deserialize from JSON if it looks like JSON
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8')
                except UnicodeDecodeError:
                    logger.debug(f"Cache value for '{key}' contains raw bytes that couldn't be decoded")
                    return value
                    
            if isinstance(value, str) and (value.startswith('{') or value.startswith('[')):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    logger.debug(f"Cache value for '{key}' looks like JSON but couldn't be parsed")
                    pass
                    
            return value
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Redis get error for key '{key}': {str(e)}")
            return default
    
    def delete(self, key: str) -> bool:
        """
        Delete a key from Redis.
        
        Args:
            key: The key to delete.
            
        Returns:
            bool: True if the key was deleted, False otherwise.
        """
        try:
            result = bool(self.client.delete(key))
            if result:
                logger.info(f"Cache DELETE: Successfully removed key '{key}' from cache")
            else:
                logger.debug(f"Cache DELETE: Key '{key}' not found in cache")
            return result
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Cache DELETE ERROR: Failed to delete key '{key}': {str(e)}")
            return False
    
    def exists(self, key: str) -> bool:
        """
        Check if a key exists in Redis.
        
        Args:
            key: The key to check.
            
        Returns:
            bool: True if the key exists, False otherwise.
        """
        try:
            result = bool(self.client.exists(key))
            if result:
                logger.debug(f"Cache CHECK: Key '{key}' exists in cache")
            else:
                logger.debug(f"Cache CHECK: Key '{key}' does not exist in cache")
            return result
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Cache CHECK ERROR: Failed to check existence of key '{key}': {str(e)}")
            return False
    
    def flush_all(self) -> bool:
        """
        Flush all keys in the current Redis database.
        WARNING: This will delete all data in the Redis database.
        
        Returns:
            bool: True if the database was flushed, False otherwise.
        """
        try:
            self.client.flushdb()
            logger.warning(f"Cache FLUSH: All keys have been removed from the Redis database")
            return True
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Cache FLUSH ERROR: Failed to flush Redis database: {str(e)}")
            return False
    
    def set_many(self, mapping: dict, expiration: int = None) -> bool:
        """
        Set multiple key-value pairs in Redis with the same expiration.
        
        Args:
            mapping: A dictionary of key-value pairs to set.
            expiration: Optional expiration time in seconds.
            
        Returns:
            bool: True if all keys were set, False otherwise.
        """
        try:
            # Use default expiration from settings if not specified
            if expiration is None:
                expiration = settings.REDIS_CACHE_EXPIRATION
                logger.debug(f"Cache SET_MANY: Using default expiration of {expiration}s for {len(mapping)} keys")
            else:
                logger.debug(f"Cache SET_MANY: Using custom expiration of {expiration}s for {len(mapping)} keys")
                
            # Serialize non-string values to JSON
            serialized_mapping = {}
            for k, v in mapping.items():
                # Handle Pydantic models
                if hasattr(v, 'model_dump'):  # New Pydantic v2.x method
                    v = v.model_dump()
                elif hasattr(v, 'dict') and callable(v.dict):  # Older Pydantic v1.x method
                    v = v.dict()
                
                if not isinstance(v, (str, bytes)):
                    serialized_mapping[k] = json.dumps(v, cls=CustomJSONEncoder)
                else:
                    serialized_mapping[k] = v
                    
            # Set all keys
            pipeline = self.client.pipeline()
            for k, v in serialized_mapping.items():
                pipeline.set(k, v, ex=expiration)
            pipeline.execute()
            
            logger.info(f"Cache SET_MANY: Successfully stored {len(mapping)} keys in Redis with TTL {expiration}s")
            return True
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Cache SET_MANY ERROR: Failed to store multiple keys: {str(e)}")
            return False
    
    def get_many(self, keys: list) -> dict:
        """
        Get multiple values from Redis by keys.
        
        Args:
            keys: A list of keys to get.
            
        Returns:
            dict: A dictionary of key-value pairs for keys that exist.
        """
        try:
            logger.debug(f"Cache GET_MANY: Attempting to retrieve {len(keys)} keys")
            pipeline = self.client.pipeline()
            for key in keys:
                pipeline.get(key)
            values = pipeline.execute()
            
            result = {}
            hits = 0
            
            for i, key in enumerate(keys):
                if values[i] is not None:
                    hits += 1
                    value = values[i]
                    # Handle bytes to string conversion
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8')
                        except UnicodeDecodeError:
                            logger.debug(f"Cache GET_MANY: Value for key '{key}' contains raw bytes that couldn't be decoded")
                            result[key] = value
                            continue
                    
                    # Try to deserialize from JSON if it looks like JSON
                    if isinstance(value, str) and (value.startswith('{') or value.startswith('[')):
                        try:
                            result[key] = json.loads(value)
                            continue
                        except json.JSONDecodeError:
                            logger.debug(f"Cache GET_MANY: Value for key '{key}' looks like JSON but couldn't be parsed")
                            pass
                    result[key] = value
            
            # Log hit/miss statistics
            misses = len(keys) - hits
            hit_rate = (hits / len(keys)) * 100 if keys else 0
            logger.info(f"Cache GET_MANY: Retrieved {hits} of {len(keys)} keys (Hit rate: {hit_rate:.1f}%) - Hits: {hits}, Misses: {misses}")
            
            return result
        except (redis.RedisError, ConnectionError) as e:
            logger.error(f"Cache GET_MANY ERROR: Failed to retrieve multiple keys: {str(e)}")
            return {}
    
    def build_key(self, *parts) -> str:
        """
        Build a Redis key from parts.
        
        Args:
            *parts: Parts to join into a key.
            
        Returns:
            str: The built key.
        """
        return ':'.join(str(p) for p in parts if p)


# Create a singleton instance
redis_manager = RedisManager()