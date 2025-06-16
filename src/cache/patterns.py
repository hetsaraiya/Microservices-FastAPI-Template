"""
Cache utility patterns for AgrEazy.

This module provides common caching patterns and utilities for the application.
"""

import time
import typing
import functools
from src.cache.redis import redis_manager
from src.utilities.logging.logger import logger

def memoize(ttl: int = None):
    """
    Simple memoization pattern using Redis.
    Unlike the cached decorator, this one doesn't handle serialization
    and is meant for simple use cases.
    
    Args:
        ttl: Time to live for cache entries in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate a simple key based on function name and arguments
            cache_key = f"memoize:{func.__name__}:{str(args)}:{str(kwargs)}"
            result = redis_manager.get(cache_key)
            
            if result is not None:
                return result
                
            result = func(*args, **kwargs)
            redis_manager.set(cache_key, result, expiration=ttl)
            return result
            
        return wrapper
    return decorator

def rate_limit(
    limit: int,
    period: int,
    key_func: typing.Callable = None
):
    """
    Rate limiting decorator using Redis.
    
    Args:
        limit: Maximum number of calls allowed within the period
        period: Time period in seconds
        key_func: Function to generate the rate limit key, defaults to IP address
        
    Returns:
        Decorator function that will apply rate limiting
    """
    def get_default_key(request):
        """Default function to get the client IP from request"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0]
        return request.client.host
        
    key_func = key_func or get_default_key
    
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            # Generate rate limit key based on the client IP or custom key function
            client_key = key_func(request)
            rate_key = f"ratelimit:{func.__name__}:{client_key}"
            
            # Get current count
            count = redis_manager.get(rate_key, 0)
            
            # Check if limit has been reached
            if count >= limit:
                logger.warning(f"Rate limit exceeded for {client_key} on {func.__name__}")
                from fastapi import HTTPException, status
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please try again later."
                )
                
            # Increment count
            pipe = redis_manager.client.pipeline()
            pipe.incr(rate_key)
            # Set expiration if not already set
            pipe.expire(rate_key, period)
            pipe.execute()
            
            # Call the original function
            return await func(request, *args, **kwargs)
            
        return wrapper
    return decorator

def cache_data(key: str, data: typing.Any, ttl: int = None) -> bool:
    """
    Utility function to manually cache data.
    
    Args:
        key: Cache key
        data: Data to cache
        ttl: Time to live in seconds
        
    Returns:
        True if data was cached successfully, False otherwise
    """
    return redis_manager.set(key, data, expiration=ttl)

def get_cached_data(key: str, default: typing.Any = None) -> typing.Any:
    """
    Utility function to manually retrieve cached data.
    
    Args:
        key: Cache key
        default: Default value to return if key doesn't exist
        
    Returns:
        Cached data or default value
    """
    return redis_manager.get(key, default)

def invalidate_data(key: str) -> bool:
    """
    Utility function to manually invalidate cached data.
    
    Args:
        key: Cache key
        
    Returns:
        True if data was invalidated successfully, False otherwise
    """
    return redis_manager.delete(key)

def cache_with_fallback(
    key: str,
    fallback_func: typing.Callable,
    ttl: int = None,
    stale_ttl: int = 3600  # 1 hour by default
) -> typing.Any:
    """
    Cache-aside pattern with stale cache behavior.
    If the cache is empty, call the fallback function and cache the result.
    If the fallback function fails, return stale data if available.
    
    Args:
        key: Cache key
        fallback_func: Function to call if cache miss
        ttl: Cache TTL in seconds
        stale_ttl: How long to keep stale data after expiration
        
    Returns:
        Cached data or result of fallback function
    """
    # Try to get fresh data from cache
    data = redis_manager.get(key)
    if data is not None:
        return data
        
    # Try to get stale data as backup
    stale_key = f"{key}:stale"
    stale_data = redis_manager.get(stale_key)
    
    try:
        # Call fallback function to get fresh data
        fresh_data = fallback_func()
        
        # Cache the fresh data
        redis_manager.set(key, fresh_data, expiration=ttl)
        
        # Also cache as stale data with longer TTL for fallback
        redis_manager.set(stale_key, fresh_data, expiration=stale_ttl)
        
        return fresh_data
    except Exception as e:
        logger.error(f"Fallback function failed for key {key}: {str(e)}")
        
        # Return stale data if available
        if stale_data is not None:
            logger.info(f"Returning stale data for key {key}")
            return stale_data
            
        # Re-raise the exception if no stale data
        raise