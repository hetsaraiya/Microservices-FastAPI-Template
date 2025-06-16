"""
Redis caching decorators for AgrEazy.

This module provides decorators for caching function results in Redis.
"""

import inspect
import json
import typing
import functools
import hashlib
from fastapi import Request, Response
from src.cache.redis import redis_manager
from src.utilities.logging.logger import logger

def cached(
    ttl: int = None,
    key_prefix: str = None,
    skip_kwargs: list = None,
):
    """
    Decorator to cache function results in Redis.
    
    Args:
        ttl: Time to live for cache entries in seconds. If None, uses default from settings.
        key_prefix: Prefix for cache keys. If None, uses function module and name.
        skip_kwargs: List of keyword argument names to skip when building cache key.
        
    Returns:
        Decorated function that will cache its results.
    """
    skip_kwargs = skip_kwargs or []
    
    def decorator(func):
        # Get the function's signature
        sig = inspect.signature(func)
        
        # Determine if function is async
        is_async = inspect.iscoroutinefunction(func)
        
        # Figure out the prefix to use
        prefix = key_prefix or f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Build a dict of all provided args and kwargs
            call_args = {}
            
            # Match the positional arguments to their parameter names
            parameters = list(sig.parameters.values())
            for i, arg in enumerate(args):
                if i < len(parameters):
                    call_args[parameters[i].name] = arg
            
            # Add the keyword arguments
            call_args.update({k: v for k, v in kwargs.items() if k not in skip_kwargs})
            
            # Generate a cache key
            key_data = json.dumps(call_args, sort_keys=True)
            key_hash = hashlib.md5(key_data.encode()).hexdigest()
            cache_key = redis_manager.build_key(prefix, key_hash)
            
            # Try to get from cache
            cached_result = redis_manager.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}({key_data})")
                return cached_result
            
            # Not in cache, call the original function
            logger.debug(f"Cache miss for {func.__name__}({key_data})")
            result = await func(*args, **kwargs)
            
            # Cache the result
            redis_manager.set(cache_key, result, expiration=ttl)
            return result
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Build a dict of all provided args and kwargs
            call_args = {}
            
            # Match the positional arguments to their parameter names
            parameters = list(sig.parameters.values())
            for i, arg in enumerate(args):
                if i < len(parameters):
                    call_args[parameters[i].name] = arg
            
            # Add the keyword arguments
            call_args.update({k: v for k, v in kwargs.items() if k not in skip_kwargs})
            
            # Generate a cache key
            key_data = json.dumps(call_args, sort_keys=True)
            key_hash = hashlib.md5(key_data.encode()).hexdigest()
            cache_key = redis_manager.build_key(prefix, key_hash)
            
            # Try to get from cache
            cached_result = redis_manager.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}({key_data})")
                return cached_result
            
            # Not in cache, call the original function
            logger.debug(f"Cache miss for {func.__name__}({key_data})")
            result = func(*args, **kwargs)
            
            # Cache the result
            redis_manager.set(cache_key, result, expiration=ttl)
            return result
        
        return async_wrapper if is_async else sync_wrapper
    
    return decorator

def cache_endpoint(
    ttl: int = None,
    key_builder: typing.Callable = None,
    content_types: list = None,
    exclude_response_codes: list = None,
):
    """
    Decorator to cache FastAPI endpoint responses in Redis.
    
    Args:
        ttl: Time to live for cache entries in seconds. If None, uses default from settings.
        key_builder: Function to build cache key from request. If None, uses request method and path with query params.
        content_types: List of content types to cache. If None, caches all responses.
        exclude_response_codes: List of response status codes to not cache.
        
    Returns:
        Decorated endpoint function that will cache its responses.
    """

    logger.debug("Initializing cache_endpoint decorator")
    content_types = content_types or ['application/json']
    exclude_response_codes = exclude_response_codes or [500, 502, 503, 504]
    
    def default_key_builder(request: Request) -> str:
        """Default function to build cache key from a request"""
        # Normalize the URL by stripping trailing slashes
        path = request.url.path.rstrip('/')
        
        # Get query params as a sorted list
        query_params = sorted(request.query_params.items())
        query_string = '&'.join(f"{k}={v}" for k, v in query_params)
        
        if query_string:
            path_with_query = f"{path}?{query_string}"
        else:
            path_with_query = path
            
        # Generate a hash of the URL
        key_hash = hashlib.md5(path_with_query.encode()).hexdigest()
        
        # Log the cache key for debugging
        logger.debug(f"Cache key for {path_with_query}: endpoint:{request.method}:{key_hash}")
        
        # Build the key with method and path hash
        return f"endpoint:{request.method}:{key_hash}"
    
    key_fn = key_builder or default_key_builder
    
    def decorator(endpoint_func):
        @functools.wraps(endpoint_func)
        async def wrapper(request: Request, *args, **kwargs):
            # Check if this is a GET request (typically the ones we want to cache)
            if request.method != "GET":
                return await endpoint_func(request, *args, **kwargs)
            
            # Generate cache key
            cache_key = key_fn(request)
            
            # Try to get from cache
            cached_data = redis_manager.get(cache_key)
            if cached_data is not None:
                logger.info(f"Cache hit for endpoint {request.url.path} with key {cache_key}")
                
                # If it's a FastAPI/Starlette response
                if isinstance(cached_data, dict) and "content" in cached_data and "status_code" in cached_data:
                    return Response(
                        content=cached_data["content"],
                        status_code=cached_data["status_code"],
                        headers=cached_data.get("headers", {}),
                        media_type=cached_data.get("media_type")
                    )
                
                # Handle Pydantic models - reconstruct from dict
                if hasattr(endpoint_func, "__annotations__") and "return" in endpoint_func.__annotations__:
                    return_type = endpoint_func.__annotations__["return"]
                    if hasattr(return_type, "__origin__") and issubclass(return_type.__origin__, typing.Generic):
                        # For Response[Dict] etc.
                        from src.models.schemas.response import Response as PydanticResponse
                        return PydanticResponse(**cached_data)
                
                # Fall back to returning the cached data directly
                return cached_data
            
            # Not in cache, call the original endpoint
            logger.debug(f"Cache miss for endpoint {request.url.path}")
            response = await endpoint_func(request, *args, **kwargs)
            
            # Store in cache based on the type of response
            if hasattr(response, "status_code"):
                # It's a FastAPI/Starlette response
                if (
                    response.status_code not in exclude_response_codes and
                    response.headers.get('content-type', '').startswith(tuple(content_types))
                ):
                    response_data = {
                        "content": response.body.decode() if hasattr(response.body, "decode") else response.body,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "media_type": response.media_type
                    }
                    redis_manager.set(cache_key, response_data, expiration=ttl)
                    logger.info(f"Cached response for {request.url.path} with key {cache_key} and TTL {ttl}s")
            else:
                # It's a Pydantic model or other serializable object
                # The RedisManager.set method now handles Pydantic models
                redis_manager.set(cache_key, response, expiration=ttl)
            
            return response
        
        return wrapper
    
    return decorator

def invalidate_cache(key_prefix: str):
    """
    Decorator to invalidate cache entries with a given prefix.
    
    Args:
        key_prefix: Prefix for cache keys to invalidate.
        
    Returns:
        Decorated function that will invalidate cache entries with the given prefix.
    """
    def decorator(func):
        is_async = inspect.iscoroutinefunction(func)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            
            # Find all keys with the prefix
            pattern = f"{key_prefix}*"
            try:
                keys = redis_manager.client.keys(pattern)
                if keys:
                    redis_manager.client.delete(*keys)
                    logger.debug(f"Invalidated {len(keys)} cache entries with prefix {key_prefix}")
            except Exception as e:
                logger.error(f"Error invalidating cache with prefix {key_prefix}: {str(e)}")
                
            return result
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            # Find all keys with the prefix
            pattern = f"{key_prefix}*"
            try:
                keys = redis_manager.client.keys(pattern)
                if keys:
                    redis_manager.client.delete(*keys)
                    logger.debug(f"Invalidated {len(keys)} cache entries with prefix {key_prefix}")
            except Exception as e:
                logger.error(f"Error invalidating cache with prefix {key_prefix}: {str(e)}")
                
            return result
        
        return async_wrapper if is_async else sync_wrapper
    
    return decorator