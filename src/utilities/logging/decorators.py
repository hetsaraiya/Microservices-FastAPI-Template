"""
Logging Decorators

This module provides decorators for automatic logging of function calls,
performance monitoring, error tracking, and audit logging.
"""

import asyncio
import functools
import inspect
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from loguru import logger

from .context import get_correlation_id, get_current_context, PerformanceTimer
from .formatters import SensitiveDataMasker, LogSanitizer


F = TypeVar('F', bound=Callable[..., Any])


class LoggingDecorators:
    """Collection of logging decorators for different use cases."""
    
    def __init__(self, 
                 logger_instance=None,
                 mask_sensitive: bool = True,
                 sanitize_input: bool = True):
        """
        Initialize logging decorators.
        
        Args:
            logger_instance: Logger instance to use
            mask_sensitive: Whether to mask sensitive data
            sanitize_input: Whether to sanitize input data
        """
        self.logger = logger_instance or logger
        self.masker = SensitiveDataMasker() if mask_sensitive else None
        self.sanitizer = LogSanitizer() if sanitize_input else None


def log_function_call(
    level: str = "INFO",
    include_args: bool = True,
    include_result: bool = True,
    include_duration: bool = True,
    max_arg_length: int = 1000,
    exclude_args: Optional[List[str]] = None,
    mask_sensitive: bool = True
) -> Callable[[F], F]:
    """
    Decorator to log function calls with arguments and results.
    
    Args:
        level: Log level to use
        include_args: Whether to log function arguments
        include_result: Whether to log function result
        include_duration: Whether to log execution duration
        max_arg_length: Maximum length for argument values in logs
        exclude_args: List of argument names to exclude from logging
        mask_sensitive: Whether to mask sensitive data
        
    Returns:
        Decorated function
    """
    exclude_args = exclude_args or []
    masker = SensitiveDataMasker() if mask_sensitive else None
    sanitizer = LogSanitizer()
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            correlation_id = get_correlation_id()
            
            # Prepare function info
            func_name = func.__name__
            module_name = func.__module__
            
            # Log function entry
            if include_args:
                # Get function signature
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                
                # Filter and mask arguments
                logged_args = {}
                for arg_name, arg_value in bound_args.arguments.items():
                    if arg_name not in exclude_args:
                        # Sanitize and truncate
                        str_value = str(arg_value)
                        if len(str_value) > max_arg_length:
                            str_value = str_value[:max_arg_length] + "... [TRUNCATED]"
                        
                        logged_args[arg_name] = sanitizer.sanitize_user_input(str_value)
                
                # Mask sensitive data
                if masker:
                    logged_args = masker.mask_dict(logged_args)
                
                logger.bind(
                    correlation_id=correlation_id,
                    function=func_name,
                    module=module_name,
                    arguments=logged_args
                ).log(level, f"Calling function: {func_name}")
            else:
                logger.bind(
                    correlation_id=correlation_id,
                    function=func_name,
                    module=module_name
                ).log(level, f"Calling function: {func_name}")
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Log function exit
                duration = time.time() - start_time
                log_data = {
                    "correlation_id": correlation_id,
                    "function": func_name,
                    "module": module_name,
                    "success": True
                }
                
                if include_duration:
                    log_data["duration_seconds"] = duration
                    log_data["duration_ms"] = duration * 1000
                
                if include_result and result is not None:
                    result_str = str(result)
                    if len(result_str) > max_arg_length:
                        result_str = result_str[:max_arg_length] + "... [TRUNCATED]"
                    
                    result_data = sanitizer.sanitize_user_input(result_str)
                    if masker:
                        result_data = masker.mask_string(result_data)
                    
                    log_data["result"] = result_data
                
                logger.bind(**log_data).log(
                    level, 
                    f"Function completed: {func_name}" + 
                    (f" in {duration:.3f}s" if include_duration else "")
                )
                
                return result
                
            except Exception as e:
                # Log function error
                duration = time.time() - start_time
                logger.bind(
                    correlation_id=correlation_id,
                    function=func_name,
                    module=module_name,
                    success=False,
                    duration_seconds=duration,
                    error_type=type(e).__name__,
                    error_message=str(e)
                ).error(f"Function failed: {func_name} - {type(e).__name__}: {str(e)}")
                
                raise
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            correlation_id = get_correlation_id()
            
            # Prepare function info
            func_name = func.__name__
            module_name = func.__module__
            
            # Log function entry (similar to sync version)
            if include_args:
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                
                logged_args = {}
                for arg_name, arg_value in bound_args.arguments.items():
                    if arg_name not in exclude_args:
                        str_value = str(arg_value)
                        if len(str_value) > max_arg_length:
                            str_value = str_value[:max_arg_length] + "... [TRUNCATED]"
                        
                        logged_args[arg_name] = sanitizer.sanitize_user_input(str_value)
                
                if masker:
                    logged_args = masker.mask_dict(logged_args)
                
                logger.bind(
                    correlation_id=correlation_id,
                    function=func_name,
                    module=module_name,
                    arguments=logged_args
                ).log(level, f"Calling async function: {func_name}")
            else:
                logger.bind(
                    correlation_id=correlation_id,
                    function=func_name,
                    module=module_name
                ).log(level, f"Calling async function: {func_name}")
            
            try:
                # Execute async function
                result = await func(*args, **kwargs)
                
                # Log function exit
                duration = time.time() - start_time
                log_data = {
                    "correlation_id": correlation_id,
                    "function": func_name,
                    "module": module_name,
                    "success": True
                }
                
                if include_duration:
                    log_data["duration_seconds"] = duration
                    log_data["duration_ms"] = duration * 1000
                
                if include_result and result is not None:
                    result_str = str(result)
                    if len(result_str) > max_arg_length:
                        result_str = result_str[:max_arg_length] + "... [TRUNCATED]"
                    
                    result_data = sanitizer.sanitize_user_input(result_str)
                    if masker:
                        result_data = masker.mask_string(result_data)
                    
                    log_data["result"] = result_data
                
                logger.bind(**log_data).log(
                    level,
                    f"Async function completed: {func_name}" +
                    (f" in {duration:.3f}s" if include_duration else "")
                )
                
                return result
                
            except Exception as e:
                # Log function error
                duration = time.time() - start_time
                logger.bind(
                    correlation_id=correlation_id,
                    function=func_name,
                    module=module_name,
                    success=False,
                    duration_seconds=duration,
                    error_type=type(e).__name__,
                    error_message=str(e)
                ).error(f"Async function failed: {func_name} - {type(e).__name__}: {str(e)}")
                
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def log_performance(
    threshold_seconds: float = 1.0,
    level: str = "WARNING",
    include_args: bool = False
) -> Callable[[F], F]:
    """
    Decorator to log performance warnings for slow functions.
    
    Args:
        threshold_seconds: Time threshold in seconds for performance warning
        level: Log level for performance warnings
        include_args: Whether to include function arguments in performance logs
        
    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if duration > threshold_seconds:
                    log_data = {
                        "correlation_id": get_correlation_id(),
                        "function": func.__name__,
                        "module": func.__module__,
                        "duration_seconds": duration,
                        "duration_ms": duration * 1000,
                        "threshold_seconds": threshold_seconds,
                        "performance_issue": True
                    }
                    
                    if include_args:
                        sig = inspect.signature(func)
                        bound_args = sig.bind(*args, **kwargs)
                        bound_args.apply_defaults()
                        log_data["arguments"] = dict(bound_args.arguments)
                    
                    logger.bind(**log_data).log(
                        level,
                        f"Slow function detected: {func.__name__} took {duration:.3f}s "
                        f"(threshold: {threshold_seconds}s)"
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.bind(
                    correlation_id=get_correlation_id(),
                    function=func.__name__,
                    module=func.__module__,
                    duration_seconds=duration,
                    error_type=type(e).__name__,
                    error_message=str(e)
                ).error(f"Function failed after {duration:.3f}s: {func.__name__}")
                raise
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                if duration > threshold_seconds:
                    log_data = {
                        "correlation_id": get_correlation_id(),
                        "function": func.__name__,
                        "module": func.__module__,
                        "duration_seconds": duration,
                        "duration_ms": duration * 1000,
                        "threshold_seconds": threshold_seconds,
                        "performance_issue": True
                    }
                    
                    if include_args:
                        sig = inspect.signature(func)
                        bound_args = sig.bind(*args, **kwargs)
                        bound_args.apply_defaults()
                        log_data["arguments"] = dict(bound_args.arguments)
                    
                    logger.bind(**log_data).log(
                        level,
                        f"Slow async function detected: {func.__name__} took {duration:.3f}s "
                        f"(threshold: {threshold_seconds}s)"
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.bind(
                    correlation_id=get_correlation_id(),
                    function=func.__name__,
                    module=func.__module__,
                    duration_seconds=duration,
                    error_type=type(e).__name__,
                    error_message=str(e)
                ).error(f"Async function failed after {duration:.3f}s: {func.__name__}")
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def log_errors(
    level: str = "ERROR",
    include_traceback: bool = True,
    reraise: bool = True
) -> Callable[[F], F]:
    """
    Decorator to log function errors with detailed information.
    
    Args:
        level: Log level for errors
        include_traceback: Whether to include full traceback
        reraise: Whether to reraise the exception after logging
        
    Returns:
        Decorated function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_data = {
                    "correlation_id": get_correlation_id(),
                    "function": func.__name__,
                    "module": func.__module__,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "error_occurred": True
                }
                
                if include_traceback:
                    import traceback
                    log_data["traceback"] = traceback.format_exc()
                
                logger.bind(**log_data).log(
                    level,
                    f"Error in function {func.__name__}: {type(e).__name__}: {str(e)}"
                )
                
                if reraise:
                    raise
                return None
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                log_data = {
                    "correlation_id": get_correlation_id(),
                    "function": func.__name__,
                    "module": func.__module__,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "error_occurred": True
                }
                
                if include_traceback:
                    import traceback
                    log_data["traceback"] = traceback.format_exc()
                
                logger.bind(**log_data).log(
                    level,
                    f"Error in async function {func.__name__}: {type(e).__name__}: {str(e)}"
                )
                
                if reraise:
                    raise
                return None
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def audit_log(
    action: str,
    resource_type: str = "unknown",
    include_args: bool = True,
    sensitive_args: Optional[List[str]] = None
) -> Callable[[F], F]:
    """
    Decorator for audit logging of sensitive operations.
    
    Args:
        action: The action being performed (e.g., "create", "update", "delete")
        resource_type: Type of resource being affected
        include_args: Whether to include function arguments
        sensitive_args: List of argument names that contain sensitive data
        
    Returns:
        Decorated function
    """
    sensitive_args = sensitive_args or []
    masker = SensitiveDataMasker()
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            correlation_id = get_correlation_id()
            context = get_current_context()
            
            # Prepare audit log data
            audit_data = {
                "correlation_id": correlation_id,
                "user_id": context.get("user_id", "anonymous"),
                "client_ip": context.get("client_ip", "unknown"),
                "action": action,
                "resource_type": resource_type,
                "function": func.__name__,
                "module": func.__module__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "audit_event": True
            }
            
            if include_args:
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                
                # Mask sensitive arguments
                args_data = dict(bound_args.arguments)
                for sensitive_arg in sensitive_args:
                    if sensitive_arg in args_data:
                        args_data[sensitive_arg] = masker._mask_value(args_data[sensitive_arg])
                
                audit_data["arguments"] = masker.mask_dict(args_data)
            
            try:
                result = func(*args, **kwargs)
                
                audit_data["success"] = True
                logger.bind(**audit_data).info(
                    f"Audit: {action} {resource_type} by {context.get('user_id', 'anonymous')}"
                )
                
                return result
                
            except Exception as e:
                audit_data["success"] = False
                audit_data["error_type"] = type(e).__name__
                audit_data["error_message"] = str(e)
                
                logger.bind(**audit_data).warning(
                    f"Audit: Failed {action} {resource_type} by {context.get('user_id', 'anonymous')} - {str(e)}"
                )
                
                raise
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            correlation_id = get_correlation_id()
            context = get_current_context()
            
            audit_data = {
                "correlation_id": correlation_id,
                "user_id": context.get("user_id", "anonymous"),
                "client_ip": context.get("client_ip", "unknown"),
                "action": action,
                "resource_type": resource_type,
                "function": func.__name__,
                "module": func.__module__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "audit_event": True
            }
            
            if include_args:
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                
                args_data = dict(bound_args.arguments)
                for sensitive_arg in sensitive_args:
                    if sensitive_arg in args_data:
                        args_data[sensitive_arg] = masker._mask_value(args_data[sensitive_arg])
                
                audit_data["arguments"] = masker.mask_dict(args_data)
            
            try:
                result = await func(*args, **kwargs)
                
                audit_data["success"] = True
                logger.bind(**audit_data).info(
                    f"Audit: {action} {resource_type} by {context.get('user_id', 'anonymous')}"
                )
                
                return result
                
            except Exception as e:
                audit_data["success"] = False
                audit_data["error_type"] = type(e).__name__
                audit_data["error_message"] = str(e)
                
                logger.bind(**audit_data).warning(
                    f"Audit: Failed {action} {resource_type} by {context.get('user_id', 'anonymous')} - {str(e)}"
                )
                
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Convenience decorators with predefined settings
def log_api_call(include_args: bool = True, include_result: bool = False):
    """Convenience decorator for API endpoint logging."""
    return log_function_call(
        level="INFO",
        include_args=include_args,
        include_result=include_result,
        include_duration=True,
        exclude_args=["password", "token", "secret"],
        mask_sensitive=True
    )


def log_database_operation(include_args: bool = False):
    """Convenience decorator for database operation logging."""
    return log_function_call(
        level="DEBUG",
        include_args=include_args,
        include_result=False,
        include_duration=True,
        mask_sensitive=True
    )


def log_external_api_call(threshold_seconds: float = 5.0):
    """Convenience decorator for external API call logging."""
    def decorator(func: F) -> F:
        # Combine function logging with performance monitoring
        func = log_function_call(
            level="INFO",
            include_args=True,
            include_result=False,
            include_duration=True,
            mask_sensitive=True
        )(func)
        
        func = log_performance(
            threshold_seconds=threshold_seconds,
            level="WARNING",
            include_args=False
        )(func)
        
        return func
    
    return decorator