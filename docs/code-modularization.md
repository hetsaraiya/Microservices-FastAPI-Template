# Code Modularization Improvements

This document describes the modularization improvements made to the codebase for better code reusability and maintainability.

## Overview

The improvements focus on two main areas:
1. **Enhanced BaseCRUDRepository** - Common CRUD operations for all repository classes
2. **Dependency Injection for Services** - Cleaner approach to accessing Redis and Kafka connections

## 1. Enhanced BaseCRUDRepository

### What Changed

The `BaseCRUDRepository` class now provides common CRUD operations that can be reused across all repository implementations, reducing code duplication.

### New Methods Available

#### Generic Type Support
The base repository now uses Python generics for type safety:
```python
class BaseCRUDRepository(Generic[ModelType]):
    def __init__(self, async_session: SQLAlchemyAsyncSession, model: Type[ModelType] = None):
        self.async_session = async_session
        self.model = model
```

#### Common Operations

- **`create(**kwargs)`** - Create a new record
- **`get_by_id(id)`** - Get a record by ID
- **`get_by_field(field_name, value)`** - Get a record by any field
- **`get_all(skip, limit)`** - Get all records with pagination
- **`update_by_id(id, **kwargs)`** - Update a record by ID
- **`delete_by_id(id)`** - Delete a record by ID
- **`count(**filters)`** - Count records matching filters
- **`exists(**filters)`** - Check if records exist
- **`bulk_create(instances)`** - Create multiple records at once

### Usage Example

```python
from src.repository.crud.base import BaseCRUDRepository
from src.models.db.user import User

class UserCRUDRepository(BaseCRUDRepository[User]):
    def __init__(self, async_session):
        super().__init__(async_session, User)
    
    # Now you can use all base methods:
    # await self.get_by_id(user_id)
    # await self.get_all(skip=0, limit=100)
    # await self.exists(email="user@example.com")
    
    # And add custom methods specific to User
    async def custom_user_method(self):
        # Your custom logic here
        pass
```

### Benefits

1. **Code Reusability** - No need to rewrite common CRUD operations in each repository
2. **Consistency** - All repositories follow the same patterns
3. **Type Safety** - Using generics provides better IDE support and type checking
4. **Less Maintenance** - Changes to common operations only need to be made in one place
5. **Faster Development** - New repositories can be created quickly by extending the base class

## 2. Dependency Injection for Redis and Kafka

### What Changed

Instead of directly accessing Redis and Kafka from `request.app` in route handlers, we now use FastAPI's dependency injection system.

### Before (Old Approach)

```python
from src.services.connections import get_redis_from_app, get_kafka_from_app

@router.post("/cache-user/{user_id}")
async def cache_user_data(
    user_id: str,
    user_data: Dict[str, Any],
    request: Request
):
    redis_client = get_redis_from_app(request.app)  # Direct app access
    # ... rest of code
```

### After (New Approach)

```python
from src.api.dependencies.redis import get_redis_client
from src.api.dependencies.kafka import get_kafka_manager

@router.post("/cache-user/{user_id}")
async def cache_user_data(
    user_id: str,
    user_data: Dict[str, Any],
    redis_client=Depends(get_redis_client)  # Dependency injection
):
    # redis_client is automatically injected
    # ... rest of code
```

### Benefits

1. **Senior Developer Pattern** - Follows industry-standard dependency injection pattern
2. **Better Testability** - Easy to mock dependencies in tests
3. **Cleaner Code** - Route handlers don't need `request: Request` parameter if they don't use it
4. **Single Connection** - All routes use the same Redis/Kafka connection from app state
5. **Separation of Concerns** - Service access is decoupled from route logic
6. **Better Error Handling** - Dependency functions can handle connection errors gracefully

### Available Dependencies

#### Redis Dependency
```python
from src.api.dependencies.redis import get_redis_client

# Usage in route
def some_route(redis_client=Depends(get_redis_client)):
    redis_client.set("key", "value")
```

#### Kafka Dependency
```python
from src.api.dependencies.kafka import get_kafka_manager
from src.services.kafka.manager import KafkaManager

# Usage in route
async def some_route(kafka_manager: KafkaManager = Depends(get_kafka_manager)):
    await kafka_manager.publish_message(topic, key, message)
```

### Connection Management

The connections are still managed centrally at application startup/shutdown:

1. **Startup** (`src/config/events.py`):
   - `initialize_redis_connection(app)` - Creates single Redis connection
   - `initialize_kafka_connection(app)` - Creates single Kafka connection
   - Connections are stored in `app.state`

2. **Runtime** - All routes access the same connections through dependencies

3. **Shutdown** (`src/config/events.py`):
   - `close_redis_connection(app)` - Closes Redis connection
   - `close_kafka_connection(app)` - Closes Kafka connection

### Health Check Example

Health checks also use dependency injection with optional dependencies:

```python
from src.api.dependencies.redis import get_redis_client

def get_redis_client_optional(request: Request):
    """Returns None if Redis is not available"""
    try:
        return get_redis_from_app(request.app)
    except:
        return None

@router.get("/health")
async def health_check(redis_client=Depends(get_redis_client_optional)):
    if redis_client:
        # Check Redis health
        await redis_client.ping()
    else:
        # Redis not available
        pass
```

## Migration Guide

### For Existing Routes

1. Replace direct app access:
   ```python
   # Old
   redis_client = get_redis_from_app(request.app)
   
   # New
   # Add to function parameters:
   redis_client=Depends(get_redis_client)
   ```

2. Remove unnecessary `request: Request` parameter if it's only used for service access

3. Update imports:
   ```python
   # Old
   from src.services.connections import get_redis_from_app, get_kafka_from_app
   
   # New
   from src.api.dependencies.redis import get_redis_client
   from src.api.dependencies.kafka import get_kafka_manager
   ```

### For New Repositories

1. Extend `BaseCRUDRepository` with your model type:
   ```python
   class MyRepository(BaseCRUDRepository[MyModel]):
       def __init__(self, async_session):
           super().__init__(async_session, MyModel)
   ```

2. Use base methods for common operations

3. Add custom methods for model-specific logic

## Examples

### Complete Route Example
```python
from fastapi import APIRouter, Depends
from src.api.dependencies.redis import get_redis_client
from src.api.dependencies.kafka import get_kafka_manager
from src.services.kafka.manager import KafkaManager

router = APIRouter()

@router.post("/process-data")
async def process_data(
    data: dict,
    redis_client=Depends(get_redis_client),
    kafka_manager: KafkaManager = Depends(get_kafka_manager)
):
    # Cache the data
    redis_client.setex(f"data:{data['id']}", 3600, json.dumps(data))
    
    # Publish event
    await kafka_manager.publish_message("data.processed", data['id'], data)
    
    return {"status": "success"}
```

### Complete Repository Example
```python
from src.repository.crud.base import BaseCRUDRepository
from src.models.db.order import Order

class OrderCRUDRepository(BaseCRUDRepository[Order]):
    def __init__(self, async_session):
        super().__init__(async_session, Order)
    
    # Use base methods
    async def get_order(self, order_id: int):
        return await self.get_by_id(order_id)
    
    async def list_orders(self, skip: int = 0, limit: int = 100):
        return await self.get_all(skip, limit)
    
    # Custom method for Order-specific logic
    async def get_orders_by_status(self, status: str):
        stmt = select(self.model).where(self.model.status == status)
        result = await self.async_session.execute(stmt)
        return list(result.scalars().all())
```

## Best Practices

1. **Always use dependency injection** for Redis and Kafka in route handlers
2. **Extend BaseCRUDRepository** for all new repository classes
3. **Use base methods** whenever possible before writing custom queries
4. **Keep custom logic** in repository-specific methods
5. **Test with mocked dependencies** for unit tests
6. **Document custom methods** clearly in your repository classes

## Files Modified

- `src/repository/crud/base.py` - Enhanced with common CRUD operations
- `src/repository/crud/user.py` - Updated to use enhanced base class
- `src/repository/crud/device.py` - Updated to use enhanced base class
- `src/repository/crud/jwt.py` - Updated to use enhanced base class
- `src/api/routes/example_integration.py` - Updated to use dependency injection
- `src/api/routes/health.py` - Updated to use dependency injection

## Summary

These modularization improvements make the codebase:
- ✅ More maintainable
- ✅ Easier to test
- ✅ More consistent
- ✅ Faster to develop with
- ✅ Following senior developer best practices
- ✅ Using single connections for Redis/Kafka across the entire backend
