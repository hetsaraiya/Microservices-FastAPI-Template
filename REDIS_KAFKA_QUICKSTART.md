# Redis and Kafka Connection Quick Start

## Quick Test

Test your Redis and Kafka connections:

```bash
python test_connections.py
```

## Start Application

The application will now automatically connect to Redis and Kafka on startup:

```bash
python run.py
```

Or with uvicorn:

```bash
uvicorn src.main:backend_app --host 0.0.0.0 --port 8000 --reload
```

## Check Health

Once running, check service health:

```bash
# Overall health
curl http://localhost:8000/api/v1/health

# Redis health
curl http://localhost:8000/api/v1/health/redis

# Kafka health  
curl http://localhost:8000/api/v1/health/kafka
```

## Environment Setup

Make sure you have Redis and Kafka running. With Docker:

```bash
# Redis
docker run -d --name redis -p 6379:6379 redis:latest

# Kafka (requires Zookeeper)
docker run -d --name zookeeper -p 2181:2181 confluentinc/cp-zookeeper:latest
docker run -d --name kafka -p 9092:9092 --link zookeeper confluentinc/cp-kafka:latest
```

Or use your existing `docker-compose.yaml` if it includes Redis and Kafka services.

## What Happens on Startup

1. ✅ Database connection established
2. ✅ Redis connection attempted and tested
3. ✅ Kafka connection attempted and producer started
4. ✅ Background tasks started (if configured)
5. ✅ Application ready to serve requests

If Redis or Kafka fail to connect, the application will log warnings but continue to run with reduced functionality.

## Usage in Code

```python
from src.services.connections import get_redis_from_app, get_kafka_from_app
from src.services.redis.utils import RedisUtils

# In your route handlers
async def my_route(request: Request):
    # Get Redis client
    redis_client = get_redis_from_app(request.app)
    
    # Or use Redis utils for common operations
    redis_utils = RedisUtils()
    await redis_utils.cache_user_data(user_id, user_data)
    
    # Get Kafka manager
    kafka_manager = get_kafka_from_app(request.app)
    await kafka_manager.publish_message("user.created", {"user_id": "123"})
```

See `src/api/routes/example_integration.py` for detailed examples.
