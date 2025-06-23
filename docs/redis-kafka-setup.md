# Redis and Kafka Connection Setup

This document describes the implemented Redis and Kafka connection management for the User Management Service.

## Overview

The application now automatically connects to Redis and Kafka during startup and gracefully closes these connections during shutdown.

## Changes Made

### 1. Service Connection Management (`src/services/connections.py`)
- Added `initialize_redis_connection()` - Establishes Redis connection at startup
- Added `initialize_kafka_connection()` - Establishes Kafka connection at startup  
- Added `close_redis_connection()` - Closes Redis connection at shutdown
- Added `close_kafka_connection()` - Closes Kafka connection at shutdown
- Added helper functions to retrieve connections from app state

### 2. Kafka Serializers (`src/services/kafka/serializers.py`)
- Created `KafkaSerializer` class for message serialization/deserialization
- Handles JSON encoding/decoding with support for special types (UUID, datetime, Pydantic models)

### 3. Updated Event Handlers (`src/config/events.py`)
- Modified startup event handler to initialize Redis and Kafka connections
- Modified shutdown event handler to properly close all connections
- Added graceful error handling - app continues if connections fail

### 4. Configuration Updates (`src/config/settings/base.py`)
- Added Kafka configuration settings:
  - `KAFKA_BOOTSTRAP_SERVERS`
  - `KAFKA_GROUP_ID`
  - `KAFKA_AUTO_OFFSET_RESET`
  - `KAFKA_ENABLE_AUTO_COMMIT`
  - `KAFKA_SESSION_TIMEOUT_MS`
  - `KAFKA_REQUEST_TIMEOUT_MS`
  - `KAFKA_RETRY_BACKOFF_MS`

### 5. Health Check Endpoint (`src/api/routes/health.py`)
- Added `/health` endpoint for overall service health
- Added `/health/redis` endpoint for Redis-specific health check
- Added `/health/kafka` endpoint for Kafka-specific health check
- Handles cases where services are disabled or unavailable

### 6. Service Exports (`src/services/__init__.py`)
- Updated to export all connection management functions
- Properly organized imports for Redis and Kafka services

## Environment Variables

Add these environment variables to configure the services:

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=          # Optional
REDIS_SSL=false

# Kafka Configuration  
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_GROUP_ID=user_service_group
KAFKA_AUTO_OFFSET_RESET=latest
KAFKA_ENABLE_AUTO_COMMIT=true
KAFKA_SESSION_TIMEOUT_MS=30000
KAFKA_REQUEST_TIMEOUT_MS=40000
KAFKA_RETRY_BACKOFF_MS=100
```

## Testing Connections

Use the provided test script to verify connections:

```bash
python test_connections.py
```

This script will:
- Test Redis connection and basic operations
- Test Kafka connection and producer initialization
- Provide a summary of connection status

## Health Checks

Check service health using the API endpoints:

```bash
# Overall health
curl http://localhost:8000/api/v1/health

# Redis specific health
curl http://localhost:8000/api/v1/health/redis

# Kafka specific health  
curl http://localhost:8000/api/v1/health/kafka
```

## Connection Lifecycle

1. **Startup**: 
   - Database connection is established first
   - Redis connection is attempted
   - Kafka connection is attempted
   - If either Redis or Kafka fails, the app continues with a warning

2. **Runtime**:
   - Connections are stored in `app.state` for access throughout the application
   - Health endpoints can be used to monitor connection status

3. **Shutdown**:
   - All connections are gracefully closed
   - Background tasks are cancelled
   - Cleanup is performed in reverse order of initialization

## Error Handling

- Connection failures during startup are logged but don't prevent the app from starting
- Services that fail to connect are marked as unavailable in app state
- Health endpoints reflect the actual status of each service
- Graceful degradation allows the app to function even if some services are unavailable

## Usage in Application Code

```python
from src.services.connections import get_redis_from_app, get_kafka_from_app

# In route handlers or dependencies
def some_route(request: Request):
    # Get Redis client
    redis_client = get_redis_from_app(request.app)
    
    # Get Kafka manager
    kafka_manager = get_kafka_from_app(request.app)
```

## Docker Compose Integration

The application is designed to work with the existing `docker-compose.yaml` configuration. Make sure Redis and Kafka services are properly configured in your Docker Compose file.
