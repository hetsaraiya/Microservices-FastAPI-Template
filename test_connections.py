#!/usr/bin/env python3
"""
Connection Test Script

This script tests Redis and Kafka connections independently 
to help debug connection issues during application startup.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config.manager import settings
from src.services.redis.client import get_redis_client
from src.services.kafka.manager import KafkaManager
from src.utilities.logging.logger import logger


async def test_redis_connection():
    """Test Redis connection"""
    try:
        logger.info(f"Testing Redis connection to {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        redis_client = get_redis_client()
        
        # Test with a simple ping
        await asyncio.to_thread(redis_client.ping)
        logger.success("✅ Redis connection successful!")
        
        # Test basic operations
        await asyncio.to_thread(redis_client.set, "test_key", "test_value", ex=10)
        value = await asyncio.to_thread(redis_client.get, "test_key")
        logger.info(f"✅ Redis operations test successful! Value: {value}")
        
        # Cleanup
        await asyncio.to_thread(redis_client.delete, "test_key")
        redis_client.close()
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Redis connection failed: {e}")
        return False


async def test_kafka_connection():
    """Test Kafka connection"""
    try:
        from src.services.kafka.config import kafka_config
        logger.info(f"Testing Kafka connection to {kafka_config.bootstrap_servers}")
        
        kafka_manager = KafkaManager()
        
        # Start Kafka manager
        await kafka_manager.start()
        logger.success("✅ Kafka connection successful!")
        
        # Test if producer is working
        if kafka_manager.producer:
            logger.info("✅ Kafka producer initialized successfully!")
        else:
            logger.warning("⚠️ Kafka producer not initialized")
        
        # Stop Kafka manager
        await kafka_manager.stop()
        logger.info("✅ Kafka disconnected successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Kafka connection failed: {e}")
        return False


async def main():
    """Main test function"""
    logger.info("🚀 Starting connection tests...")
    
    # Test Redis
    redis_ok = await test_redis_connection()
    
    # Test Kafka  
    kafka_ok = await test_kafka_connection()
    
    # Summary
    logger.info("=" * 50)
    logger.info("CONNECTION TEST SUMMARY:")
    logger.info(f"Redis:  {'✅ PASS' if redis_ok else '❌ FAIL'}")
    logger.info(f"Kafka:  {'✅ PASS' if kafka_ok else '❌ FAIL'}")
    logger.info("=" * 50)
    
    if redis_ok and kafka_ok:
        logger.success("🎉 All connections successful!")
        return 0
    else:
        logger.error("💥 Some connections failed!")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)