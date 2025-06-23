from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.admin import AIOKafkaAdminClient
from aiokafka.admin.new_topic import NewTopic
import json
import asyncio
from typing import Dict, List, Callable, Optional
import logging
from .config import kafka_config
from .topics import KafkaTopics, TOPIC_CONFIGS
from .serializers import KafkaSerializer

logger = logging.getLogger(__name__)

class KafkaManager:
    def __init__(self):
        self.config = kafka_config
        self.producer: Optional[AIOKafkaProducer] = None
        self.consumers: Dict[str, AIOKafkaConsumer] = {}
        self.handlers: Dict[str, List[Callable]] = {}
        self.serializer = KafkaSerializer()
        self._running = False
    
    async def start(self):
        """Initialize Kafka producer and consumers"""
        try:
            # Start producer
            await self._start_producer()
            
            # Create topics if they don't exist
            await self._create_topics()
            
            # Start consumers
            await self._start_consumers()
            
            self._running = True
            logger.info("Kafka manager started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Kafka manager: {e}")
            raise
    
    async def stop(self):
        """Stop all Kafka connections"""
        self._running = False
        
        if self.producer:
            await self.producer.stop()
        
        for consumer in self.consumers.values():
            await consumer.stop()
        
        logger.info("Kafka manager stopped")
    
    async def _start_producer(self):
        """Start Kafka producer"""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.config.bootstrap_servers,
            value_serializer=self.serializer.serialize,
            key_serializer=lambda x: x.encode() if x else None,
            retry_backoff_ms=self.config.retry_backoff_ms,
            request_timeout_ms=self.config.request_timeout_ms
        )
        await self.producer.start()
        logger.info("Kafka producer started")
    
    async def _start_consumers(self):
        """Start Kafka consumers for different topic groups"""
        
        # Consumer for handling requests from other services
        request_consumer = AIOKafkaConsumer(
            KafkaTopics.USER_DETAILS_REQUEST,
            KafkaTopics.USER_VALIDATION_REQUEST,
            KafkaTopics.USER_PERMISSIONS_REQUEST,
            bootstrap_servers=self.config.bootstrap_servers,
            group_id=f"{self.config.group_id}_requests",
            value_deserializer=self.serializer.deserialize,
            auto_offset_reset=self.config.auto_offset_reset
        )
        
        await request_consumer.start()
        self.consumers["requests"] = request_consumer
        
        # Start background task to process messages
        asyncio.create_task(self._consume_messages("requests"))
        
        logger.info("Kafka consumers started")
    
    async def _create_topics(self):
        """Create Kafka topics if they don't exist"""
        admin_client = AIOKafkaAdminClient(
            bootstrap_servers=self.config.bootstrap_servers
        )
        
        try:
            await admin_client.start()
            
            # Get existing topics
            existing_topics = set(await admin_client.list_topics())
            
            # Create missing topics
            topics_to_create = []
            for topic, config in TOPIC_CONFIGS.items():
                if topic not in existing_topics:
                    new_topic = NewTopic(
                        name=topic,
                        num_partitions=config.get("num_partitions", 1),
                        replication_factor=config.get("replication_factor", 1)
                    )
                    topics_to_create.append(new_topic)
            
            if topics_to_create:
                await admin_client.create_topics(topics_to_create)
                logger.info(f"Created {len(topics_to_create)} topics")
            
        finally:
            await admin_client.close()
    
    async def publish(self, topic: str, message: dict, key: Optional[str] = None):
        """Publish message to Kafka topic"""
        if not self.producer:
            raise RuntimeError("Producer not initialized")
        
        try:
            await self.producer.send_and_wait(topic, message, key=key)
            logger.debug(f"Published message to {topic}")
            
        except Exception as e:
            logger.error(f"Failed to publish to {topic}: {e}")
            raise
    
    async def publish_message(self, topic: str, message: dict, key: str = None):
        """
        Publish a message to a Kafka topic
        
        Args:
            topic: The topic to publish to
            message: The message data to publish
            key: Optional message key for partitioning
        """
        if not self.producer:
            raise RuntimeError("Kafka producer not initialized")
        
        try:
            await self.producer.send_and_wait(
                topic=topic,
                value=message,
                key=key
            )
            logger.info(f"Message published to topic {topic}")
            
        except Exception as e:
            logger.error(f"Failed to publish message to {topic}: {e}")
            raise
    
    def register_handler(self, topic: str, handler: Callable):
        """Register message handler for a topic"""
        if topic not in self.handlers:
            self.handlers[topic] = []
        self.handlers[topic].append(handler)
        logger.info(f"Registered handler for topic: {topic}")
    
    async def _consume_messages(self, consumer_group: str):
        """Background task to consume and process messages"""
        consumer = self.consumers[consumer_group]
        
        try:
            async for message in consumer:
                if not self._running:
                    break
                
                topic = message.topic
                handlers = self.handlers.get(topic, [])
                
                for handler in handlers:
                    try:
                        await handler(message.value, message)
                    except Exception as e:
                        logger.error(f"Handler error for {topic}: {e}")
                        
        except Exception as e:
            logger.error(f"Consumer error in {consumer_group}: {e}")

# Global instance
kafka_manager = KafkaManager()