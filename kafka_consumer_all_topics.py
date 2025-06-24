import asyncio
from aiokafka import AIOKafkaConsumer

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"  # Change if your broker is different
GROUP_ID = "all_topics_consumer_group"

async def consume():
    consumer = AIOKafkaConsumer(
        # No topics here, will subscribe below
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )
    await consumer.start()
    try:
        # Subscribe to all topics using regex pattern (no await)
        consumer.subscribe(pattern=".*")
        topics = await consumer.topics()
        print(f"Name of all the topics are: {topics}")
        print("Subscribed to all topics. Waiting for messages...")
        while True:
            result = await consumer.getmany(timeout_ms=1000)
            for tp, messages in result.items():
                for msg in messages:
                    print(f"[Topic: {tp.topic}] [Partition: {tp.partition}] [Offset: {msg.offset}] Value: {msg.value.decode(errors='replace')}")
    finally:
        await consumer.stop()

if __name__ == "__main__":
    asyncio.run(consume())
