Comparison: Kafka with Zookeeper vs Kafka without Zookeeper (KRaft Mode)
1. Kafka with Zookeeper (Traditional Approach)
In a traditional Kafka setup, Kafka relies on Zookeeper for managing the Kafka cluster. Zookeeper performs key functions like:

Cluster Coordination: It keeps track of Kafka brokers, their status, and the health of the cluster.

Leader Election: For each Kafka partition, Zookeeper manages the leader election, ensuring there is one leader for a partition at any time.

Metadata Storage: Zookeeper stores metadata information like topics, partitions, and replication details.

Advantages of Using Zookeeper:

Proven and Stable: Zookeeper has been used with Kafka for many years and is highly reliable in managing a distributed system.

Fault Tolerance: It helps Kafka maintain data availability and consistency by handling broker failures and partition reassignments.

How to Run Kafka with Zookeeper:

You need to set up both Zookeeper and Kafka as separate services. Kafka depends on Zookeeper for coordination.

Using Docker Compose, both services can be configured and run together. Zookeeper runs on port 2181, and Kafka on port 9093.

Example Docker Compose Setup:

version: '3.8'

services:
  zookeeper:
    image: wurstmeister/zookeeper:3.4.6
    ports:
      - "2181:2181"
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  kafka:
    image: wurstmeister/kafka:latest
    ports:
      - "9093:9093"
    environment:
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
    depends_on:
      - zookeeper
To start the services, run:

docker-compose up
2. Kafka without Zookeeper (KRaft Mode)
KRaft Mode (Kafka Raft mode) was introduced in Kafka 2.8.0 to eliminate the need for Zookeeper. Kafka now takes on the responsibilities that were traditionally handled by Zookeeper, such as:

Cluster Coordination: Kafka itself coordinates the brokers.

Leader Election: Kafka handles leader election for partitions directly.

Metadata Management: Kafka stores metadata internally.

Advantages of KRaft Mode:

Simplified Architecture: No need to run a separate Zookeeper service. Kafka itself manages everything.

Easier Management: The system is simpler to deploy and manage, especially for smaller setups.

More Efficient: Reduces overhead since there’s no need for an additional service (Zookeeper).

How to Run Kafka Without Zookeeper:

Kafka runs as a standalone broker and uses its internal Raft protocol for coordination.

This mode is useful for smaller deployments or environments where a simpler setup is preferred.

Example Docker Command for KRaft Mode:

docker run -d \
  --name=kafka \
  -p 9093:9093 \
  -e KAFKA_ADVERTISED_LISTENER=INSIDE-KAFKA:9093 \
  -e KAFKA_KRAFT_MODE=true \
  -e KAFKA_ZOOKEEPER_CONNECT= \
  confluentinc/cp-kafka:latest
Key Differences:
Feature	Kafka with Zookeeper	Kafka without Zookeeper (KRaft Mode)
Cluster Coordination	Managed by Zookeeper	Managed by Kafka itself
Leader Election	Managed by Zookeeper	Managed by Kafka
Metadata Storage	Stored in Zookeeper	Stored internally by Kafka
Fault Tolerance	High fault tolerance with Zookeeper’s help	Fault tolerance is managed by Kafka
Setup Complexity	Requires both Kafka and Zookeeper services	Simpler, with only Kafka running
Compatibility	Well-established and stable	Newer and evolving feature
Ideal Use Case	Large-scale, multi-broker environments	Smaller, simpler setups or testing

Conclusion:
Kafka with Zookeeper is the traditional and well-established way of running Kafka, especially for large-scale, distributed systems that require high fault tolerance and robust coordination.

Kafka without Zookeeper (KRaft Mode) is an exciting new approach, ideal for simpler setups where you want to eliminate the overhead of managing Zookeeper. It is still evolving, so it’s suitable for testing or small-scale use cases but may require more testing in production environments.

Choose the setup based on your specific use case, scale, and need for simplicity.