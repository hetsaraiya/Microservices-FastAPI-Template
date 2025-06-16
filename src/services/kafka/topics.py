from enum import Enum

class KafkaTopics(str, Enum):
    # Outbound topics (User Service publishes)
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated" 
    USER_DELETED = "user.deleted"
    USER_ROLE_CHANGED = "user.role.changed"
    USER_STATUS_CHANGED = "user.status.changed"
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    
    # Inbound topics (User Service consumes)
    USER_DETAILS_REQUEST = "user.details.request"
    USER_VALIDATION_REQUEST = "user.validation.request"
    USER_PERMISSIONS_REQUEST = "user.permissions.request"
    
    # Response topics
    USER_DETAILS_RESPONSE = "user.details.response"
    USER_VALIDATION_RESPONSE = "user.validation.response"
    USER_PERMISSIONS_RESPONSE = "user.permissions.response"
    
    # System events
    SYSTEM_NOTIFICATION = "system.notification"
    AUDIT_LOG = "audit.log"

# Topic configurations
TOPIC_CONFIGS = {
    KafkaTopics.USER_DETAILS_REQUEST: {
        "num_partitions": 3,
        "replication_factor": 2,
        "retention_ms": 3600000,  # 1 hour
    },
    KafkaTopics.USER_CREATED: {
        "num_partitions": 5,
        "replication_factor": 2,
        "retention_ms": 604800000,  # 7 days
    },
    # Add more topic configs as needed
}