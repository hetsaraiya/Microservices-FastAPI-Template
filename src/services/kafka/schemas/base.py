from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

class BaseKafkaMessage(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    service_name: str = "user_service"
    version: str = "1.0"
    
class RequestMessage(BaseKafkaMessage):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    requesting_service: str
    correlation_id: Optional[str] = None
    timeout_seconds: int = 30

class ResponseMessage(BaseKafkaMessage):
    request_id: str
    requesting_service: str
    success: bool = True
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None

class EventMessage(BaseKafkaMessage):
    event_type: str
    entity_id: str
    entity_type: str
    data: Dict[str, Any]
    previous_data: Optional[Dict[str, Any]] = None

# src/services/kafka/schemas/user_events.py
from .base import EventMessage, RequestMessage, ResponseMessage
from typing import Optional, List, Dict, Any

class UserDetailsRequest(RequestMessage):
    user_id: str
    fields_requested: Optional[List[str]] = None  # Specific fields to return

class UserDetailsResponse(ResponseMessage):
    user_details: Optional[Dict[str, Any]] = None

class UserValidationRequest(RequestMessage):
    user_id: str
    action: str  # "create_trip", "access_admin", etc.
    resource: Optional[str] = None

class UserValidationResponse(ResponseMessage):
    is_valid: bool = False
    user_details: Optional[Dict[str, Any]] = None
    permissions: List[str] = []
    roles: List[str] = []

class UserCreatedEvent(EventMessage):
    event_type: str = "user_created"
    entity_type: str = "user"
    
class UserUpdatedEvent(EventMessage):
    event_type: str = "user_updated"
    entity_type: str = "user"