import json
import logging
from typing import Any, Optional
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class KafkaSerializer:
    """Kafka message serializer/deserializer"""
    
    def serialize(self, value: Any) -> Optional[bytes]:
        """
        Serialize a value to bytes for Kafka
        
        Args:
            value: The value to serialize
            
        Returns:
            bytes: Serialized value
        """
        if value is None:
            return None
            
        try:
            # Handle different types
            if isinstance(value, (dict, list)):
                json_str = json.dumps(value, default=self._json_default)
            elif isinstance(value, str):
                json_str = value
            else:
                json_str = json.dumps(value, default=self._json_default)
                
            return json_str.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to serialize value: {e}")
            raise
    
    def deserialize(self, value: Optional[bytes]) -> Any:
        """
        Deserialize bytes from Kafka to a Python object
        
        Args:
            value: The bytes to deserialize
            
        Returns:
            Any: Deserialized value
        """
        if value is None:
            return None
            
        try:
            json_str = value.decode('utf-8')
            return json.loads(json_str)
            
        except Exception as e:
            logger.error(f"Failed to deserialize value: {e}")
            # Return the raw string if JSON parsing fails
            return value.decode('utf-8') if isinstance(value, bytes) else value
    
    def _json_default(self, obj: Any) -> Any:
        """
        Default JSON serializer for special types
        
        Args:
            obj: Object to serialize
            
        Returns:
            Any: Serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif hasattr(obj, 'model_dump'):  # Pydantic v2
            return obj.model_dump()
        elif hasattr(obj, 'dict') and callable(obj.dict):  # Pydantic v1
            return obj.dict()
        else:
            return str(obj)
