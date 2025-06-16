# src/services/kafka/handlers/user_request_handler.py
from typing import Dict, Any
import logging
from src.schemas.user_events import (
    UserDetailsRequest, UserDetailsResponse,
    UserValidationRequest, UserValidationResponse
)
from ..manager import kafka_manager
from ..topics import KafkaTopics
from src.repository.crud.user import UserCRUDRepository
from src.api.dependencies.repository import get_async_session

logger = logging.getLogger(__name__)

class UserRequestHandler:
    def __init__(self):
        self.user_crud = UserCRUDRepository()
    
    async def handle_user_details_request(self, message: Dict[str, Any], raw_message):
        """Handle user details request from other services"""
        try:
            request = UserDetailsRequest(**message)
            logger.info(f"Processing user details request: {request.request_id}")
            
            # Get user details from database
            async for session in get_async_session():
                user = await self.user_crud.read_user_by_id(session, request.user_id)
                
                if user:
                    user_details = {
                        "user_id": user.id,
                        "name": user.name,
                        "email": user.email,
                        "phone": user.phone,
                        "role": user.role,
                        "is_active": user.is_active,
                        "permissions": user.permissions or [],
                        "created_at": user.created_at.isoformat(),
                        "last_login": user.last_login.isoformat() if user.last_login else None
                    }
                    
                    # Filter fields if specific fields requested
                    if request.fields_requested:
                        user_details = {
                            k: v for k, v in user_details.items() 
                            if k in request.fields_requested
                        }
                else:
                    user_details = None
                
                # Send response
                response = UserDetailsResponse(
                    request_id=request.request_id,
                    requesting_service=request.requesting_service,
                    success=True,
                    user_details=user_details,
                    correlation_id=request.correlation_id
                )
                
                await kafka_manager.publish(
                    KafkaTopics.USER_DETAILS_RESPONSE,
                    response.dict()
                )
                
        except Exception as e:
            logger.error(f"Error handling user details request: {e}")
            
            # Send error response
            error_response = UserDetailsResponse(
                request_id=message.get("request_id", "unknown"),
                requesting_service=message.get("requesting_service", "unknown"),
                success=False,
                error_message=str(e)
            )
            
            await kafka_manager.publish(
                KafkaTopics.USER_DETAILS_RESPONSE,
                error_response.dict()
            )
    
    async def handle_user_validation_request(self, message: Dict[str, Any], raw_message):
        """Handle user validation request"""
        try:
            request = UserValidationRequest(**message)
            
            async with get_async_session() as session:
                user = await self.user_crud.get_by_id(session, request.user_id)
                
                is_valid = False
                user_details = None
                permissions = []
                roles = []
                
                if user and user.is_active:
                    is_valid = True
                    user_details = {
                        "user_id": user.id,
                        "name": user.name,
                        "email": user.email,
                        "role": user.role
                    }
                    permissions = user.permissions or []
                    roles = [user.role] if user.role else []
                    
                    # Check specific action permissions
                    if request.action:
                        is_valid = await self._check_permission(user, request.action)
                
                response = UserValidationResponse(
                    request_id=request.request_id,
                    requesting_service=request.requesting_service,
                    success=True,
                    is_valid=is_valid,
                    user_details=user_details,
                    permissions=permissions,
                    roles=roles
                )
                
                await kafka_manager.publish(
                    KafkaTopics.USER_VALIDATION_RESPONSE,
                    response.dict()
                )
                
        except Exception as e:
            logger.error(f"Error handling user validation request: {e}")
    
    async def _check_permission(self, user, action: str) -> bool:
        """Check if user has permission for specific action"""
        user_permissions = user.permissions or []
        
        # Define permission mappings
        permission_map = {
            "create_trip": ["user", "driver", "admin"],
            "manage_drivers": ["admin"],
            "view_analytics": ["admin", "manager"],
            "process_payments": ["admin", "finance"]
        }
        
        required_permissions = permission_map.get(action, [])
        return any(perm in user_permissions for perm in required_permissions)

# Initialize handler
user_request_handler = UserRequestHandler()

# Register handlers with Kafka manager
kafka_manager.register_handler(
    KafkaTopics.USER_DETAILS_REQUEST,
    user_request_handler.handle_user_details_request
)

kafka_manager.register_handler(
    KafkaTopics.USER_VALIDATION_REQUEST,
    user_request_handler.handle_user_validation_request
)