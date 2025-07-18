import uuid
from fastapi import APIRouter, Depends, status, Request, HTTPException
import pydantic

from src.api.dependencies.repository import get_repository
from src.api.dependencies.kafka import get_kafka_manager
from src.models.db.user import UserTypeEnum
from src.models.schemas.user import UserInResponse, UserInUpdate, UserWithToken
from src.services.kafka.topics import KafkaTopics
from src.services.kafka.manager import KafkaManager
from src.repository.crud.user import UserCRUDRepository
from src.securities.authorizations.jwt import jwt_generator
from src.utilities.exceptions.database import EntityDoesNotExist
from src.utilities.exceptions.http.exc_404 import (
    http_404_exc_email_not_found_request,
    http_404_exc_id_not_found_request,
    http_404_exc_username_not_found_request,
)
from src.api.dependencies.auth import oauth2_scheme, verify_token
from src.repository.crud.jwt import JwtRecordCRUDRepository
from src.utilities.logging.logger import logger
from src.services.connections import get_kafka_from_app
from src.services.kafka.topics import KafkaTopics

router = APIRouter(prefix="/users", tags=["users"])

# Dependency for Kafka manager
from fastapi import Depends

def get_kafka_manager(request: Request):
    return get_kafka_from_app(request.app)

# Add new /me endpoint
@router.get(
    path="/me",
    name="users:read-current-user",
    status_code=status.HTTP_200_OK,
)
async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Get current authenticated user information"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        
        # Get user from database
        db_user = await user_repo.read_user_by_id(id=user_id)
        
        # Return user information in the format expected by the Flutter client
        return {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
            "userType": db_user.user_type,
            "isVerified": db_user.is_verified,
            "isActive": db_user.is_active,
            "isLoggedIn": db_user.is_logged_in,
            "createdAt": db_user.created_at,
            "updatedAt": db_user.updated_at
        }
        
    except EntityDoesNotExist:
        logger.error(f"User not found in database for token user_id: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    except Exception as e:
        logger.error(f"Error retrieving current user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        )


@router.get(
    path="",
    name="users:read-users",
    response_model=list[UserInResponse],
    status_code=status.HTTP_200_OK,
)
async def get_users(
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
) -> list[UserInResponse]:
    db_users = await user_repo.read_users()
    db_user_list: list = list()

    for db_user in db_users:
        access_token = jwt_generator.generate_access_token(user=db_user)
        user = UserInResponse(
            id=db_user.id,
            authorized_user=UserWithToken(
                token=access_token,
                username=db_user.username,
                email=db_user.email,  # type: ignore
                user_type=db_user.user_type,
                is_verified=db_user.is_verified,
                is_active=db_user.is_active,
                is_logged_in=db_user.is_logged_in,
                created_at=db_user.created_at,
                updated_at=db_user.updated_at,
            ),
        )
        db_user_list.append(user)

    return db_user_list


@router.get(
    path="/{id}",
    name="users:read-user-by-id",
    response_model=UserInResponse,
    status_code=status.HTTP_200_OK,
)
async def get_user(
    id: uuid.UUID,
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
) -> UserInResponse:
    try:
        db_user = await user_repo.read_user_by_id(id=id)
        access_token = jwt_generator.generate_access_token(user=db_user)

    except EntityDoesNotExist:
        raise await http_404_exc_id_not_found_request(id=id)

    return UserInResponse(
        id=db_user.id,
        authorized_user=UserWithToken(
            token=access_token,
            username=db_user.username,
            email=db_user.email,  # type: ignore
            user_type=db_user.user_type,
            is_verified=db_user.is_verified,
            is_active=db_user.is_active,
            is_logged_in=db_user.is_logged_in,
            created_at=db_user.created_at,
            updated_at=db_user.updated_at,
        ),
    )


@router.patch(
    path="/{id}",
    name="users:update-user-by-id",
    response_model=UserInResponse,
    status_code=status.HTTP_200_OK,
)
async def update_user(
    query_id: uuid.UUID,
    update_username: str | None = None,
    update_email: pydantic.EmailStr | None = None,
    update_password: str | None = None,
    update_user_type: UserTypeEnum | None = None,
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
    kafka_manager: KafkaManager = Depends(get_kafka_manager),
) -> UserInResponse:
    user_update = UserInUpdate(
        username=update_username, 
        email=update_email, 
        password=update_password,
        user_type=update_user_type
    )
    try:
        updated_db_user = await user_repo.update_user_by_id(id=query_id, user_update=user_update)

        # Publish user updated event to Kafka
        try:
            await kafka_manager.publish_message(
                KafkaTopics.USER_UPDATED.value,
                {
                    "user_id": str(updated_db_user.id),
                    "username": updated_db_user.username,
                    "email": updated_db_user.email,
                    "user_type": updated_db_user.user_type,
                    "updated_at": updated_db_user.updated_at.isoformat(),
                    "event_type": "user_updated"
                }
            )
            logger.info(f"Published user updated event for user {updated_db_user.id}")
        except Exception as kafka_error:
            logger.error(f"Failed to publish user updated event: {kafka_error}")
            # Continue with the response even if Kafka fails

    except EntityDoesNotExist:
        raise await http_404_exc_id_not_found_request(id=query_id)

    access_token = jwt_generator.generate_access_token(user=updated_db_user)

    return UserInResponse(
        id=updated_db_user.id,
        authorized_user=UserWithToken(
            token=access_token,
            username=updated_db_user.username,
            email=updated_db_user.email,  # type: ignore
            user_type=updated_db_user.user_type,
            is_verified=updated_db_user.is_verified,
            is_active=updated_db_user.is_active,
            is_logged_in=updated_db_user.is_logged_in,
            created_at=updated_db_user.created_at,
            updated_at=updated_db_user.updated_at,
        ),
    )


@router.delete(path="", name="users:delete-user-by-id", status_code=status.HTTP_200_OK)
async def delete_user(
    id: uuid.UUID, 
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
    kafka_manager: KafkaManager = Depends(get_kafka_manager)
) -> dict[str, str]:
    try:
        # Get user before deletion for Kafka event
        db_user = await user_repo.read_user_by_id(id=id)
        
        deletion_result = await user_repo.delete_user_by_id(id=id)
        
        # Publish user deleted event to Kafka
        try:
            await kafka_manager.publish_message(
                KafkaTopics.USER_DELETED.value,
                {
                    "user_id": str(db_user.id),
                    "username": db_user.username,
                    "email": db_user.email,
                    "user_type": db_user.user_type,
                    "deleted_at": db_user.updated_at.isoformat(),
                    "event_type": "user_deleted"
                }
            )
            logger.info(f"Published user deleted event for user {db_user.id}")
        except Exception as kafka_error:
            logger.error(f"Failed to publish user deleted event: {kafka_error}")
            # Continue with the response even if Kafka fails

    except EntityDoesNotExist:
        raise await http_404_exc_id_not_found_request(id=id)

    return {"notification": deletion_result}


# Example: Publish a Kafka event when a user is updated
@router.post(
    path="/{id}/publish-event",
    name="users:publish-user-event",
    status_code=status.HTTP_200_OK,
)
async def publish_user_event(
    id: uuid.UUID,
    event_data: dict,
    kafka_manager: KafkaManager = Depends(get_kafka_manager)
):
    try:
        await kafka_manager.publish_message(
            KafkaTopics.USER_UPDATED.value,
            {"user_id": str(id), **event_data}
        )
        return {"message": "User event published to Kafka"}
    except Exception as e:
        logger.error(f"Failed to publish user event: {e}")
        raise HTTPException(status_code=500, detail="Failed to publish user event")
