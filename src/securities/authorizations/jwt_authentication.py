from functools import wraps
from typing import Optional, Dict, Any

from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, OAuth2PasswordBearer
from jose import JWTError as JoseJWTError
from fastapi.security import HTTPBearer
from fastapi.security.utils import get_authorization_scheme_param
import sqlalchemy

from src.repository.crud.jwt import JwtRecordCRUDRepository
from src.utilities.exceptions.exceptions import AuthorizationHeaderException, SecurityException
from src.securities.authorizations.jwt import jwt_generator
from src.repository.crud.user import UserCRUDRepository
from src.api.dependencies.repository import get_repository
from src.models.db.user import User
from src.config.manager import settings
from src.api.dependencies.auth import get_client_ip, get_device_info
from src.repository.database import async_db


class CustomHTTPBearer(HTTPBearer):
    async def __call__(
        self, request: Request
    ) -> Optional[HTTPAuthorizationCredentials]:
        authorization = request.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise AuthorizationHeaderException("sign_in_required")
            else:
                return None
        if scheme.lower() != "bearer":
            if self.auto_error:
                raise AuthorizationHeaderException("session_expired_or_closed")
            else:
                return None
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)

security = CustomHTTPBearer()


class CustomOAuth2PasswordBearer(OAuth2PasswordBearer):
    def __init__(self, token_url: str, param_name: str = "Authorization"):
        super().__init__(token_url)
        self.param_name = param_name

    async def __call__(self, request: Request) -> str:
        authorization: str = request.headers.get(self.param_name)

        if authorization is None:
            raise AuthorizationHeaderException("AUTH_TOKEN_MISSING")

        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            raise AuthorizationHeaderException(
                detail="AUTH_TOKEN_MISSING",
            )

        return token


async def get_current_user(user_id: int) -> User:
    """Get user by ID"""
    async for async_session in async_db.get_session():
        stmt = sqlalchemy.select(User).where(User.id == user_id, User.is_active == True)
        result = await async_session.execute(statement=stmt)
        return result.scalar_one_or_none()


async def get_user_by_email(email: str) -> User:
    """Get user by email"""
    async for async_session in async_db.get_session():
        stmt = sqlalchemy.select(User).where(User.email == email, User.is_active == True)
        result = await async_session.execute(statement=stmt)
        return result.scalar_one_or_none()


async def jwt_authentication(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
) -> Dict[str, Any]:
    """JWT Authentication middleware that extracts and validates the JWT token"""
    token = credentials.credentials
    if token is None:
        raise AuthorizationHeaderException('sign_in_required')
    
    # Check if token is blacklisted
    if await jwt_repo.is_jwt_blacklisted(jwt=token):
        raise AuthorizationHeaderException('session_expired_or_closed')

    try:
        # Get IP address
        client_ip = get_client_ip(request)
        
        # Decode token
        token_data = jwt_generator.retrieve_details_from_token(token)
        user_id = token_data.get("user_id")
        email = token_data.get("email")
        device_id = token_data.get("device_id")
        
        # Verify user exists
        current_user = await get_current_user(user_id=user_id)
        if not current_user:
            raise AuthorizationHeaderException(detail='sign_in_required')
            
        # Verify IP address (if enabled)
        if settings.JWT_IP_CHECK_ENABLED and not await jwt_repo.validate_token_ip(token, client_ip):
            # Handle suspicious activity (you might want to log this or perform additional security actions)
            raise AuthorizationHeaderException("Security alert: IP address mismatch")
        
        # Update token last used time
        await jwt_repo.update_last_used(token)
        
        # Add user and token data to request state for later use
        request.state.user = current_user
        request.state.token_data = token_data
        request.state.device_id = device_id

        return {
            "user": current_user,
            "token_data": token_data
        }
        
    except SecurityException as security_error:
        raise AuthorizationHeaderException(detail=str(security_error))
    except Exception as e:
        raise AuthorizationHeaderException(detail='sign_in_required')
