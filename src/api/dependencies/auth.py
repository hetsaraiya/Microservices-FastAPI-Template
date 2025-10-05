from typing import List, Optional, Dict, Any

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from src.config.manager import settings
from src.models.db.user import UserTypeEnum, User
from src.models.schemas.jwt import JWTUser
from src.repository.crud.jwt import JwtRecordCRUDRepository
from src.utilities.exceptions.exceptions import AuthorizationHeaderException, SecurityException
from src.securities.authorizations.jwt import jwt_generator
from src.api.dependencies.repository import get_repository
from src.utilities.logging.logger import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_client_ip(request: Request) -> str:
    """Get client IP address from request"""
    if x_forwarded_for := request.headers.get("X-Forwarded-For"):
        # Get the client's IP from the X-Forwarded-For header if behind a proxy
        return x_forwarded_for.split(",")[0].strip()
    elif client_host := getattr(request.client, "host", None):
        # Otherwise get it from the client's host attribute
        return client_host
    return "unknown"


async def verify_token(
    token: str, 
    request: Request,
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
) -> Dict[str, Any]:
    """Verify JWT token and return token information"""
    try:
        # Check if token is blacklisted
        if await jwt_repo.is_jwt_blacklisted(jwt=token):
            raise AuthorizationHeaderException("Token has been revoked")
        
        # Decode token and extract data
        token_data = jwt_generator.retrieve_details_from_token(token)
        
        # Verify IP address if enabled
        client_ip = get_client_ip(request)
        if settings.JWT_IP_CHECK_ENABLED and not await jwt_repo.validate_token_ip(token, client_ip):
            logger.warning(f"IP mismatch detected. Token IP vs Current: {await jwt_repo.get_token_ip(token)} vs {client_ip}")
            raise AuthorizationHeaderException("IP address mismatch - security violation")
        
        # Update last used timestamp
        await jwt_repo.update_last_used(token)
        
        return token_data
        
    except SecurityException as security_error:
        logger.warning(f"Security exception during token verification: {str(security_error)}")
        raise AuthorizationHeaderException(detail=str(security_error))
    except JWTError as jwt_error:
        logger.warning(f"JWT error during token verification: {str(jwt_error)}")
        raise AuthorizationHeaderException(detail="Could not validate credentials")


class RoleChecker:
    """
    Role-based access control dependency.
    Use this to protect routes based on user roles.
    """
    def __init__(self, allowed_roles: List[UserTypeEnum]):
        self.allowed_roles = allowed_roles

    async def __call__(
        self, 
        request: Request,
        token: str = Depends(oauth2_scheme),
        jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
    ):
        # Verify token first
        token_data = await verify_token(token, request, jwt_repo)
        
        # Check if user's role is in allowed roles
        user_type = token_data.get("user_type", "RIDER")
        
        if not any(role.value == user_type for role in self.allowed_roles):
            logger.warning(f"Unauthorized access attempt: User with role {user_type} tried to access resource requiring {self.allowed_roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return token_data


# Predefined role checkers for convenience
def admin_required():
    return RoleChecker([UserTypeEnum.ADMIN])


def driver_required():
    return RoleChecker([UserTypeEnum.DRIVER])


def rider_required():
    return RoleChecker([UserTypeEnum.RIDER])


def rider_or_driver_required():
    return RoleChecker([UserTypeEnum.RIDER, UserTypeEnum.DRIVER])