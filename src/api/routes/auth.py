from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Body
from pydantic import BaseModel, EmailStr
from datetime import datetime
import uuid
import time

from src.api.dependencies.repository import get_repository
from src.api.dependencies.auth import (
    get_client_ip,
    verify_token,
    oauth2_scheme
)
from src.models.schemas.jwt import JWTResponse
from src.models.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    ActivityResponse
)
from src.repository.crud.user import UserCRUDRepository
from src.repository.crud.jwt import JwtRecordCRUDRepository
from src.securities.authorizations.jwt import jwt_generator
from src.config.manager import settings
from src.utilities.exceptions.database import EntityAlreadyExists
from src.utilities.exceptions.exceptions import SecurityException
from src.utilities.logging.logger import logger
from src.models.schemas.user import UserInLogin, UserInCreate
from src.models.db.user import UserTypeEnum

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/register", response_model=JWTResponse)
async def register(
    request: Request,
    register_data: RegisterRequest,
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Register a new user and return authentication tokens"""
    try:
        # Map the role to UserTypeEnum
        user_type = UserTypeEnum.RIDER  # Default
        if register_data.role.lower() == "driver":
            user_type = UserTypeEnum.DRIVER

        # Check if username or email already exists
        try:
            await user_repo.is_username_taken(register_data.username)
            await user_repo.is_email_taken(register_data.email)
        except EntityAlreadyExists as e:
            logger.error(f"User validation error: {str(e)}")
            raise e

        # Create user model for database
        user_create = UserInCreate(
            username=register_data.username,
            email=register_data.email,
            password=register_data.password,
            user_type=user_type
        )

        # Create the user in database
        new_user = await user_repo.create_user(user_create=user_create)
        
        # Store phone number and any other extra fields in user_metadata if your model supports it
        # Assuming you might want to add a way to store this in future
        
        # Calculate token expiration time
        expiration_time = settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60
            
        # Generate JWT token
        access_token, expires_in = jwt_generator.generate_access_token(new_user)
        
        # Generate a refresh token if configured
        refresh_token, refresh_token_expires_in = jwt_generator.generate_refresh_token(new_user)

        # Store refresh token
        await jwt_repo.create_jwt_record(
            jwt=refresh_token,
            user_id=new_user.id,
            token_type="refresh",
            expires_in=refresh_token_expires_in
        )
        
        # Store access token in database
        await jwt_repo.create_jwt_record(
            jwt=access_token,
            user_id=new_user.id,
            token_type="access",
            expires_in=expiration_time
        )
        
        # Log successful registration
        logger.info(f"New user registered: {new_user.username} (ID: {new_user.id}, Type: {new_user.user_type})")
        
        # Return response with tokens
        return JWTResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            refresh_token=refresh_token
        )
        
    except EntityAlreadyExists as e:
        # Explicitly handle this exception
        logger.error(f"User validation error: {str(e)}")
        raise e
    except HTTPException as e:
        # Forward HTTP exceptions
        logger.error(f"Registration error: {str(e)}")
        raise e
    except Exception as e:
        # Catch all other exceptions
        logger.error(f"Registration error: {str(e)}")
        raise e


@router.post("/login", response_model=JWTResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository)),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Login endpoint for user authentication"""
    try:
        print(f"Login data: {request.json()}")
        # Authenticate user
        user_login = UserInLogin(
            username=login_data.username,
            password=login_data.password
        )
        logger.info(f"Attempting login for user: {user_login.username}")
        user = await user_repo.read_user_by_password_authentication(user_login=user_login)
        
        # Get current IP address
        current_ip = get_client_ip(request)
            
        # Calculate token expiration time
        expiration_time = settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60
            
        # Generate JWT token
        access_token, expires_in = jwt_generator.generate_access_token(user)
        
        # Generate a refresh token if configured
        refresh_token = None
        if settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME > 0:
            refresh_token, _ = jwt_generator.generate_refresh_token(user)
            refresh_expiry = settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME * 24 * 60 * 60  # Convert days to seconds
            
            # Store refresh token
            await jwt_repo.create_jwt_record(
                jwt=refresh_token,
                user_id=user.id,
                token_type="refresh",
                expires_in=refresh_expiry
            )
        
        # Store access token in database
        await jwt_repo.create_jwt_record(
            jwt=access_token,
            user_id=user.id,
            token_type="access",
            expires_in=expiration_time
        )
        
        # Return response with tokens
        response = JWTResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in
        )
        
        if refresh_token:
            response.refresh_token = refresh_token
        
        return response
        
    except SecurityException as security_error:
        logger.warning(f"Security exception during login: {str(security_error)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(security_error),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/refresh-token", response_model=JWTResponse)
async def refresh_token(
    request: Request,
    refresh_token: str = Body(..., embed=True),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository)),
    user_repo: UserCRUDRepository = Depends(get_repository(repo_type=UserCRUDRepository))
):
    """Refresh an access token using a refresh token"""
    try:
        # Verify refresh token
        token_data = jwt_generator.retrieve_details_from_token(refresh_token)
        
        # Check if token is blacklisted
        if await jwt_repo.is_jwt_blacklisted(jwt=refresh_token):
            raise SecurityException("Refresh token has been revoked")
        
        # Get the token record
        token_record = await jwt_repo.get_token_record(refresh_token)
        if not token_record or token_record.token_type != "refresh":
            raise SecurityException("Invalid refresh token")
        
        # Get user
        user_id = token_data.get("user_id")
        user = await user_repo.read_user_by_id(id=user_id)
        
        # Generate new access token
        access_token, expires_in = jwt_generator.generate_access_token(user)
        
        # Store new access token
        await jwt_repo.create_jwt_record(
            jwt=access_token,
            user_id=user.id,
            token_type="access",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60
        )
        
        # Log the token refresh
        logger.info(f"Refreshed token for user {user.username}")
        
        return JWTResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            refresh_token=refresh_token  # Return the same refresh token
        )
        
    except SecurityException as security_error:
        logger.warning(f"Security exception during token refresh: {str(security_error)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(security_error),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout")
async def logout(
    request: Request,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Logout current session"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        
        # Blacklist the token
        await jwt_repo.blacklist_jwt(jwt=token)
        
        user_id = token_data.get("user_id")
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/activity", response_model=ActivityResponse)
async def get_user_activity(
    request: Request,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Get user login activity, including suspicious activity detection"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        
        # Get recent activity
        recent = await jwt_repo.get_recent_activity(user_id)
        recent_activity = [
            {
                "timestamp": record["timestamp"],
                "device_name": record.get("user_agent", "Unknown"),
                "device_type": "web",  # Default since we don't track device types anymore
                "ip_address": record["ip_address"],
                "location": {
                    "country": record.get("country"),
                    "city": record.get("city")
                } if record.get("country") else None,
                "is_android": False,  # Default since we don't track this anymore
                "model": None,
                "os_version": None
            }
            for record in recent
        ]
        
        # Get suspicious activity
        suspicious_activity = await jwt_repo.get_suspicious_activity(user_id)
        
        return ActivityResponse(
            recent_activity=recent_activity,
            suspicious_activity=suspicious_activity
        )
        
    except Exception as e:
        logger.error(f"Get activity error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving activity data"
        )
