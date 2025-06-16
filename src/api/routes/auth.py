from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Body
from pydantic import BaseModel, EmailStr

from src.api.dependencies.repository import get_repository
from src.api.dependencies.auth import (
    get_client_ip,
    get_device_info,
    verify_token,
    oauth2_scheme
)
from src.models.schemas.jwt import DeviceInfo, JWTResponse
from src.models.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    DeviceListResponse,
    DeviceDetailResponse,
    UpdateDeviceInfoRequest,
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
        
        # Get device info from request and client data
        print("Register data:", register_data)
        device_info = get_device_info(request, register_data.device_id, register_data.client_data)
        
        # Calculate token expiration time
        expiration_time = settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60
            
        # Generate JWT token
        access_token, expires_in, device_id = jwt_generator.generate_access_token(new_user, device_info)
        
        # Generate a refresh token if configured
        refresh_token, refresh_token_expires_in, _ = jwt_generator.generate_refresh_token(new_user, device_info)

        # Store refresh token
        await jwt_repo.create_jwt_record(
            jwt=refresh_token,
            user_id=new_user.id,
            device_info=device_info,
            token_type="refresh",
            expires_in=refresh_token_expires_in
        )
        
        # Store access token in database with device info
        await jwt_repo.create_jwt_record(
            jwt=access_token,
            user_id=new_user.id,
            device_info=device_info,
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
            device_id=device_id,
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
    """Login endpoint that supports device-based authentication with enhanced device information"""
    try:
        print(f"Login data: {request.json()}")
        # Authenticate user
        user_login = UserInLogin(
            username=login_data.username,
            password=login_data.password
        )
        logger.info(f"Attempting login for user: {user_login.username}")
        user = await user_repo.read_user_by_password_authentication(user_login=user_login)
        
        # Get device info from request and client data
        device_info = get_device_info(request, login_data.device_id, login_data.client_data)
        
        # Log information about Android devices
        if device_info.device_type == "android":
            logger.info(
                f"Android login: {device_info.manufacturer} {device_info.model}, "
                f"OS: {device_info.os_version}, "
                f"Android ID: {device_info.android_id or 'not provided'}, "
                f"Rooted: {device_info.is_rooted or 'unknown'}"
            )
        
        # Get current IP address
        current_ip = get_client_ip(request)
        
        # Check if user has reached maximum number of devices
        user_devices = await jwt_repo.get_user_active_devices(user.id)
        
        # Check if this is a returning device by device_id, IP address, or device_hash
        is_returning_device = any(
            d.device_id == device_info.device_id or 
            d.ip_address == current_ip or
            d.device_hash == device_info.device_hash
            for d in user_devices
        )
        
        if len(user_devices) >= settings.JWT_MAX_DEVICES and not is_returning_device:
            # If max devices reached and this is a new device, require logging out from another device
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum number of devices ({settings.JWT_MAX_DEVICES}) reached. Please log out from another device."
            )
            
        # Calculate token expiration time
        expiration_time = settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60
            
        # Generate JWT token
        access_token, expires_in, device_id = jwt_generator.generate_access_token(user, device_info)
        
        # Generate a refresh token if configured
        refresh_token = None
        if settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME > 0:
            refresh_token, _, _ = jwt_generator.generate_refresh_token(user, device_info)
            refresh_expiry = settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME * 24 * 60 * 60  # Convert days to seconds
            
            # Store refresh token
            await jwt_repo.create_jwt_record(
                jwt=refresh_token,
                user_id=user.id,
                device_info=device_info,
                token_type="refresh",
                expires_in=refresh_expiry
            )
        
        # Store access token in database with device info
        await jwt_repo.create_jwt_record(
            jwt=access_token,
            user_id=user.id,
            device_info=device_info,
            token_type="access",
            expires_in=expiration_time
        )
        
        # Return response with tokens
        response = JWTResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            device_id=device_id
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
        
        # Get device info from the refresh token record
        device_info = DeviceInfo(
            device_id=token_record.device_id,
            device_name=token_record.device_name,
            device_type=token_record.device_type,
            ip_address=token_record.ip_address,
            user_agent=token_record.user_agent,
            manufacturer=token_record.manufacturer,
            model=token_record.model,
            os_version=token_record.os_version,
            app_version=token_record.app_version,
            screen_resolution=token_record.screen_resolution,
            network_type=token_record.network_type,
            device_language=token_record.device_language,
            battery_level=token_record.battery_level,
            is_rooted=token_record.is_rooted,
            android_id=token_record.android_id,
            device_hash=token_record.device_hash,
        )
        
        # Generate new access token
        access_token, expires_in, device_id = jwt_generator.generate_access_token(user, device_info)
        
        # Store new access token
        await jwt_repo.create_jwt_record(
            jwt=access_token,
            user_id=user.id,
            device_info=device_info,
            token_type="access",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60
        )
        
        # Log the token refresh
        logger.info(f"Refreshed token for user {user.username} on device {device_info.device_name} ({device_info.device_id})")
        
        return JWTResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            device_id=device_id,
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
    """Logout from current device"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        
        # Blacklist the token
        await jwt_repo.blacklist_jwt(jwt=token)
        
        # Also blacklist any refresh tokens for this device
        device_id = token_data.get("device_id")
        user_id = token_data.get("user_id")
        if device_id and user_id:
            await jwt_repo.blacklist_device_tokens(user_id, device_id)
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout-all-devices")
async def logout_all_devices(
    request: Request,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Logout from all devices"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        
        # Blacklist all user tokens
        count = await jwt_repo.blacklist_all_user_tokens(user_id)
        
        return {"message": f"Successfully logged out from all devices", "device_count": count}
        
    except Exception as e:
        logger.error(f"Logout from all devices error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout-device")
async def logout_device(
    request: Request,
    device_id: str = Body(..., embed=True),
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Logout from a specific device"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        
        # Blacklist device tokens
        count = await jwt_repo.blacklist_device_tokens(user_id, device_id)
        
        if count == 0:
            return {"message": "Device not found or already logged out"}
        
        return {"message": "Successfully logged out from device"}
        
    except Exception as e:
        logger.error(f"Logout device error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/devices", response_model=DeviceListResponse)
async def get_devices(
    request: Request,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Get all active devices for the current user"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        current_device_id = token_data.get("device_id")
        
        # Get user devices
        devices = await jwt_repo.get_user_active_devices(user_id)
        
        # Format device data
        device_list = [
            {
                "device_id": device.device_id,
                "device_name": device.device_name or "Unknown device",
                "device_type": device.device_type or "unknown",
                "manufacturer": device.manufacturer,
                "model": device.model,
                "os_version": device.os_version,
                "last_active": device.last_used_at,
                "ip_address": device.ip_address,
                "location": {
                    "country": device.country_code,
                    "region": device.region,
                    "city": device.city
                } if device.country_code else None,
                "is_current": device.device_id == current_device_id,
                "is_android": device.device_type == "android"
            }
            for device in devices
        ]
        
        return {"devices": device_list}
        
    except Exception as e:
        logger.error(f"Get devices error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/android-devices")
async def get_android_devices(
    request: Request,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Get all active Android devices for the current user with detailed information"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        current_device_id = token_data.get("device_id")
        
        # Get user's Android devices
        devices = await jwt_repo.get_android_devices(user_id)
        
        # Format Android device data with more detailed information
        device_list = []
        for device in devices:
            device_info = {
                "device_id": device.device_id,
                "device_name": device.device_name or "Unknown Android device",
                "manufacturer": device.manufacturer,
                "model": device.model,
                "os_version": device.os_version,
                "last_active": device.last_used_at,
                "ip_address": device.ip_address,
                "is_current": device.device_id == current_device_id,
                
                # Android-specific details
                "android_details": {
                    "android_id": device.android_id,
                    "app_version": device.app_version,
                    "screen_resolution": device.screen_resolution,
                    "is_rooted": device.is_rooted,
                    "security_patch_level": device.last_security_patch,
                    "network_type": device.network_type,
                    "device_language": device.device_language,
                    "battery_level": device.battery_level
                },
                
                # Hardware information
                "hardware_info": {
                    "cpu_info": device.cpu_info,
                    "total_memory": device.total_memory,
                    "available_memory": device.available_memory,
                    "total_storage": device.total_storage,
                    "available_storage": device.available_storage
                },
                
                # Location information (if available)
                "location": {
                    "country": device.country_code,
                    "region": device.region,
                    "city": device.city,
                    "latitude": device.latitude,
                    "longitude": device.longitude
                } if device.country_code or device.latitude else None,
                
                # Custom data
                "client_data": device.client_data or {}
            }
            
            device_list.append(device_info)
        
        return {"android_devices": device_list}
        
    except Exception as e:
        logger.error(f"Get Android devices error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/devices/{device_id}", response_model=DeviceDetailResponse)
async def get_device_details(
    device_id: str,
    request: Request,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Get detailed information about a specific device"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        current_device_id = token_data.get("device_id")
        
        # Get device details
        device = await jwt_repo.get_device_details(user_id, device_id)
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Prepare location data if available
        location_info = None
        if device.country_code or device.city or device.latitude is not None:
            location_info = {
                "country": device.country_code,
                "region": device.region,
                "city": device.city,
                "latitude": device.latitude,
                "longitude": device.longitude
            }
        
        # Prepare hardware info
        hardware_info = None
        if device.cpu_info or device.total_memory:
            hardware_info = {
                "cpu_info": device.cpu_info,
                "total_memory": device.total_memory,
                "available_memory": device.available_memory,
                "total_storage": device.total_storage,
                "available_storage": device.available_storage
            }
            
        # Prepare Android-specific info
        android_info = None
        if device.device_type == "android":
            android_info = {
                "android_id": device.android_id,
                "app_version": device.app_version,
                "screen_resolution": device.screen_resolution,
                "is_rooted": device.is_rooted,
                "security_patch_level": device.last_security_patch,
                "network_type": device.network_type,
                "device_language": device.device_language,
                "battery_level": device.battery_level
            }
        
        # Return formatted device details
        return DeviceDetailResponse(
            device_id=device.device_id,
            device_name=device.device_name or "Unknown device",
            device_type=device.device_type or "unknown",
            manufacturer=device.manufacturer,
            model=device.model,
            os_version=device.os_version,
            ip_address=device.ip_address,
            last_login=device.created_at,
            last_active=device.last_used_at,
            is_current=device.device_id == current_device_id,
            hardware_info=hardware_info,
            location_info=location_info,
            android_info=android_info,
            client_data=device.client_data or {}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get device details error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving device details"
        )


@router.post("/update-device-info")
async def update_device_info(
    request: Request,
    info: UpdateDeviceInfoRequest,
    token: str = Depends(oauth2_scheme),
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
):
    """Update dynamic device information (particularly useful for Android devices)"""
    try:
        # Verify and decode token
        token_data = await verify_token(token, request, jwt_repo)
        user_id = token_data.get("user_id")
        
        # Verify device belongs to user
        device = await jwt_repo.get_device_details(user_id, info.device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
            
        # Create device info object with update data
        device_info = DeviceInfo(
            device_id=info.device_id,
            battery_level=info.battery_level,
            network_type=info.network_type,
            available_memory=info.available_memory,
            available_storage=info.available_storage,
            latitude=info.latitude,
            longitude=info.longitude,
            client_data=info.client_data or {}
        )
        
        # Update the device info
        success = await jwt_repo.update_device_info(token, device_info)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to update device information"
            )
            
        return {"message": "Device information updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update device info error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating device information"
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
                "timestamp": record.created_at,
                "device_name": record.device_name,
                "device_type": record.device_type,
                "ip_address": record.ip_address,
                "location": {
                    "country": record.country_code,
                    "region": record.region,
                    "city": record.city
                } if record.country_code else None,
                "is_android": record.device_type == "android",
                "model": record.model,
                "os_version": record.os_version
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
