from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import List, Optional

from src.api.dependencies.auth import oauth2_scheme, verify_token, admin_required, get_device_info
from src.api.dependencies.repository import get_repository
from src.models.schemas.jwt import DeviceBlacklistRequest, DeviceResponse, DeviceInfo
from src.repository.crud.device import DeviceCRUDRepository
from src.utilities.logging.logger import logger

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("/", response_model=List[DeviceResponse])
async def list_all_devices(
    request: Request,
    token: str = Depends(oauth2_scheme),
    admin_check: bool = Depends(admin_required()),
    device_repo: DeviceCRUDRepository = Depends(get_repository(repo_type=DeviceCRUDRepository))
):
    """Get all devices in the system (admin only)"""
    try:
        devices = await device_repo.get_all_devices()
        
        return [
            DeviceResponse(
                device_id=device.android_id,  # Use android_id as the primary identifier
                device_name=device.device_name or "Unknown device",
                device_type=device.device_type,
                manufacturer=device.manufacturer,
                model=device.model,
                os_version=device.os_version,
                ip_address=device.ip_address,
                is_blacklisted=device.is_blacklisted,
                last_used_at=device.last_used_at,
                created_at=device.created_at
            )
            for device in devices
        ]
    except Exception as e:
        logger.error(f"List devices error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve devices"
        )


@router.get("/{android_id}", response_model=DeviceResponse)
async def get_device(
    android_id: str,
    request: Request,
    token: str = Depends(oauth2_scheme),
    admin_check: bool = Depends(admin_required()),
    device_repo: DeviceCRUDRepository = Depends(get_repository(repo_type=DeviceCRUDRepository))
):
    """Get device details (admin only)"""
    try:
        device = await device_repo.get_device_by_android_id(android_id)
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        return DeviceResponse(
            device_id=device.android_id,  # Use android_id as the primary identifier
            device_name=device.device_name or "Unknown device",
            device_type=device.device_type,
            manufacturer=device.manufacturer,
            model=device.model,
            os_version=device.os_version,
            ip_address=device.ip_address,
            is_blacklisted=device.is_blacklisted,
            last_used_at=device.last_used_at,
            created_at=device.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get device error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve device"
        )


@router.post("/blacklist", status_code=status.HTTP_200_OK)
async def blacklist_device(
    request: Request,
    blacklist_request: DeviceBlacklistRequest,
    token: str = Depends(oauth2_scheme),
    admin_check: bool = Depends(admin_required()),
    device_repo: DeviceCRUDRepository = Depends(get_repository(repo_type=DeviceCRUDRepository))
):
    """Blacklist a device to prevent it from being used for login (admin only)"""
    try:
        success = await device_repo.blacklist_device(
            blacklist_request.device_id,  # device_id in request payload will be android_id
            blacklist_request.reason
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        return {"message": f"Device {blacklist_request.device_id} has been blacklisted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Blacklist device error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to blacklist device"
        )


@router.post("/unblacklist/{android_id}", status_code=status.HTTP_200_OK)
async def unblacklist_device(
    android_id: str,
    request: Request,
    token: str = Depends(oauth2_scheme),
    admin_check: bool = Depends(admin_required()),
    device_repo: DeviceCRUDRepository = Depends(get_repository(repo_type=DeviceCRUDRepository))
):
    """Remove a device from the blacklist (admin only)"""
    try:
        success = await device_repo.unblacklist_device(android_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        return {"message": f"Device {android_id} has been removed from blacklist successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unblacklist device error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unblacklist device"
        )


@router.get("/check/{android_id}", status_code=status.HTTP_200_OK)
async def check_device_status(
    android_id: str,
    request: Request,
    token: str = Depends(oauth2_scheme),
    device_repo: DeviceCRUDRepository = Depends(get_repository(repo_type=DeviceCRUDRepository))
):
    """Check if a device is blacklisted"""
    try:
        # Verify token
        token_data = await verify_token(token, request)
        
        device = await device_repo.get_device_by_android_id(android_id)
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        return {
            "device_id": device.android_id,
            "is_blacklisted": device.is_blacklisted,
            "blacklist_reason": device.blacklist_reason if device.is_blacklisted else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Check device status error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check device status"
        )