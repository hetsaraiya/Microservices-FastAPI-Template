import sqlalchemy
from sqlalchemy.future import select
from typing import Optional, List, Dict, Any

from src.models.db.device import Device
from src.models.schemas.jwt import DeviceInfo
from src.repository.crud.base import BaseCRUDRepository


class DeviceCRUDRepository(BaseCRUDRepository):
    async def get_device_by_id(self, device_id: str) -> Optional[Device]:
        """Get a device by its device_id"""
        stmt = select(Device).where(Device.device_id == device_id)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_device_by_android_id(self, android_id: str) -> Optional[Device]:
        """Get a device by its Android ID"""
        stmt = select(Device).where(Device.android_id == android_id)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_device_by_ip(self, ip_address: str) -> Optional[Device]:
        """Get a device by IP address"""
        stmt = select(Device).where(Device.ip_address == ip_address)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_device_by_hash(self, device_hash: str) -> Optional[Device]:
        """Get a device by its hash"""
        stmt = select(Device).where(Device.device_hash == device_hash)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all_devices(self) -> List[Device]:
        """Get all devices in the system"""
        stmt = select(Device).order_by(Device.last_used_at.desc())
        result = await self.async_session.execute(stmt)
        return result.scalars().all()

    async def get_user_devices(self, user_id: int) -> List[Device]:
        """Get all devices associated with a user through JWT records"""
        stmt = (
            select(Device)
            .join(Device.jwt_records)
            .where(
                sqlalchemy.text(f"jwt_record.user_id = {user_id}"),
                Device.is_blacklisted == False
            )
            .group_by(Device.id)
            .order_by(Device.last_used_at.desc())
        )
        result = await self.async_session.execute(stmt)
        return result.scalars().all()

    async def get_or_create_device(self, device_info: DeviceInfo) -> Device:
        """Get existing device or create a new one"""
        # Try to find device by ID
        device = await self.get_device_by_id(device_info.device_id)
        
        if not device:
            # Try by Android ID if available
            if device_info.android_id:
                device = await self.get_device_by_android_id(device_info.android_id)
                
            # Try by device hash if available
            if not device and device_info.device_hash:
                device = await self.get_device_by_hash(device_info.device_hash)
                
            # Create new device if not found
            if not device:
                stmt = sqlalchemy.text("SELECT EXTRACT(EPOCH FROM NOW())")
                result = await self.async_session.execute(stmt)
                current_time = int(result.scalar())
                
                device = Device(
                    device_id=device_info.device_id,
                    device_hash=device_info.device_hash,
                    android_id=device_info.android_id,
                    device_name=device_info.device_name,
                    device_type=device_info.device_type,
                    ip_address=device_info.ip_address,
                    user_agent=device_info.user_agent,
                    # Android-specific fields
                    manufacturer=device_info.manufacturer,
                    model=device_info.model,
                    os_version=device_info.os_version,
                    app_version=device_info.app_version,
                    screen_resolution=device_info.screen_resolution,
                    network_type=device_info.network_type,
                    device_language=device_info.device_language,
                    battery_level=device_info.battery_level,
                    is_rooted=device_info.is_rooted,
                    # iOS-specific fields
                    device_model=device_info.device_model,
                    ios_version=device_info.ios_version,
                    is_jailbroken=device_info.is_jailbroken,
                    # Web browser fields
                    browser_name=device_info.browser_name,
                    browser_version=device_info.browser_version,
                    # Hardware info
                    cpu_info=device_info.cpu_info,
                    total_memory=device_info.total_memory,
                    available_memory=device_info.available_memory,
                    total_storage=device_info.total_storage,
                    available_storage=device_info.available_storage,
                    # Location data
                    country_code=device_info.country_code,
                    region=device_info.region,
                    city=device_info.city,
                    latitude=device_info.latitude,
                    longitude=device_info.longitude,
                    last_security_patch=device_info.last_security_patch,
                    client_data=device_info.client_data,
                    created_at=current_time,
                    last_used_at=current_time,
                    is_blacklisted=False
                )
                
                self.async_session.add(device)
                await self.async_session.commit()
                await self.async_session.refresh(device)
        else:
            # Update existing device with new info
            await self.update_device(device.device_id, device_info)
            
        return device

    async def update_device(self, device_id: str, device_info: DeviceInfo) -> bool:
        """Update device information"""
        device = await self.get_device_by_id(device_id)
        
        if not device:
            return False
            
        # Only update fields that are provided
        if device_info.device_name is not None:
            device.device_name = device_info.device_name
        if device_info.device_type is not None:
            device.device_type = device_info.device_type
        if device_info.ip_address is not None:
            device.ip_address = device_info.ip_address
        if device_info.manufacturer is not None:
            device.manufacturer = device_info.manufacturer
        if device_info.model is not None:
            device.model = device_info.model
        if device_info.os_version is not None:
            device.os_version = device_info.os_version
        if device_info.android_id is not None:
            device.android_id = device_info.android_id
        if device_info.app_version is not None:
            device.app_version = device_info.app_version
        if device_info.screen_resolution is not None:
            device.screen_resolution = device_info.screen_resolution
        if device_info.network_type is not None:
            device.network_type = device_info.network_type
        if device_info.device_language is not None:
            device.device_language = device_info.device_language
        if device_info.battery_level is not None:
            device.battery_level = device_info.battery_level
        if device_info.is_rooted is not None:
            device.is_rooted = device_info.is_rooted
            
        # iOS-specific fields
        if device_info.device_model is not None:
            device.device_model = device_info.device_model
        if device_info.ios_version is not None:
            device.ios_version = device_info.ios_version
        if device_info.is_jailbroken is not None:
            device.is_jailbroken = device_info.is_jailbroken
            
        # Web browser fields
        if device_info.browser_name is not None:
            device.browser_name = device_info.browser_name
        if device_info.browser_version is not None:
            device.browser_version = device_info.browser_version
            
        # Hardware info
        if device_info.cpu_info is not None:
            device.cpu_info = device_info.cpu_info
        if device_info.total_memory is not None:
            device.total_memory = device_info.total_memory
        if device_info.available_memory is not None:
            device.available_memory = device_info.available_memory
        if device_info.total_storage is not None:
            device.total_storage = device_info.total_storage
        if device_info.available_storage is not None:
            device.available_storage = device_info.available_storage
            
        # Location info
        if device_info.country_code is not None:
            device.country_code = device_info.country_code
        if device_info.region is not None:
            device.region = device_info.region
        if device_info.city is not None:
            device.city = device_info.city
        if device_info.latitude is not None:
            device.latitude = device_info.latitude
        if device_info.longitude is not None:
            device.longitude = device_info.longitude
        if device_info.last_security_patch is not None:
            device.last_security_patch = device_info.last_security_patch
            
        # Update client data by merging
        if device_info.client_data:
            if not device.client_data:
                device.client_data = {}
                
        # Update last_used_at timestamp
        stmt = sqlalchemy.text("SELECT EXTRACT(EPOCH FROM NOW())")
        result = await self.async_session.execute(stmt)
        device.last_used_at = int(result.scalar())
        
        await self.async_session.commit()
        await self.async_session.refresh(device)
        return True

    async def blacklist_device(self, device_id: str, reason: Optional[str] = None) -> bool:
        """Blacklist a device to prevent future logins"""
        device = await self.get_device_by_id(device_id)
        
        if not device:
            return False
            
        device.is_blacklisted = True
        device.blacklist_reason = reason
        
        # Also blacklist all active tokens for this device
        stmt = (
            sqlalchemy.update("jwt_record")
            .where(sqlalchemy.text(f"device_id = '{device_id}'"))
            .values(is_blacklisted=True)
        )
        await self.async_session.execute(stmt)
        
        await self.async_session.commit()
        return True

    async def unblacklist_device(self, device_id: str) -> bool:
        """Remove a device from the blacklist"""
        device = await self.get_device_by_id(device_id)
        
        if not device:
            return False
            
        device.is_blacklisted = False
        device.blacklist_reason = None
        
        await self.async_session.commit()
        return True