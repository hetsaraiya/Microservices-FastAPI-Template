import sqlalchemy
import datetime
import uuid
from typing import Optional, List, Dict, Any

from src.config.manager import settings
from src.models.db.jwt import JwtRecord
from src.models.db.device import Device
from src.repository.crud.base import BaseCRUDRepository
from src.repository.crud.device import DeviceCRUDRepository
from src.utilities.exceptions.exceptions import EntityDoesNotExistException, SecurityException
from src.models.schemas.jwt import DeviceInfo
from src.utilities.logging.logger import logger


class JwtRecordCRUDRepository(BaseCRUDRepository):
    async def create_jwt_record(self, jwt: str, user_id: int, device_info: DeviceInfo, token_type: str = "access", expires_in: int = None) -> JwtRecord:
        """
        Create a JWT record with detailed device information
        
        Args:
            jwt: The JWT token string
            user_id: The user ID associated with the token
            device_info: DeviceInfo object containing device information
            token_type: Type of token (access or refresh)
            expires_in: Token expiration time in seconds
        """
        # First get or create the device
        device_repo = DeviceCRUDRepository(self.async_session)
        device = await device_repo.get_or_create_device(device_info)
        
        # Create timestamp
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        # Calculate expiration time
        expires_at = None
        if expires_in:
            expires_at = current_time + expires_in

        # Check if device is blacklisted
        if device.is_blacklisted:
            raise SecurityException(f"Device {device.android_id} is blacklisted: {device.blacklist_reason}")

        # Create JWT record with reference to device
        jwt_record = JwtRecord(
            jwt=jwt,
            user_id=user_id,
            android_id=device.android_id,
            token_type=token_type,
            expires_at=expires_at,
            created_at=current_time,
            last_used_at=current_time
        )
        
        logger.info(f"New jwt record created: {jwt_record.token_type}")
        
        self.async_session.add(jwt_record)
        await self.async_session.commit()
        
        logger.info(f"Created new {token_type} token for user {user_id} on device {device.device_name} ({device.android_id})")
        
        return jwt_record
    
    async def create_jwt_pair(
        self, 
        refresh_token: str, 
        access_token: str,
        user_id: int, 
        device_info: DeviceInfo, 
        refresh_expires_in: int = None,
        access_expires_in: int = None
    ) -> tuple[JwtRecord, JwtRecord]:
        """Create both refresh and access tokens in a single transaction"""
        # First get or create the device
        device_repo = DeviceCRUDRepository(self.async_session)
        device = await device_repo.get_or_create_device(device_info)
        
        # Check if device is blacklisted
        if device.is_blacklisted:
            raise SecurityException(f"Device {device.android_id} is blacklisted: {device.blacklist_reason}")
        
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        
        # Create refresh token
        refresh_record = JwtRecord(
            jwt=refresh_token,
            user_id=user_id,
            android_id=device.android_id,
            token_type="refresh",
            expires_at=current_time + refresh_expires_in if refresh_expires_in else None,
            created_at=current_time,
            last_used_at=current_time
        )
        
        # Create access token record
        access_record = JwtRecord(
            jwt=access_token,
            user_id=user_id,
            android_id=device.android_id,
            token_type="access",
            expires_at=current_time + access_expires_in if access_expires_in else None,
            created_at=current_time,
            last_used_at=current_time
        )
        
        # Add both records in a single transaction
        self.async_session.add(refresh_record)
        self.async_session.add(access_record)
        await self.async_session.commit()
        
        logger.info(f"Created token pair for user {user_id} on device {device.device_name}")
        
        return refresh_record, access_record

    async def blacklist_jwt(self, jwt: str) -> JwtRecord:
        stmt = sqlalchemy.select(JwtRecord).where(JwtRecord.jwt == jwt)
        result = await self.async_session.execute(stmt)
        jwt_record = result.scalar_one_or_none()

        if not jwt_record:
            raise EntityDoesNotExistException("JWT token not found")

        jwt_record.is_blacklisted = True
        await self.async_session.commit()
        await self.async_session.refresh(instance=jwt_record)
        
        logger.info(f"Blacklisted token for user {jwt_record.user_id} on device {jwt_record.android_id}")
        
        return jwt_record
    
    async def blacklist_device_tokens(self, user_id: int, android_id: str) -> int:
        """Blacklist all tokens for a specific device"""
        stmt = (
            sqlalchemy.update(JwtRecord)
            .where(JwtRecord.user_id == user_id, JwtRecord.android_id == android_id)
            .values(is_blacklisted=True)
        )
        result = await self.async_session.execute(stmt)
        await self.async_session.commit()
        
        count = result.rowcount
        logger.info(f"Blacklisted {count} tokens for user {user_id} on device {android_id}")
        
        return count
    
    async def blacklist_all_user_tokens(self, user_id: int) -> int:
        """Blacklist all tokens for a user (log out from all devices)"""
        stmt = (
            sqlalchemy.update(JwtRecord)
            .where(JwtRecord.user_id == user_id)
            .values(is_blacklisted=True)
        )
        result = await self.async_session.execute(stmt)
        await self.async_session.commit()
        
        count = result.rowcount
        logger.info(f"Blacklisted {count} tokens for user {user_id} (all devices)")
        
        return count

    async def is_jwt_blacklisted(self, jwt: str) -> bool:
        # Check if the token itself is blacklisted
        stmt = sqlalchemy.select(JwtRecord).where(JwtRecord.jwt == jwt)
        result = await self.async_session.execute(stmt)
        jwt_record = result.scalar_one_or_none()
        
        if not jwt_record:
            return False
            
        if jwt_record.is_blacklisted:
            return True
            
        # Also check if the device is blacklisted
        device_stmt = (
            sqlalchemy.select(Device.is_blacklisted)
            .where(Device.android_id == jwt_record.android_id)
        )
        device_result = await self.async_session.execute(device_stmt)
        device_blacklisted = device_result.scalar_one_or_none()
        
        return bool(device_blacklisted)
    
    async def update_last_used(self, jwt: str) -> None:
        """Update the last_used_at timestamp for a token and its device"""
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        
        # First get the token to find the android id
        token_stmt = sqlalchemy.select(JwtRecord.android_id).where(JwtRecord.jwt == jwt)
        token_result = await self.async_session.execute(token_stmt)
        android_id = token_result.scalar_one_or_none()
        
        # Update token last_used_at
        stmt = (
            sqlalchemy.update(JwtRecord)
            .where(JwtRecord.jwt == jwt)
            .values(last_used_at=current_time)
        )
        await self.async_session.execute(stmt)
        
        # Also update device last_used_at if we have an android_id
        if android_id:
            device_stmt = (
                sqlalchemy.update(Device)
                .where(Device.android_id == android_id)
                .values(last_used_at=current_time)
            )
            await self.async_session.execute(device_stmt)
            
        await self.async_session.commit()
    
    async def get_token_record(self, jwt: str) -> Optional[JwtRecord]:
        """Get the token record by JWT string"""
        stmt = sqlalchemy.select(JwtRecord).where(JwtRecord.jwt == jwt)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_token_device(self, jwt: str) -> Optional[Device]:
        """Get the device associated with a token"""
        stmt = (
            sqlalchemy.select(Device)
            .join(JwtRecord, Device.android_id == JwtRecord.android_id)
            .where(JwtRecord.jwt == jwt)
        )
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()
        
    async def get_token_ip(self, jwt: str) -> Optional[str]:
        """Get the IP address associated with a token's device"""
        device = await self.get_token_device(jwt)
        return device.ip_address if device else None
    
    async def validate_token_ip(self, jwt: str, ip_address: str) -> bool:
        """Validate that the token is being used from the same IP address"""
        device = await self.get_token_device(jwt)
        
        if not device:
            return False
        
        # If IP validation is not required or IP matches
        if not settings.JWT_IP_CHECK_ENABLED or device.ip_address == ip_address:
            return True
        
        # Log potential security issue
        logger.warning(f"IP address mismatch for token. Stored: {device.ip_address}, Current: {ip_address}")
        
        return False
    
    async def update_device_info(self, jwt: str, device_info: DeviceInfo) -> bool:
        """
        Update device information for an existing token
        This is useful for updating dynamic information like battery level or network type
        """
        # First get the android id from the token
        token_stmt = sqlalchemy.select(JwtRecord.android_id).where(JwtRecord.jwt == jwt)
        token_result = await self.async_session.execute(token_stmt)
        android_id = token_result.scalar_one_or_none()
        
        if not android_id:
            return False
            
        # Update the device using the device repository
        device_repo = DeviceCRUDRepository(self.async_session)
        return await device_repo.update_device(android_id, device_info)
    
    async def get_user_active_devices(self, user_id: int) -> List[Device]:
        """Get all active devices for a user"""
        device_repo = DeviceCRUDRepository(self.async_session)
        return await device_repo.get_user_devices(user_id)
    
    async def get_android_devices(self, user_id: int) -> List[Device]:
        """Get all active Android devices for a user"""
        stmt = (
            sqlalchemy.select(Device)
            .join(Device.jwt_records)
            .where(
                sqlalchemy.text(f"jwt_record.user_id = {user_id}"),
                Device.is_blacklisted == False,
                Device.device_type == "android"
            )
            .group_by(Device.id)
            .order_by(Device.last_used_at.desc())
        )
        result = await self.async_session.execute(stmt)
        return result.scalars().all()
    
    async def get_device_details(self, user_id: int, android_id: str) -> Optional[Device]:
        """Get detailed information about a specific device"""
        stmt = (
            sqlalchemy.select(Device)
            .join(Device.jwt_records)
            .where(
                sqlalchemy.text(f"jwt_record.user_id = {user_id}"),
                Device.android_id == android_id,
                Device.is_blacklisted == False
            )
            .group_by(Device.id)
        )
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_suspicious_activity(self, user_id: int, days: int = 30) -> List[Dict[str, Any]]:
        """Get potentially suspicious login activity"""
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        timeframe = current_time - (days * 24 * 60 * 60)  # Convert days to seconds
        
        # Get all active tokens in the timeframe
        stmt = (
            sqlalchemy.select(JwtRecord, Device)
            .join(Device, Device.android_id == JwtRecord.android_id)
            .where(
                JwtRecord.user_id == user_id,
                JwtRecord.created_at > timeframe,
            )
            .order_by(JwtRecord.created_at.desc())
        )
        
        result = await self.async_session.execute(stmt)
        records = result.all()  # This returns (JwtRecord, Device) tuples
        
        # Group by day to detect multiple locations
        daily_logins = {}
        suspicious_activity = []
        
        for jwt_record, device in records:
            # Get the day
            day = datetime.datetime.fromtimestamp(jwt_record.created_at).strftime('%Y-%m-%d')
            
            if day not in daily_logins:
                daily_logins[day] = []
                
            daily_logins[day].append({
                "ip": device.ip_address,
                "country": device.country_code,
                "city": device.city,
                "device": device.device_name,
                "android_id": device.android_id,
                "timestamp": jwt_record.created_at,
                "latitude": device.latitude,
                "longitude": device.longitude
            })
        
        # Check for multiple locations in the same day
        for day, logins in daily_logins.items():
            if len(logins) > 1:
                # Check if there are multiple cities, countries or significant distance between locations
                countries = set(login["country"] for login in logins if login["country"])
                cities = set(login["city"] for login in logins if login["city"])
                ips = set(login["ip"] for login in logins if login["ip"])
                
                # Check for logins from different locations
                has_location_data = any(login["latitude"] is not None and login["longitude"] is not None for login in logins)
                
                if len(countries) > 1 or len(cities) > 1 or len(ips) > 3:
                    suspicious_activity.append({
                        "day": day,
                        "logins": logins,
                        "reason": "Multiple locations/IPs in one day"
                    })
                elif has_location_data:
                    # Check for impossible travel (significant distance in short time)
                    # This would require calculating distance between coordinates
                    # and checking time difference between logins
                    sorted_logins = sorted(logins, key=lambda x: x["timestamp"])
                    for i in range(len(sorted_logins) - 1):
                        cur_login = sorted_logins[i]
                        next_login = sorted_logins[i + 1]
                        
                        # If both have location data
                        if (cur_login["latitude"] is not None and cur_login["longitude"] is not None and
                            next_login["latitude"] is not None and next_login["longitude"] is not None):
                            
                            # Calculate time difference in hours
                            time_diff = (next_login["timestamp"] - cur_login["timestamp"]) / 3600
                            
                            # This would require a function to calculate distance between coordinates
                            # For simplicity, just check if they're from different cities in short time
                            if (cur_login["city"] != next_login["city"] and 
                                cur_login["city"] and next_login["city"] and
                                time_diff < 2):  # Less than 2 hours between logins
                                
                                suspicious_activity.append({
                                    "day": day,
                                    "logins": [cur_login, next_login],
                                    "reason": f"Impossible travel: {cur_login['city']} to {next_login['city']} in {time_diff:.1f} hours"
                                })
        
        # Also check for multiple different device types or suspicious device changes
        devices_by_day = {}
        for _, device in records:
            day = datetime.datetime.fromtimestamp(jwt_record.created_at).strftime('%Y-%m-%d')
            
            if day not in devices_by_day:
                devices_by_day[day] = set()
                
            if device.device_type:
                devices_by_day[day].add(device.device_type)
        
        for day, device_types in devices_by_day.items():
            if len(device_types) > 2:  # More than 2 different device types in a day
                logins = daily_logins.get(day, [])
                suspicious_activity.append({
                    "day": day,
                    "logins": logins,
                    "reason": f"Multiple device types used: {', '.join(device_types)}"
                })
        
        return suspicious_activity
    
    async def get_recent_activity(self, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent login activity for a user"""
        stmt = (
            sqlalchemy.select(JwtRecord, Device)
            .join(Device, Device.android_id == JwtRecord.android_id)
            .where(
                JwtRecord.user_id == user_id,
                JwtRecord.token_type == "access"
            )
            .order_by(JwtRecord.created_at.desc())
            .limit(limit)
        )
        
        result = await self.async_session.execute(stmt)
        records = result.all()
        
        # Format the results
        activity = []
        for jwt_record, device in records:
            activity.append({
                "timestamp": jwt_record.created_at,
                "android_id": device.android_id,
                "device_name": device.device_name,
                "ip_address": device.ip_address,
                "location": {
                    "country": device.country_code,
                    "city": device.city
                } if device.country_code else None,
                "device_type": device.device_type
            })
            
        return activity

    async def cleanup_expired_tokens(self) -> None:
        """Clean up expired or old tokens"""
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        
        # Delete tokens that are explicitly expired
        expired_stmt = sqlalchemy.delete(JwtRecord).where(
            JwtRecord.expires_at.isnot(None),
            JwtRecord.expires_at < current_time
        )
        
        expired_result = await self.async_session.execute(expired_stmt)
        
        # Delete tokens older than general expiration time
        general_expiry = current_time - (settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME * 60)
        old_stmt = sqlalchemy.delete(JwtRecord).where(
            JwtRecord.token_type == "access",
            JwtRecord.created_at < general_expiry
        )
        
        old_result = await self.async_session.execute(old_stmt)
        
        # Delete refresh tokens that are older than the refresh token expiration time
        if settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME > 0:
            refresh_expiry = current_time - (settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME * 24 * 60 * 60)
            refresh_stmt = sqlalchemy.delete(JwtRecord).where(
                JwtRecord.token_type == "refresh",
                JwtRecord.created_at < refresh_expiry
            )
            refresh_result = await self.async_session.execute(refresh_stmt)
        else:
            refresh_result = None
        
        # Commit changes
        await self.async_session.commit()
        
        total_deleted = expired_result.rowcount + old_result.rowcount
        if refresh_result:
            total_deleted += refresh_result.rowcount
            
        logger.info(f"Cleaned up {total_deleted} expired tokens")

    @staticmethod
    def generate_device_id() -> str:
        """Generate a unique device ID"""
        return str(uuid.uuid4())
