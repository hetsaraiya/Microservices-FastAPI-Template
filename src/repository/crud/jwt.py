import sqlalchemy
import datetime
import uuid
from typing import Optional, List, Dict, Any

from src.config.manager import settings
from src.models.db.jwt import JwtRecord
from src.repository.crud.base import BaseCRUDRepository
from src.utilities.exceptions.exceptions import EntityDoesNotExistException, SecurityException
from src.utilities.logging.logger import logger


class JwtRecordCRUDRepository(BaseCRUDRepository[JwtRecord]):
    def __init__(self, async_session):
        super().__init__(async_session, JwtRecord)
    async def create_jwt_record(self, jwt: str, user_id: int, token_type: str = "access", expires_in: int = None) -> JwtRecord:
        """
        Create a JWT record
        
        Args:
            jwt: The JWT token string
            user_id: The user ID associated with the token
            token_type: Type of token (access or refresh)
            expires_in: Token expiration time in seconds
        """
        # Create timestamp
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

        # Calculate expiration time
        expires_at = None
        if expires_in:
            expires_at = current_time + expires_in

        # Create JWT record
        jwt_record = JwtRecord(
            jwt=jwt,
            user_id=user_id,
            android_id=None,  # No device tracking
            token_type=token_type,
            expires_at=expires_at,
            created_at=current_time,
            last_used_at=current_time
        )
        
        logger.info(f"New jwt record created: {jwt_record.token_type}")
        
        self.async_session.add(jwt_record)
        await self.async_session.commit()
        
        logger.info(f"Created new {token_type} token for user {user_id}")
        
        return jwt_record
    
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
            
        return False
    
    async def update_last_used(self, jwt: str) -> None:
        """Update the last_used_at timestamp for a token"""
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        
        # Update token last_used_at
        stmt = (
            sqlalchemy.update(JwtRecord)
            .where(JwtRecord.jwt == jwt)
            .values(last_used_at=current_time)
        )
        await self.async_session.execute(stmt)
        await self.async_session.commit()

    async def get_token_record(self, jwt: str) -> Optional[JwtRecord]:
        """Get the token record by JWT string"""
        stmt = sqlalchemy.select(JwtRecord).where(JwtRecord.jwt == jwt)
        result = await self.async_session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_suspicious_activity(self, user_id: int, days: int = 30) -> List[Dict[str, Any]]:
        """Get potentially suspicious login activity"""
        current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        timeframe = current_time - (days * 24 * 60 * 60)  # Convert days to seconds
        
        # Get all active tokens in the timeframe
        stmt = (
            sqlalchemy.select(JwtRecord)
            .where(
                JwtRecord.user_id == user_id,
                JwtRecord.created_at > timeframe,
            )
            .order_by(JwtRecord.created_at.desc())
        )
        
        result = await self.async_session.execute(stmt)
        records = result.scalars().all()
        
        # Group by day to detect multiple locations (simplified without device info)
        daily_logins = {}
        suspicious_activity = []
        
        for jwt_record in records:
            # Get the day
            day = datetime.datetime.fromtimestamp(jwt_record.created_at).strftime('%Y-%m-%d')
            
            if day not in daily_logins:
                daily_logins[day] = []
                
            daily_logins[day].append({
                "timestamp": jwt_record.created_at,
                "token_type": jwt_record.token_type
            })
        
        # Check for multiple logins in the same day
        for day, logins in daily_logins.items():
            if len(logins) > 5:  # More than 5 logins in a day is suspicious
                suspicious_activity.append({
                    "day": day,
                    "login_count": len(logins),
                    "reason": f"Multiple logins in one day: {len(logins)}"
                })
        
        return suspicious_activity
    
    async def get_recent_activity(self, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent login activity for a user"""
        stmt = (
            sqlalchemy.select(JwtRecord)
            .where(
                JwtRecord.user_id == user_id,
                JwtRecord.token_type == "access"
            )
            .order_by(JwtRecord.created_at.desc())
            .limit(limit)
        )
        
        result = await self.async_session.execute(stmt)
        records = result.scalars().all()
        
        # Format the results
        activity = []
        for jwt_record in records:
            activity.append({
                "timestamp": jwt_record.created_at,
                "action": "login",
                "ip_address": jwt_record.ip_address,
                "user_agent": jwt_record.user_agent,
                "country": jwt_record.country_code,
                "city": jwt_record.city
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
