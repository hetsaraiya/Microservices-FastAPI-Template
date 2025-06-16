import datetime
import uuid
from typing import Tuple, List, Dict, Any, Optional

import pydantic
from jose import jwt as jose_jwt, JWTError as JoseJWTError

from src.config.manager import settings
from src.models.db.user import User
from src.models.schemas.jwt import JWTUser, JWToken, DeviceInfo
from src.utilities.exceptions.database import EntityDoesNotExist
from src.utilities.exceptions.exceptions import SecurityException
from src.utilities.logging.logger import logger


class JWTGenerator:
    def __init__(self):
        pass

    def _generate_jwt_token(
        self,
        *,
        jwt_data: dict[str, Any],
        expires_delta: datetime.timedelta | None = None,
        jti: str = None,
        subject: str = None,
    ) -> str:
        to_encode = jwt_data.copy()
        for key, value in jwt_data.items():
            if isinstance(value, uuid.UUID):
                to_encode[key] = str(value)
            else:
                to_encode[key] = value


        if expires_delta:
            expire = datetime.datetime.utcnow() + expires_delta
        else:
            expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=settings.JWT_MIN)

        # Generate a unique JWT ID if not provided
        if not jti:
            jti = str(uuid.uuid4())
            
        # Use provided subject or default
        if not subject:
            subject = settings.JWT_SUBJECT
        to_encode.update(JWToken(exp=expire, sub=subject, jti=jti).dict())

        return jose_jwt.encode(to_encode, key=settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    def generate_access_token(self, user: User, device_info: DeviceInfo) -> Tuple[str, int, uuid.UUID]:
        """
        Generate an access token with device information
        Returns the token, expiration time in seconds, and the device ID
        """
        if not user:
            raise EntityDoesNotExist("Cannot generate JWT token without User entity!")

        # If no device ID provided, generate one
        if not device_info.device_id:
            device_info.device_id = str(uuid.uuid4())

        # Calculate expiration
        expiration_minutes = settings.JWT_ACCESS_TOKEN_EXPIRATION_TIME
        expiration_seconds = expiration_minutes * 60
        expires_delta = datetime.timedelta(minutes=expiration_minutes)

        # Create token payload
        token_data = JWTUser(
            username=user.username, 
            email=user.email, 
            user_type=user.user_type,
            user_id=user.id
        ).dict()
        
        # Add device info to payload
        token_data.update({
            "device": {
                "id": device_info.device_id,
                "name": device_info.device_name,
                "type": device_info.device_type,
                "hash": device_info.device_hash
            }
        })

        # Generate token with unique JWT ID
        jti = str(uuid.uuid4())
        token = self._generate_jwt_token(
            jwt_data=token_data,
            expires_delta=expires_delta,
            jti=jti,
            subject=settings.JWT_SUBJECT
        )

        return token, expiration_seconds, device_info.android_id
        
    def generate_refresh_token(self, user: User, device_info: DeviceInfo) -> Tuple[str, int, uuid.UUID]:
        """
        Generate a refresh token with device information
        Returns the token, expiration time in seconds, and the device ID
        """
        if not user:
            raise EntityDoesNotExist("Cannot generate refresh token without User entity!")

        # Calculate expiration (refresh tokens typically last longer)
        refresh_expiration_days = settings.JWT_REFRESH_TOKEN_EXPIRATION_TIME
        expiration_seconds = refresh_expiration_days * 24 * 60 * 60  # Convert days to seconds
        expires_delta = datetime.timedelta(days=refresh_expiration_days)

        # Create token payload (include minimal data for security)
        token_data = {
            "user_id": user.id,
            "device_id": device_info.device_id,
            "token_type": "refresh"
        }

        # Generate token with unique JWT ID
        jti = str(uuid.uuid4())
        token = self._generate_jwt_token(
            jwt_data=token_data,
            expires_delta=expires_delta,
            jti=jti,
            subject="refresh"
        )

        return token, expiration_seconds, device_info.device_id

    def retrieve_details_from_token(self, token: str) -> Dict[str, Any]:
        try:
            payload = jose_jwt.decode(
                token=token, 
                key=settings.JWT_SECRET_KEY, 
                algorithms=[settings.JWT_ALGORITHM]
            )
            
            # Check token type - handle different payload structures
            subject = payload.get("sub")
            
            if subject == "refresh":
                # This is a refresh token - simplified structure
                user_id = payload.get("user_id")
                device_id = payload.get("device_id")
                
                if not user_id or not device_id:
                    raise SecurityException("Invalid refresh token payload structure")
                
                return {
                    "user_id": user_id,
                    "device_id": device_id,
                    "token_type": "refresh",
                    "jti": payload.get("jti"),
                    "exp": payload.get("exp"),
                    "raw_payload": payload
                }
            
            # Regular access token
            username = payload.get("username")
            email = payload.get("email")
            user_type = payload.get("user_type", "RIDER")
            user_id = payload.get("user_id")
            
            if not username or not email or not user_id:
                raise SecurityException("Invalid JWT payload structure")
                
            # Extract device info
            device_info = payload.get("device", {})
            device_id = device_info.get("id") if device_info else None
            
            # Extract JWT ID
            jti = payload.get("jti")
            if not jti:
                raise SecurityException("Missing JWT ID (jti)")
            
            # Return all information
            return {
                "username": username,
                "email": email,
                "user_type": user_type,
                "user_id": user_id,
                "device_id": device_id,
                "jti": jti,
                "token_type": "access",
                "raw_payload": payload
            }

        except JoseJWTError as token_decode_error:
            logger.error(f"JWT decode error: {str(token_decode_error)}")
            raise SecurityException("Unable to decode JWT Token") from token_decode_error
        except pydantic.ValidationError as validation_error:
            logger.error(f"JWT validation error: {str(validation_error)}")
            raise SecurityException("Invalid payload in token") from validation_error


def get_jwt_generator() -> JWTGenerator:
    return JWTGenerator()


jwt_generator: JWTGenerator = get_jwt_generator()
