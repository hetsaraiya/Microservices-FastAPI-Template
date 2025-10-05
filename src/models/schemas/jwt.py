import datetime
from typing import Optional, Dict, Any, List
import uuid

import pydantic


class JWToken(pydantic.BaseModel):
    exp: datetime.datetime
    sub: str
    jti: str  # JWT ID for token identification


class JWTUser(pydantic.BaseModel):
    username: str
    email: pydantic.EmailStr
    user_type: str = "RIDER"  # Default to RIDER
    user_id: uuid.UUID  # Changed from int to str for UUID


class JWTResponse(pydantic.BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
