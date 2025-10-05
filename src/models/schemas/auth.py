
from typing import Any, Dict, List, Optional

from pydantic import EmailStr
from src.models.schemas.base import BaseSchemaModel

class LoginRequest(BaseSchemaModel):
    username: str
    email: EmailStr
    password: str


class RegisterRequest(BaseSchemaModel):
    username: str
    email: EmailStr
    password: str
    phone: str
    role: str



class ActivityResponse(BaseSchemaModel):
    recent_activity: List[Dict[str, Any]]
    suspicious_activity: List[Dict[str, Any]]
