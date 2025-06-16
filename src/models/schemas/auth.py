
from typing import Any, Dict, List, Optional

from pydantic import EmailStr
from src.models.schemas.base import BaseSchemaModel

class LoginRequest(BaseSchemaModel):
    username: str
    email: EmailStr
    password: str
    device_id: Optional[str] = None
    client_data: Optional[Dict[str, Any]] = None


class RegisterRequest(BaseSchemaModel):
    username: str
    email: EmailStr
    password: str
    phone: str
    role: str
    device_id: Optional[str] = None
    client_data: Optional[Dict[str, Any]] = None



class DeviceListResponse(BaseSchemaModel):
    devices: List[Dict[str, Any]]


class DeviceDetailResponse(BaseSchemaModel):
    device_id: str
    device_name: str
    device_type: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    last_login: int
    last_active: int
    is_current: bool
    hardware_info: Optional[Dict[str, Any]] = None
    location_info: Optional[Dict[str, Any]] = None
    android_info: Optional[Dict[str, Any]] = None
    client_data: Dict[str, Any] = {}


class UpdateDeviceInfoRequest(BaseSchemaModel):
    device_id: str
    battery_level: Optional[float] = None
    network_type: Optional[str] = None
    available_memory: Optional[str] = None
    available_storage: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    client_data: Optional[Dict[str, Any]] = None


class ActivityResponse(BaseSchemaModel):
    recent_activity: List[Dict[str, Any]]
    suspicious_activity: List[Dict[str, Any]]
