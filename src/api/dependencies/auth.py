from typing import List, Optional, Dict, Any
import uuid
import re
import hashlib
import json

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from src.config.manager import settings
from src.models.db.user import UserTypeEnum, User
from src.models.schemas.jwt import JWTUser, DeviceInfo
from src.repository.crud.jwt import JwtRecordCRUDRepository
from src.utilities.exceptions.exceptions import AuthorizationHeaderException, SecurityException
from src.securities.authorizations.jwt import jwt_generator
from src.api.dependencies.repository import get_repository
from src.utilities.logging.logger import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_client_ip(request: Request) -> str:
    """Get client IP address from request"""
    if x_forwarded_for := request.headers.get("X-Forwarded-For"):
        # Get the client's IP from the X-Forwarded-For header if behind a proxy
        return x_forwarded_for.split(",")[0].strip()
    elif client_host := getattr(request.client, "host", None):
        # Otherwise get it from the client's host attribute
        return client_host
    return "unknown"


def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """
    Parse user agent string to extract detailed device information
    Returns a dictionary with device information
    """
    result = {
        "device_type": "unknown",
        "browser_name": None,
        "browser_version": None,
        "os_name": None,
        "os_version": None,
        "manufacturer": None,
        "model": None,
        "is_mobile": False,
    }
    
    # Check if it's a mobile device
    if any(x in user_agent.lower() for x in ["android", "iphone", "ipad", "mobile"]):
        result["is_mobile"] = True
        
        # Detect Android devices
        android_match = re.search(r'Android\s([0-9\.]+)', user_agent)
        if android_match:
            result["device_type"] = "android"
            result["os_name"] = "Android"
            result["os_version"] = android_match.group(1)
            
            # Extract manufacturer and model
            device_match = re.search(r';\s([^;]+(?:\s[^;]+)*)\sbuild/[^\s]+', user_agent.lower())
            if device_match:
                device_info = device_match.group(1).strip()
                parts = device_info.split(' ')
                if len(parts) > 1:
                    result["manufacturer"] = parts[0].capitalize()
                    result["model"] = ' '.join(parts[1:]).capitalize()
        
        # Detect iOS devices with improved detection
        elif 'iPhone' in user_agent or 'iPad' in user_agent or 'iPod' in user_agent:
            result["device_type"] = "ios"
            result["os_name"] = "iOS"
            result["manufacturer"] = "Apple"
            
            # Determine iOS device model
            if 'iPhone' in user_agent:
                # Try to extract iPhone model number if available
                iphone_model = re.search(r'iPhone(\d+,\d+)', user_agent)
                if iphone_model:
                    result["model"] = f"iPhone {iphone_model.group(1)}"
                else:
                    result["model"] = "iPhone"
            elif 'iPad' in user_agent:
                # Try to extract iPad model if available
                ipad_model = re.search(r'iPad(\d+,\d+)', user_agent)
                if ipad_model:
                    result["model"] = f"iPad {ipad_model.group(1)}"
                else:
                    result["model"] = "iPad"
            elif 'iPod' in user_agent:
                result["model"] = "iPod Touch"
            
            # Extract iOS version with improved pattern matching
            ios_version = re.search(r'OS\s(\d+[_\.]\d+(?:[_\.]\d+)?)', user_agent)
            if ios_version:
                result["os_version"] = ios_version.group(1).replace('_', '.')
                
            # Handle newer iOS user agent style (CPU OS vs. CPU iPhone OS)
            if not result["os_version"]:
                ios_version_alt = re.search(r'Version/(\d+\.\d+(?:\.\d+)?)', user_agent)
                if ios_version_alt:
                    result["os_version"] = ios_version_alt.group(1)
    else:
        # Desktop browsers
        result["device_type"] = "web"  # Changed from "desktop" to "web" for consistency
        
        # Windows detection
        if 'Windows' in user_agent:
            result["os_name"] = "Windows"
            win_version = re.search(r'Windows\sNT\s([0-9\.]+)', user_agent)
            if win_version:
                version_map = {
                    '10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7', '6.0': 'Vista', '5.2': 'XP', '5.1': 'XP'
                }
                result["os_version"] = version_map.get(win_version.group(1), win_version.group(1))
        
        # macOS detection
        elif 'Macintosh' in user_agent:
            result["os_name"] = "macOS"
            mac_version = re.search(r'Mac\sOS\sX\s([0-9_\.]+)', user_agent)
            if mac_version:
                result["os_version"] = mac_version.group(1).replace('_', '.')
            result["manufacturer"] = "Apple"
        
        # Linux detection
        elif 'Linux' in user_agent and 'Android' not in user_agent:
            result["os_name"] = "Linux"
    
    # Browser detection with improved information
    if 'Chrome' in user_agent and 'Chromium' not in user_agent and 'Edg' not in user_agent and 'OPR' not in user_agent and 'CriOS' not in user_agent:
        result["browser_name"] = "Chrome"
        chrome_version = re.search(r'Chrome/([0-9\.]+)', user_agent)
        if chrome_version:
            result["browser_version"] = chrome_version.group(1)
    elif 'CriOS' in user_agent:  # Chrome on iOS
        result["browser_name"] = "Chrome"
        chrome_version = re.search(r'CriOS/([0-9\.]+)', user_agent)
        if chrome_version:
            result["browser_version"] = chrome_version.group(1)
    elif 'Firefox' in user_agent or 'FxiOS' in user_agent:
        result["browser_name"] = "Firefox"
        if 'FxiOS' in user_agent:  # Firefox on iOS
            firefox_version = re.search(r'FxiOS/([0-9\.]+)', user_agent)
        else:
            firefox_version = re.search(r'Firefox/([0-9\.]+)', user_agent)
        if firefox_version:
            result["browser_version"] = firefox_version.group(1)
    elif 'Safari' in user_agent and 'Chrome' not in user_agent and 'Edg' not in user_agent and 'CriOS' not in user_agent and 'FxiOS' not in user_agent:
        result["browser_name"] = "Safari"
        safari_version = re.search(r'Version/([0-9\.]+)', user_agent)
        if safari_version:
            result["browser_version"] = safari_version.group(1)
    elif 'Edg' in user_agent:
        result["browser_name"] = "Edge"
        edge_version = re.search(r'Edg/([0-9\.]+)', user_agent)
        if edge_version:
            result["browser_version"] = edge_version.group(1)
    elif 'OPR' in user_agent or 'Opera' in user_agent:
        result["browser_name"] = "Opera"
        opera_version = re.search(r'OPR/([0-9\.]+)', user_agent)
        if opera_version:
            result["browser_version"] = opera_version.group(1)
    elif 'MSIE' in user_agent or 'Trident/' in user_agent:
        result["browser_name"] = "Internet Explorer"
        ie_version = re.search(r'MSIE\s([0-9\.]+)', user_agent)
        if ie_version:
            result["browser_version"] = ie_version.group(1)
        elif 'Trident/' in user_agent:  # IE 11
            result["browser_version"] = "11.0"
            
    return result


def generate_device_hash(request: Request, user_agent: str, device_id: Optional[str] = None) -> str:
    """
    Generate a unique device hash based on available device information
    This helps with device fingerprinting for security
    """
    # Combine available device information
    elements = [
        user_agent,
        get_client_ip(request),
        device_id or str(uuid.uuid4()),
        # Add a secret to make hash less predictable
        settings.JWT_DEVICE_SECRET
    ]
    
    # Create a hash of the combined data
    hash_input = "||".join([str(item) for item in elements])
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()


def get_device_info(request: Request, device_id: Optional[str] = None, client_data: Optional[Dict[str, Any]] = None) -> DeviceInfo:
    """Extract device information from request and client data"""
    user_agent = request.headers.get("User-Agent", "unknown")
    ip_address = get_client_ip(request)
    
    # Parse user agent for device details
    ua_info = parse_user_agent(user_agent)
    
    # Use provided device_id or generate a new one
    if not device_id:
        device_id = str(uuid.uuid4())
    
    # Create device hash for fingerprinting
    device_hash = generate_device_hash(request, user_agent, device_id)
    logger.debug(f"Generated device hash: {device_hash}")
    # Determine device name based on available information
    if ua_info.get("model") and ua_info.get("manufacturer"):
        device_name = f"{ua_info['manufacturer']} {ua_info['model']}"
    else:
        device_name = f"{ua_info['device_type'].capitalize()} - {user_agent[:30]}"
    
    # Create a base device info object
    device_info = DeviceInfo(
        android_id=client_data.get("android_id", device_id) if client_data else "device_id",  # Use android_id as the unique identifier
        device_name=device_name,
        device_type=ua_info["device_type"],
        ip_address=ip_address,
        user_agent=user_agent,
        manufacturer=ua_info.get("manufacturer"),
        model=ua_info.get("model"),
        os_version=ua_info.get("os_version"),
        browser_name=ua_info.get("browser_name"),
        browser_version=ua_info.get("browser_version"),
        device_hash=device_hash,
        client_data={}
    )
    
    # Add client data if provided (especially important for Android devices)
    if client_data:
        # Process Android-specific data
        device_info.manufacturer = client_data.get("manufacturer", device_info.manufacturer)
        device_info.model = client_data.get("model", device_info.model)
        device_info.os_version = client_data.get("os_version", device_info.os_version)
        device_info.app_version = client_data.get("app_version")
        device_info.screen_resolution = client_data.get("screen_resolution")
        device_info.network_type = client_data.get("network_type")
        device_info.device_language = client_data.get("device_language")
        device_info.battery_level = client_data.get("battery_level")
        device_info.is_rooted = client_data.get("is_rooted")
        device_info.android_id = client_data.get("android_id")
        device_info.last_security_patch = client_data.get("security_patch_level")
        
        # Hardware information
        device_info.cpu_info = client_data.get("cpu_info")
        device_info.total_memory = client_data.get("total_memory")
        device_info.available_memory = client_data.get("available_memory")
        device_info.total_storage = client_data.get("total_storage")
        device_info.available_storage = client_data.get("available_storage")
        
        # Location data (if available)
        device_info.country_code = client_data.get("country_code")
        device_info.region = client_data.get("region")
        device_info.city = client_data.get("city")
        device_info.latitude = client_data.get("latitude")
        device_info.longitude = client_data.get("longitude")
        
        # Store any additional client data
        filtered_client_data = {k: v for k, v in client_data.items() if k not in [
            "manufacturer", "model", "os_version", "app_version", "screen_resolution",
            "network_type", "device_language", "battery_level", "is_rooted",
            "security_patch_level", "country_code", "region", "city", "latitude", "longitude",
            "android_id", "cpu_info", "total_memory", "available_memory", "total_storage", 
            "available_storage"
        ]}
        device_info.client_data = filtered_client_data
    
    logger.debug(f"Device info captured: {device_info.model=}, {device_info.manufacturer=}, {device_info.device_type=}")
    return device_info


async def verify_token(
    token: str, 
    request: Request,
    jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
) -> Dict[str, Any]:
    """Verify JWT token and return token information"""
    try:
        # Check if token is blacklisted
        if await jwt_repo.is_jwt_blacklisted(jwt=token):
            raise AuthorizationHeaderException("Token has been revoked")
        
        # Decode token and extract data
        token_data = jwt_generator.retrieve_details_from_token(token)
        
        # Verify IP address if enabled
        client_ip = get_client_ip(request)
        if settings.JWT_IP_CHECK_ENABLED and not await jwt_repo.validate_token_ip(token, client_ip):
            logger.warning(f"IP mismatch detected. Token IP vs Current: {await jwt_repo.get_token_ip(token)} vs {client_ip}")
            raise AuthorizationHeaderException("IP address mismatch - security violation")
        
        # Update last used timestamp
        await jwt_repo.update_last_used(token)
        
        return token_data
        
    except SecurityException as security_error:
        logger.warning(f"Security exception during token verification: {str(security_error)}")
        raise AuthorizationHeaderException(detail=str(security_error))
    except JWTError as jwt_error:
        logger.warning(f"JWT error during token verification: {str(jwt_error)}")
        raise AuthorizationHeaderException(detail="Could not validate credentials")


class RoleChecker:
    """
    Role-based access control dependency.
    Use this to protect routes based on user roles.
    """
    def __init__(self, allowed_roles: List[UserTypeEnum]):
        self.allowed_roles = allowed_roles

    async def __call__(
        self, 
        request: Request,
        token: str = Depends(oauth2_scheme),
        jwt_repo: JwtRecordCRUDRepository = Depends(get_repository(repo_type=JwtRecordCRUDRepository))
    ):
        # Verify token first
        token_data = await verify_token(token, request, jwt_repo)
        
        # Check if user's role is in allowed roles
        user_type = token_data.get("user_type", "RIDER")
        
        if not any(role.value == user_type for role in self.allowed_roles):
            logger.warning(f"Unauthorized access attempt: User with role {user_type} tried to access resource requiring {self.allowed_roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return token_data


# Predefined role checkers for convenience
def admin_required():
    return RoleChecker([UserTypeEnum.ADMIN])


def driver_required():
    return RoleChecker([UserTypeEnum.DRIVER])


def rider_required():
    return RoleChecker([UserTypeEnum.RIDER])


def rider_or_driver_required():
    return RoleChecker([UserTypeEnum.RIDER, UserTypeEnum.DRIVER])