from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.utilities.exceptions.database import EntityAlreadyExists


async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "data": [],
            "message": "An internal server error occurred",
            "error": str(exc),
            "status": False
        },
    )

class UserNotFoundException(HTTPException):
    def __init__(self, detail: str = "User not found"):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class UserAlreadyExistsException(HTTPException):
    def __init__(self, detail: str = "User already exists"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class InvalidCredentialsException(HTTPException):
    def __init__(self, detail: str = "Invalid credentials"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class AuthorizationHeaderException(HTTPException):
    def __init__(self, detail: str = "Authorization header missing or invalid"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class SecurityException(Exception):
    """Base security exception for authentication and authorization issues"""


class EntityDoesNotExistException(Exception):
    """Thrown when an entity doesn't exist in the database"""
    def __init__(self, detail: str = "Authorization header missing or invalid"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class InternalServerErrorException(Exception):
    """Thrown when an unexpected server error occurs"""

# Exception handlers
async def user_not_found_exception_handler(request: Request, exc: UserNotFoundException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "data": [],
            "message": exc.detail,
            "error": "User not found",
            "status": False
        },
    )

async def user_already_exists_exception_handler(request: Request, exc: UserAlreadyExistsException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "data": [],
            "message": exc.detail,
            "error": "User already exists",
            "status": False
        },
    )

async def invalid_credentials_exception_handler(request: Request, exc: InvalidCredentialsException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "data": [],
            "message": exc.detail,
            "error": "Invalid credentials",
            "status": False
        },
    )

async def authorization_header_exception_handler(request: Request, exc: AuthorizationHeaderException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "data": [],
            "message": exc.detail,
            "error": "Authorization header missing or invalid",
            "status": False
        },
        headers=exc.headers,
    )

async def security_exception_handler(request: Request, exc: SecurityException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "data": [],
            "message": str(exc),
            "error": "Security exception",
            "status": False
        },
    )

async def entity_does_not_exist_exception_handler(request: Request, exc: EntityDoesNotExistException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "data": [],
            "message": str(exc),
            "error": "Entity does not exist",
            "status": False
        },
    )

async def internal_server_error_exception_handler(request: Request, exc: InternalServerErrorException):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "data": [],
            "message": str(exc),
            "error": "Internal server error",
            "status": False
        },
    )

async def entity_already_exists_exception_handler(request: Request, exc: EntityAlreadyExists):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "data": [],
            "message": str(exc),
            "error": "Entity already exists",
            "status": False
        },
    )

from fastapi import FastAPI

def register_exception_handlers(app: FastAPI):
    app.add_exception_handler(UserNotFoundException, user_not_found_exception_handler)
    app.add_exception_handler(UserAlreadyExistsException, user_already_exists_exception_handler)
    app.add_exception_handler(InvalidCredentialsException, invalid_credentials_exception_handler)
    app.add_exception_handler(AuthorizationHeaderException, authorization_header_exception_handler)
    app.add_exception_handler(SecurityException, security_exception_handler)
    app.add_exception_handler(EntityDoesNotExistException, entity_does_not_exist_exception_handler)
    app.add_exception_handler(EntityAlreadyExists, entity_already_exists_exception_handler)
    app.add_exception_handler(InternalServerErrorException, internal_server_error_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
