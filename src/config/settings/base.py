import logging
import pathlib
import os

import decouple

# Updated import for Pydantic v2
try:
    from pydantic_settings import BaseSettings
    from pydantic import BaseModel, PostgresDsn
except ImportError:
    # Fallback for older versions
    from pydantic import BaseSettings, BaseModel, PostgresDsn  # type: ignore

ROOT_DIR: pathlib.Path = pathlib.Path(__file__).parent.parent.parent.parent.resolve()

# Load environment files at module level
def get_config():
    main_env_file = f"{str(ROOT_DIR)}/.env"
    print(f"Loading environment configuration from: {main_env_file}")
    
    # First load main .env to get ENVIRONMENT
    config = decouple.Config(decouple.RepositoryEnv(main_env_file))
    environment = config("ENVIRONMENT", default="LOCAL")
    print(f"Environment set to: {environment}")
    
    # Based on ENVIRONMENT, load the specific env file
    env_file_mapping = {
        "DEV": ".env.development",
        "PROD": ".env.production",
        "LOCAL": ".env.local"
    }
    
    specific_env_file = env_file_mapping.get(environment)
    if specific_env_file:
        env_file_path = f"{str(ROOT_DIR)}/{specific_env_file}"
        if os.path.exists(env_file_path):
            print(f"Loading environment file: {specific_env_file}")
            # Create a new config that searches both files
            return decouple.Config(decouple.RepositoryEnv(env_file_path))
    
    return config

# Create config object with correct search paths
config = get_config()

class BackendBaseSettings(BaseSettings):
    TITLE: str = "Backend API"
    VERSION: str = "0.1.0"
    TIMEZONE: str = "UTC"
    DESCRIPTION: str | None = None
    DEBUG: bool = config("DEBUG", cast=bool, default=False)

    SERVER_HOST: str = config("BACKEND_SERVER_HOST", cast=str)
    SERVER_PORT: int = config("BACKEND_SERVER_PORT", cast=int)
    SERVER_WORKERS: int = config("BACKEND_SERVER_WORKERS", cast=int)
    API_PREFIX: str = "/api"
    DOCS_URL: str = "/docs"
    OPENAPI_URL: str = "/openapi.json"
    REDOC_URL: str = "/redoc"
    OPENAPI_PREFIX: str = ""

    DB_POSTGRES_HOST: str = config("POSTGRES_HOST", cast=str)
    DB_MAX_POOL_CON: int = config("DB_MAX_POOL_CON", cast=int)
    DB_POSTGRES_NAME: str = config("POSTGRES_DB", cast=str)
    DB_POSTGRES_PASSWORD: str = config("POSTGRES_PASSWORD", cast=str)
    DB_POOL_SIZE: int = config("DB_POOL_SIZE", cast=int)
    DB_POOL_OVERFLOW: int = config("DB_POOL_OVERFLOW", cast=int)
    DB_POSTGRES_PORT: int = config("POSTGRES_PORT", cast=int)
    DB_POSTGRES_SCHEMA: str = config("POSTGRES_SCHEMA", cast=str)
    DB_TIMEOUT: int = config("DB_TIMEOUT", cast=int)
    DB_POSTGRES_USERNAME: str = config("POSTGRES_USERNAME", cast=str)

    IS_DB_ECHO_LOG: bool = config("IS_DB_ECHO_LOG", cast=bool)
    IS_DB_FORCE_ROLLBACK: bool = config("IS_DB_FORCE_ROLLBACK", cast=bool)
    IS_DB_EXPIRE_ON_COMMIT: bool = config("IS_DB_EXPIRE_ON_COMMIT", cast=bool)

    API_TOKEN: str = config("API_TOKEN", cast=str)
    AUTH_TOKEN: str = config("AUTH_TOKEN", cast=str)
    JWT_TOKEN_PREFIX: str = config("JWT_TOKEN_PREFIX", cast=str)
    JWT_SECRET_KEY: str = config("JWT_SECRET_KEY", cast=str)
    JWT_SUBJECT: str = config("JWT_SUBJECT", cast=str)
    JWT_MIN: int = config("JWT_MIN", cast=int)
    JWT_HOUR: int = config("JWT_HOUR", cast=int)
    JWT_DAY: int = config("JWT_DAY", cast=int)
    JWT_ACCESS_TOKEN_EXPIRATION_TIME: int = JWT_MIN * JWT_HOUR * JWT_DAY

    # JWT Token settings
    JWT_SECRET_KEY: str = config("JWT_SECRET_KEY", cast=str)
    JWT_SUBJECT: str = config("JWT_SUBJECT", cast=str)
    JWT_FORGOT_PASSWORD_SUBJECT: str = config("JWT_FORGOT_PASSWORD_SUBJECT", default="password-reset", cast=str)
    JWT_TOKEN_PREFIX: str = config("JWT_TOKEN_PREFIX", cast=str)
    JWT_ALGORITHM: str = config("JWT_ALGORITHM", cast=str)
    JWT_MIN: int = config("JWT_MIN", cast=int)
    JWT_HOUR: int = config("JWT_HOUR", cast=int)
    JWT_DAY: int = config("JWT_DAY", cast=int)
    JWT_ACCESS_TOKEN_EXPIRATION_TIME: int = JWT_MIN * JWT_HOUR * JWT_DAY
    
    # JWT Device and Security Settings
    JWT_MAX_DEVICES: int = config("JWT_MAX_DEVICES", default=5, cast=int)
    JWT_IP_CHECK_ENABLED: bool = config("JWT_IP_CHECK_ENABLED", default=False, cast=bool)
    JWT_DEVICE_SECRET: str = config("JWT_DEVICE_SECRET", default="device-secret-key", cast=str)
    JWT_REFRESH_TOKEN_EXPIRATION_TIME: int = config("JWT_REFRESH_TOKEN_EXPIRATION_TIME", default=30, cast=int)  # Days
    JWT_SUSPICIOUS_ACTIVITY_MONITORING: bool = config("JWT_SUSPICIOUS_ACTIVITY_MONITORING", default=True, cast=bool)
    JWT_ANDROID_DATA_COLLECTION: bool = config("JWT_ANDROID_DATA_COLLECTION", default=True, cast=bool)

    IS_ALLOWED_CREDENTIALS: bool = config("IS_ALLOWED_CREDENTIALS", cast=bool)
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",  # React default port
        "http://0.0.0.0:3000",
        "http://127.0.0.1:3000",  # React docker port
        "http://127.0.0.1:3001",
        "http://localhost:5173",  # Qwik default port
        "http://0.0.0.0:5173",
        "http://127.0.0.1:5173",  # Qwik docker port
        "http://127.0.0.1:5174",
    ]
    ALLOWED_METHODS: list[str] = ["*"]
    ALLOWED_HEADERS: list[str] = ["*"]

    LOGGING_LEVEL: int = logging.INFO
    LOGGERS: tuple[str, str] = ("uvicorn.asgi", "uvicorn.access")
    
    # Enhanced Logging Configuration
    LOG_LEVEL: str = config("LOG_LEVEL", default="INFO", cast=str)
    LOG_FORMAT: str = config("LOG_FORMAT", default="detailed", cast=str)  # simple, detailed, json
    LOG_DIR: str = config("LOG_DIR", default="logs", cast=str)
    LOG_ROTATION_SIZE: str = config("LOG_ROTATION_SIZE", default="10 MB", cast=str)
    LOG_RETENTION_TIME: str = config("LOG_RETENTION_TIME", default="30 days", cast=str)
    LOG_COMPRESSION: str = config("LOG_COMPRESSION", default="gz", cast=str)
    
    # Logging Feature Flags
    ENABLE_CONSOLE_LOGGING: bool = config("ENABLE_CONSOLE_LOGGING", default=True, cast=bool)
    ENABLE_FILE_LOGGING: bool = config("ENABLE_FILE_LOGGING", default=True, cast=bool)
    ENABLE_JSON_LOGGING: bool = config("ENABLE_JSON_LOGGING", default=False, cast=bool)
    ENABLE_ERROR_FILE: bool = config("ENABLE_ERROR_FILE", default=True, cast=bool)
    ENABLE_SECURITY_LOGGING: bool = config("ENABLE_SECURITY_LOGGING", default=True, cast=bool)
    ENABLE_PERFORMANCE_LOGGING: bool = config("ENABLE_PERFORMANCE_LOGGING", default=True, cast=bool)
    ENABLE_REQUEST_LOGGING: bool = config("ENABLE_REQUEST_LOGGING", default=True, cast=bool)
    ENABLE_CORRELATION_ID: bool = config("ENABLE_CORRELATION_ID", default=True, cast=bool)
    
    # Logging Security and Data Handling
    MASK_SENSITIVE_DATA: bool = config("MASK_SENSITIVE_DATA", default=True, cast=bool)
    LOG_REQUEST_BODY: bool = config("LOG_REQUEST_BODY", default=False, cast=bool)
    LOG_RESPONSE_BODY: bool = config("LOG_RESPONSE_BODY", default=False, cast=bool)
    LOG_HEADERS: bool = config("LOG_HEADERS", default=True, cast=bool)
    MAX_LOG_BODY_SIZE: int = config("MAX_LOG_BODY_SIZE", default=10000, cast=int)
    
    # Performance Monitoring
    PERFORMANCE_THRESHOLD_MS: float = config("PERFORMANCE_THRESHOLD_MS", default=1000.0, cast=float)
    
    # Async Logging
    ASYNC_LOGGING: bool = config("ASYNC_LOGGING", default=True, cast=bool)
    BACKTRACE_ENABLED: bool = config("BACKTRACE_ENABLED", default=True, cast=bool)
    DIAGNOSE_ENABLED: bool = config("DIAGNOSE_ENABLED", default=True, cast=bool)
    COLORIZE_CONSOLE: bool = config("COLORIZE_CONSOLE", default=True, cast=bool)
    
    # Security Middleware Configuration
    ENABLE_ATTACK_DETECTION: bool = config("ENABLE_ATTACK_DETECTION", default=True, cast=bool)
    ENABLE_RATE_LIMITING: bool = config("ENABLE_RATE_LIMITING", default=True, cast=bool)
    ENABLE_IP_BLOCKING: bool = config("ENABLE_IP_BLOCKING", default=True, cast=bool)
    ENABLE_USER_AGENT_FILTERING: bool = config("ENABLE_USER_AGENT_FILTERING", default=True, cast=bool)
    MAX_REQUEST_SIZE_MB: float = config("MAX_REQUEST_SIZE_MB", default=10.0, cast=float)
    BLOCK_EMPTY_USER_AGENTS: bool = config("BLOCK_EMPTY_USER_AGENTS", default=False, cast=bool)
    
    # Rate Limiting Configuration
    RATE_LIMIT_PER_MINUTE: int = config("RATE_LIMIT_PER_MINUTE", default=60, cast=int)
    RATE_LIMIT_PER_HOUR: int = config("RATE_LIMIT_PER_HOUR", default=1000, cast=int)
    RATE_LIMIT_BURST: int = config("RATE_LIMIT_BURST", default=10, cast=int)
    RATE_LIMIT_BLOCK_DURATION: int = config("RATE_LIMIT_BLOCK_DURATION", default=15, cast=int)

    HASHING_ALGORITHM_LAYER_1: str = config("HASHING_ALGORITHM_LAYER_1", cast=str)
    HASHING_ALGORITHM_LAYER_2: str = config("HASHING_ALGORITHM_LAYER_2", cast=str)
    HASHING_SALT: str = config("HASHING_SALT", cast=str)
    JWT_ALGORITHM: str = config("JWT_ALGORITHM", cast=str)

    # Redis settings
    REDIS_HOST: str = config("REDIS_HOST", cast=str, default="localhost")
    REDIS_PORT: int = config("REDIS_PORT", cast=int, default=6379)
    REDIS_DB: int = config("REDIS_DB", cast=int, default=0)
    REDIS_PASSWORD: str | None = config("REDIS_PASSWORD", cast=str, default=None)
    REDIS_SSL: bool = config("REDIS_SSL", cast=bool, default=False)

    # Email settings
    EMAIL_SENDER: str = config("EMAIL_SENDER", cast=str, default="noreply@yourdomain.com")
    SMTP_SERVER: str = config("SMTP_SERVER", cast=str, default="smtp.gmail.com")
    SMTP_PORT: int = config("SMTP_PORT", cast=int, default=587)
    SMTP_TLS: bool = config("SMTP_TLS", cast=bool, default=True)
    EMAIL_USERNAME: str = config("EMAIL_USERNAME", cast=str, default="")
    EMAIL_PASSWORD: str = config("EMAIL_PASSWORD", cast=str, default="")

    class Config:
        case_sensitive: bool = True
        validate_assignment: bool = True

    @property
    def set_backend_app_attributes(self) -> dict[str, str | bool | None]:
        """
        Set all `FastAPI` class' attributes with the custom values defined in `BackendBaseSettings`.
        """
        return {
            "title": self.TITLE,
            "version": self.VERSION,
            "debug": self.DEBUG,
            "description": self.DESCRIPTION,
            "docs_url": self.DOCS_URL,
            "openapi_url": self.OPENAPI_URL,
            "redoc_url": self.REDOC_URL,
            "openapi_prefix": self.OPENAPI_PREFIX,
            "api_prefix": self.API_PREFIX,
        }