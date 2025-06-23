from redis import StrictRedis, Redis


from src.config.manager import settings

from src.config.settings.base import BackendBaseSettings
from src.utilities.logging.logger import logger

def get_redis_client() -> Redis:
    """Creates and returns a Redis client instance."""
    try:
        logger.info("Attempting to connect to Redis...")
        redis_client = Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            # ssl=settings.REDIS_SSL,
            # ssl_cert_reqs=None,
            # socket_connect_timeout=5,
            # decode_responses=True,
            db=0
        )
        redis_client.ping()  # Verify connection
        logger.info("Successfully connected to Redis.")
        return redis_client
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise SystemExit(f"Worker exiting: Cannot connect to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}") from e
