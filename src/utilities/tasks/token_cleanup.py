import asyncio
from datetime import datetime
from src.repository.crud.jwt import JwtRecordCRUDRepository
from src.repository.database import async_db
from src.utilities.logging.logger import logger

async def cleanup_expired_tokens():
    """Background task to clean up expired tokens"""
    logger.info("Starting expired token cleanup task")
    
    try:
        async for session in async_db.get_session():
            jwt_repo = JwtRecordCRUDRepository(async_session=session)
            await jwt_repo.cleanup_expired_tokens()
            logger.info("Expired token cleanup completed")
    except Exception as e:
        logger.error(f"Error during token cleanup: {str(e)}")

async def start_token_cleanup_task():
    """Start the token cleanup task as a background process"""
    while True:
        await cleanup_expired_tokens()
        # Run once every 24 hours
        await asyncio.sleep(24 * 60 * 60)
