from fastapi import HTTPException, status


async def http_404_exc_id_not_found_request(id: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with id '{id}' not found",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def http_404_exc_username_not_found_request(username: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with username '{username}' not found",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def http_404_exc_email_not_found_request(email: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with email '{email}' not found",
        headers={"WWW-Authenticate": "Bearer"},
    )