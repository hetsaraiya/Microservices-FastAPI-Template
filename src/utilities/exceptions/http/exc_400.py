from fastapi import HTTPException, status


async def http_exc_400_credentials_bad_signup_request() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User signup failed. Username or email already exists.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def http_exc_400_credentials_bad_signin_request() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Incorrect username, email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )