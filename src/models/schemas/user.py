import datetime
import enum
import uuid
from typing import Optional

import pydantic

from src.models.db.user import UserTypeEnum
from src.models.schemas.base import BaseSchemaModel


class UserInCreate(BaseSchemaModel):
    username: str
    email: pydantic.EmailStr
    password: str
    user_type: UserTypeEnum = UserTypeEnum.RIDER


class UserInUpdate(BaseSchemaModel):
    username: str | None = None
    email: str | None = None
    password: str | None = None
    user_type: UserTypeEnum | None = None


class UserInLogin(BaseSchemaModel):
    username: str
    password: str


class UserWithToken(BaseSchemaModel):
    token: str
    username: str
    email: pydantic.EmailStr
    user_type: str
    is_verified: bool
    is_active: bool
    is_logged_in: bool
    created_at: datetime.datetime
    updated_at: datetime.datetime | None


class UserInResponse(BaseSchemaModel):
    id: uuid.UUID
    authorized_user: UserWithToken