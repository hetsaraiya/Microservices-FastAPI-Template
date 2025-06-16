import datetime
import enum
import uuid

import sqlalchemy
from sqlalchemy.orm import Mapped as SQLAlchemyMapped, mapped_column as sqlalchemy_mapped_column
from sqlalchemy.sql import functions as sqlalchemy_functions
from sqlalchemy.dialects.postgresql import UUID
from uuid import uuid4

from src.repository.table import Base, generate_uuid


class UserTypeEnum(str, enum.Enum):
    DRIVER = "DRIVER"
    RIDER = "RIDER"
    ADMIN = "ADMIN"


class User(Base):  # type: ignore
    __tablename__ = "user"

    id: SQLAlchemyMapped[uuid.UUID] = sqlalchemy_mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    username: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(
        sqlalchemy.String(length=64), nullable=False, unique=True
    )
    email: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=64), nullable=False, unique=True)
    _hashed_password: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=1024), nullable=True)
    _hash_salt: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=1024), nullable=True)
    is_verified: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=False, default=False)
    is_active: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=False, default=False)
    is_logged_in: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=False, default=False)

    # User Type for RBAC
    user_type: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(
        sqlalchemy.String(length=32), 
        nullable=False, 
        default=UserTypeEnum.RIDER.value
    )

    # Permissions Fields
    is_staff: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, default=False)
    is_superuser: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, default=False)
    is_active: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, default=True)

    created_at: SQLAlchemyMapped[datetime.datetime] = sqlalchemy_mapped_column(
        sqlalchemy.DateTime(timezone=True), nullable=False, server_default=sqlalchemy_functions.now()
    )
    updated_at: SQLAlchemyMapped[datetime.datetime] = sqlalchemy_mapped_column(
        sqlalchemy.DateTime(timezone=True),
        nullable=True,
        server_onupdate=sqlalchemy.schema.FetchedValue(for_update=True),
    )

    __mapper_args__ = {"eager_defaults": True}

    @property
    def hashed_password(self) -> str:
        return self._hashed_password

    def set_hashed_password(self, hashed_password: str) -> None:
        self._hashed_password = hashed_password

    @property
    def hash_salt(self) -> str:
        return self._hash_salt

    def set_hash_salt(self, hash_salt: str) -> None:
        self._hash_salt = hash_salt
        
    def has_role(self, role: UserTypeEnum) -> bool:
        """Check if user has a specific role"""
        return self.user_type == role.value
        
    def is_admin(self) -> bool:
        """Check if user has admin role"""
        return self.user_type == UserTypeEnum.ADMIN.value
        
    def is_driver(self) -> bool:
        """Check if user has driver role"""
        return self.user_type == UserTypeEnum.DRIVER.value
        
    def is_rider(self) -> bool:
        """Check if user has rider role"""
        return self.user_type == UserTypeEnum.RIDER.value