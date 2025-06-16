import datetime
import uuid
import sqlalchemy
from sqlalchemy.orm import Mapped as SQLAlchemyMapped, mapped_column as sqlalchemy_mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID
from uuid import uuid4
from sqlalchemy import ForeignKey

from src.repository.table import Base, generate_uuid

class JwtRecord(Base):
    __tablename__ = "jwt_record"

    id: SQLAlchemyMapped[uuid.UUID] = sqlalchemy_mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    jwt: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=1024), nullable=False, unique=True, index=True)
    user_id: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id"), nullable=False, index=True
    )
    
    # Reference to device - now using android_id
    android_id: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), 
                                                                ForeignKey("device.android_id"), nullable=True, index=True)
    
    # Token status
    is_blacklisted: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=False, default=False)
    token_type: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=20), nullable=True, default="access")
    
    # Timestamps
    created_at: SQLAlchemyMapped[int] = sqlalchemy_mapped_column(
        sqlalchemy.BigInteger, nullable=False
    )
    updated_at: SQLAlchemyMapped[int] = sqlalchemy_mapped_column(
        sqlalchemy.BigInteger,
        nullable=True,
        server_onupdate=sqlalchemy.text("extract(epoch from now())::bigint"),
    )
    last_used_at: SQLAlchemyMapped[int] = sqlalchemy_mapped_column(
        sqlalchemy.BigInteger, nullable=True
    )
    expires_at: SQLAlchemyMapped[int] = sqlalchemy_mapped_column(
        sqlalchemy.BigInteger, nullable=True
    )
    
    # Relationship with Device model
    device = relationship("Device", back_populates="jwt_records")
    # Add relationship with User model
    user = relationship("User", backref="jwt_records")

    __mapper_args__ = {"eager_defaults": True}