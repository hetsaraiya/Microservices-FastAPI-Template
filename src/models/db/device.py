import datetime
import uuid
import sqlalchemy
from sqlalchemy.orm import Mapped as SQLAlchemyMapped, mapped_column as sqlalchemy_mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB, UUID
from uuid import uuid4

from src.repository.table import Base, generate_uuid


class Device(Base):
    __tablename__ = "device"

    id: SQLAlchemyMapped[uuid.UUID] = sqlalchemy_mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid4
    )

    # Unique identifiers - android_id is now the key unique identifier
    android_id: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), nullable=False, unique=True, index=True)
    device_id: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), nullable=True, index=True)
    device_hash: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), nullable=True, index=True)
    
    # Basic device info
    device_name: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), nullable=True)
    device_type: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    ip_address: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=45), nullable=True, index=True)
    user_agent: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=500), nullable=True)
    
    # Android specific fields
    manufacturer: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=100), nullable=True)
    model: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=100), nullable=True)
    os_version: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    app_version: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    screen_resolution: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    network_type: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    device_language: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=20), nullable=True)
    battery_level: SQLAlchemyMapped[float] = sqlalchemy_mapped_column(sqlalchemy.Float, nullable=True)
    is_rooted: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=True)
    
    # iOS specific fields
    device_model: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)  # e.g., iPhone12,1
    ios_version: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=20), nullable=True)  # iOS version
    is_jailbroken: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=True)
    
    # Web browser specific fields
    browser_name: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    browser_version: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=20), nullable=True)
    
    # Hardware information
    cpu_info: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), nullable=True)
    total_memory: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    available_memory: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    total_storage: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    available_storage: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    
    # Location data
    country_code: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=10), nullable=True)
    region: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=100), nullable=True)
    city: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=100), nullable=True)
    latitude: SQLAlchemyMapped[float] = sqlalchemy_mapped_column(sqlalchemy.Float, nullable=True)
    longitude: SQLAlchemyMapped[float] = sqlalchemy_mapped_column(sqlalchemy.Float, nullable=True)
    
    # Security info
    last_security_patch: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=50), nullable=True)
    
    # Store additional client data as JSON
    client_data: SQLAlchemyMapped[dict] = sqlalchemy_mapped_column(JSONB, nullable=True)
    
    # Device status
    is_blacklisted: SQLAlchemyMapped[bool] = sqlalchemy_mapped_column(sqlalchemy.Boolean, nullable=False, default=False)
    blacklist_reason: SQLAlchemyMapped[str] = sqlalchemy_mapped_column(sqlalchemy.String(length=255), nullable=True)
    
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
    
    # Relationships
    jwt_records = relationship("JwtRecord", back_populates="device", cascade="all, delete-orphan")
    
    __mapper_args__ = {"eager_defaults": True}