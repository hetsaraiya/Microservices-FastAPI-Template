"""enhance jwt record table with android device info

Revision ID: e4f6d9ab3c8d
Revises: b5e8c7de3f5c
Create Date: 2023-07-01 12:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from alembic import op

# revision identifiers, used by Alembic.
revision = "e4f6d9ab3c8d"
down_revision = "b5e8c7de3f5c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to the jwt_record table
    
    # Add token type and expiration fields first
    op.add_column("jwt_record", sa.Column("token_type", sa.String(length=20), nullable=True, server_default="access"))
    op.add_column("jwt_record", sa.Column("expires_at", sa.BigInteger(), nullable=True))
    
    # Add device index
    op.create_index(op.f("ix_jwt_record_device_id"), "jwt_record", ["device_id"], unique=False)
    
    # Add Android specific fields
    op.add_column("jwt_record", sa.Column("manufacturer", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("model", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("os_version", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("app_version", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("screen_resolution", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("network_type", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("device_language", sa.String(length=20), nullable=True))
    op.add_column("jwt_record", sa.Column("battery_level", sa.Float(), nullable=True))
    op.add_column("jwt_record", sa.Column("is_rooted", sa.Boolean(), nullable=True))
    op.add_column("jwt_record", sa.Column("android_id", sa.String(length=255), nullable=True))
    
    # Add Hardware information
    op.add_column("jwt_record", sa.Column("cpu_info", sa.String(length=255), nullable=True))
    op.add_column("jwt_record", sa.Column("total_memory", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("available_memory", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("total_storage", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("available_storage", sa.String(length=50), nullable=True))
    
    # Add location data columns
    op.add_column("jwt_record", sa.Column("country_code", sa.String(length=10), nullable=True))
    op.add_column("jwt_record", sa.Column("region", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("city", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("latitude", sa.Float(), nullable=True))
    op.add_column("jwt_record", sa.Column("longitude", sa.Float(), nullable=True))
    
    # Add security info columns
    op.add_column("jwt_record", sa.Column("device_hash", sa.String(length=255), nullable=True))
    op.add_column("jwt_record", sa.Column("last_security_patch", sa.String(length=50), nullable=True))
    
    # Add client data column
    op.add_column("jwt_record", sa.Column("client_data", JSONB(), nullable=True))


def downgrade() -> None:
    # Remove new columns in reverse order
    op.drop_column("jwt_record", "client_data")
    op.drop_column("jwt_record", "last_security_patch")
    op.drop_column("jwt_record", "device_hash")
    op.drop_column("jwt_record", "longitude")
    op.drop_column("jwt_record", "latitude")
    op.drop_column("jwt_record", "city")
    op.drop_column("jwt_record", "region")
    op.drop_column("jwt_record", "country_code")
    op.drop_column("jwt_record", "available_storage")
    op.drop_column("jwt_record", "total_storage")
    op.drop_column("jwt_record", "available_memory")
    op.drop_column("jwt_record", "total_memory")
    op.drop_column("jwt_record", "cpu_info")
    op.drop_column("jwt_record", "android_id")
    op.drop_column("jwt_record", "is_rooted")
    op.drop_column("jwt_record", "battery_level")
    op.drop_column("jwt_record", "device_language")
    op.drop_column("jwt_record", "network_type")
    op.drop_column("jwt_record", "screen_resolution")
    op.drop_column("jwt_record", "app_version")
    op.drop_column("jwt_record", "os_version")
    op.drop_column("jwt_record", "model")
    op.drop_column("jwt_record", "manufacturer")
    op.drop_index(op.f("ix_jwt_record_device_id"), table_name="jwt_record")
    op.drop_column("jwt_record", "expires_at")
    op.drop_column("jwt_record", "token_type")