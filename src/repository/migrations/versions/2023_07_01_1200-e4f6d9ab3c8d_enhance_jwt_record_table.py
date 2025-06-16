"""enhance jwt record table

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
    # Enhanced columns for jwt_record table
    
    # Add Android specific columns
    op.add_column("jwt_record", sa.Column("manufacturer", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("model", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("os_version", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("app_version", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("screen_resolution", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("network_type", sa.String(length=50), nullable=True))
    op.add_column("jwt_record", sa.Column("device_language", sa.String(length=20), nullable=True))
    op.add_column("jwt_record", sa.Column("battery_level", sa.Float(), nullable=True))
    op.add_column("jwt_record", sa.Column("is_rooted", sa.Boolean(), nullable=True))
    
    # Add location data columns
    op.add_column("jwt_record", sa.Column("country_code", sa.String(length=10), nullable=True))
    op.add_column("jwt_record", sa.Column("region", sa.String(length=100), nullable=True))
    op.add_column("jwt_record", sa.Column("city", sa.String(length=100), nullable=True))
    
    # Add security info columns
    op.add_column("jwt_record", sa.Column("device_hash", sa.String(length=255), nullable=True))
    op.add_column("jwt_record", sa.Column("last_security_patch", sa.String(length=50), nullable=True))
    
    # Add client data column
    op.add_column("jwt_record", sa.Column("client_data", JSONB(), nullable=True))
    
    # Add token type column
    op.add_column("jwt_record", sa.Column("token_type", sa.String(length=20), nullable=True, server_default="access"))
    
    # Add expiration timestamp
    op.add_column("jwt_record", sa.Column("expires_at", sa.BigInteger(), nullable=True))
    
    # Add index on device_id for faster queries
    op.create_index(op.f("ix_jwt_record_device_id"), "jwt_record", ["device_id"], unique=False)


def downgrade() -> None:
    # Remove new columns in reverse order
    op.drop_index(op.f("ix_jwt_record_device_id"), table_name="jwt_record")
    op.drop_column("jwt_record", "expires_at")
    op.drop_column("jwt_record", "token_type")
    op.drop_column("jwt_record", "client_data")
    op.drop_column("jwt_record", "last_security_patch")
    op.drop_column("jwt_record", "device_hash")
    op.drop_column("jwt_record", "city")
    op.drop_column("jwt_record", "region")
    op.drop_column("jwt_record", "country_code")
    op.drop_column("jwt_record", "is_rooted")
    op.drop_column("jwt_record", "battery_level")
    op.drop_column("jwt_record", "device_language")
    op.drop_column("jwt_record", "network_type")
    op.drop_column("jwt_record", "screen_resolution")
    op.drop_column("jwt_record", "app_version")
    op.drop_column("jwt_record", "os_version")
    op.drop_column("jwt_record", "model")
    op.drop_column("jwt_record", "manufacturer")
