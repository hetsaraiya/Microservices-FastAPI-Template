"""create separate device table with android_id as primary identifier

Revision ID: a3b6d8c5e7f9
Revises: e4f6d9ab3c8d
Create Date: 2025-03-23 12:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from alembic import op

# revision identifiers, used by Alembic.
revision = "a3b6d8c5e7f9"
down_revision = "e4f6d9ab3c8d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create new device table with android_id as the unique identifier
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        
        # Unique identifiers - android_id is now the primary unique identifier
        sa.Column("android_id", sa.String(length=255), nullable=False, unique=True, index=True),
        sa.Column("device_id", sa.String(length=255), nullable=True, index=True),
        sa.Column("device_hash", sa.String(length=255), nullable=True, index=True),
        
        # Basic device info
        sa.Column("device_name", sa.String(length=255), nullable=True),
        sa.Column("device_type", sa.String(length=50), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True, index=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        
        # Android specific fields
        sa.Column("manufacturer", sa.String(length=100), nullable=True),
        sa.Column("model", sa.String(length=100), nullable=True),
        sa.Column("os_version", sa.String(length=50), nullable=True),
        sa.Column("app_version", sa.String(length=50), nullable=True),
        sa.Column("screen_resolution", sa.String(length=50), nullable=True),
        sa.Column("network_type", sa.String(length=50), nullable=True),
        sa.Column("device_language", sa.String(length=20), nullable=True),
        sa.Column("battery_level", sa.Float(), nullable=True),
        sa.Column("is_rooted", sa.Boolean(), nullable=True),
        
        # Hardware information
        sa.Column("cpu_info", sa.String(length=255), nullable=True),
        sa.Column("total_memory", sa.String(length=50), nullable=True),
        sa.Column("available_memory", sa.String(length=50), nullable=True),
        sa.Column("total_storage", sa.String(length=50), nullable=True),
        sa.Column("available_storage", sa.String(length=50), nullable=True),
        
        # Location data
        sa.Column("country_code", sa.String(length=10), nullable=True),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column("city", sa.String(length=100), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        
        # Security info
        sa.Column("last_security_patch", sa.String(length=50), nullable=True),
        
        # Additional data
        sa.Column("client_data", JSONB(), nullable=True),
        
        # Device status
        sa.Column("is_blacklisted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("blacklist_reason", sa.String(length=255), nullable=True),
        
        # Timestamps
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=True, 
                  server_default=sa.text("extract(epoch from now())::bigint")),
        sa.Column("last_used_at", sa.BigInteger(), nullable=True),
        
        sa.PrimaryKeyConstraint("id")
    )
    
    # Create indexes for device table
    op.create_index("ix_device_android_id", "device", ["android_id"], unique=True)
    op.create_index("ix_device_device_id", "device", ["device_id"], unique=False)
    op.create_index("ix_device_device_hash", "device", ["device_hash"], unique=False)
    op.create_index("ix_device_ip_address", "device", ["ip_address"], unique=False)
    
    # Insert data from jwt_record into device
    # First need to handle potential NULL android_id values
    op.execute("""
    UPDATE jwt_record 
    SET android_id = COALESCE(android_id, device_id) 
    WHERE android_id IS NULL AND device_id IS NOT NULL
    """)
    
    # For records that still have NULL android_id, generate UUID
    op.execute("""
    UPDATE jwt_record 
    SET android_id = md5(random()::text || clock_timestamp()::text)
    WHERE android_id IS NULL
    """)
    
    # Insert data using android_id as primary key
    op.execute("""
    INSERT INTO device (
        android_id, device_id, device_hash, device_name, device_type, ip_address, user_agent,
        manufacturer, model, os_version, app_version, screen_resolution, network_type, device_language,
        battery_level, is_rooted, cpu_info, total_memory, available_memory, total_storage, available_storage,
        country_code, region, city, latitude, longitude, last_security_patch, client_data,
        is_blacklisted, created_at, last_used_at
    )
    SELECT 
        android_id, device_id, device_hash, device_name, device_type, ip_address, user_agent,
        manufacturer, model, os_version, app_version, screen_resolution, network_type, device_language,
        battery_level, is_rooted, cpu_info, total_memory, available_memory, total_storage, available_storage,
        country_code, region, city, latitude, longitude, last_security_patch, client_data,
        false, created_at, last_used_at
    FROM jwt_record
    WHERE android_id IS NOT NULL
    GROUP BY android_id, device_id, device_hash, device_name, device_type, ip_address, user_agent,
        manufacturer, model, os_version, app_version, screen_resolution, network_type, device_language,
        battery_level, is_rooted, cpu_info, total_memory, available_memory, total_storage, available_storage,
        country_code, region, city, latitude, longitude, last_security_patch, client_data,
        created_at, last_used_at
    """)
    
    # Add android_id column to jwt_record if it doesn't exist yet
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'jwt_record' AND column_name = 'android_id'
        ) THEN
            ALTER TABLE jwt_record ADD COLUMN android_id VARCHAR(255);
        END IF;
    END
    $$;
    """)
    
    # Add foreign key constraint
    op.create_foreign_key(
        "fk_jwt_record_android_id", "jwt_record", "device", 
        ["android_id"], ["android_id"]
    )
    
    # Ensure all JWT records have android_id value
    op.execute("""
    UPDATE jwt_record j
    SET android_id = d.android_id
    FROM device d
    WHERE j.device_id = d.device_id AND j.android_id IS NULL AND d.device_id IS NOT NULL
    """)


def downgrade() -> None:
    # Drop the foreign key constraint
    op.drop_constraint("fk_jwt_record_android_id", "jwt_record", type_="foreignkey")
    
    # Drop the device table
    op.drop_table("device")