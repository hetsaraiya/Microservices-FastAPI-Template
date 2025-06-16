"""update jwt record table

Revision ID: b5e8c7de3f5c
Revises: a7d2e45fb8d2
Create Date: 2023-06-20 16:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b5e8c7de3f5c"
down_revision = "a7d2e45fb8d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create jwt_record table with enhanced columns
    op.create_table(
        "jwt_record",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("jwt", sa.String(length=1024), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.String(length=255), nullable=True),
        sa.Column("device_name", sa.String(length=255), nullable=True),
        sa.Column("device_type", sa.String(length=50), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column("is_blacklisted", sa.Boolean(), nullable=False, default=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.BigInteger(), nullable=True),
        sa.Column("last_used_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("jwt"),
        sa.Index("ix_jwt_record_jwt", "jwt"),
        sa.Index("ix_jwt_record_user_id", "user_id"),
    )


def downgrade() -> None:
    op.drop_table("jwt_record")
