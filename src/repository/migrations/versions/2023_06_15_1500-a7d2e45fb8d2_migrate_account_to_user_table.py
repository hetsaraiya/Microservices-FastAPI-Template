"""migrate account to user table

Revision ID: a7d2e45fb8d2
Revises: 60d1844cb5d3
Create Date: 2023-06-15 15:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a7d2e45fb8d2"
down_revision = "60d1844cb5d3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create user table with same structure as account
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=64), nullable=False),
        sa.Column("_hashed_password", sa.String(length=1024), nullable=True),
        sa.Column("_hash_salt", sa.String(length=1024), nullable=True),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_logged_in", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    
    # Copy data from account to user table
    op.execute(
        """
        INSERT INTO "user" (id, username, email, _hashed_password, _hash_salt, is_verified, 
                          is_active, is_logged_in, created_at, updated_at)
        SELECT id, username, email, _hashed_password, _hash_salt, is_verified, 
               is_active, is_logged_in, created_at, updated_at
        FROM account
        """
    )
    
    # Drop the old account table
    op.drop_table("account")


def downgrade() -> None:
    # Create account table with same structure as user
    op.create_table(
        "account",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=64), nullable=False),
        sa.Column("_hashed_password", sa.String(length=1024), nullable=True),
        sa.Column("_hash_salt", sa.String(length=1024), nullable=True),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_logged_in", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    
    # Copy data from user to account table
    op.execute(
        """
        INSERT INTO account (id, username, email, _hashed_password, _hash_salt, is_verified, 
                          is_active, is_logged_in, created_at, updated_at)
        SELECT id, username, email, _hashed_password, _hash_salt, is_verified, 
               is_active, is_logged_in, created_at, updated_at
        FROM "user"
        """
    )
    
    # Drop the new user table
    op.drop_table("user")