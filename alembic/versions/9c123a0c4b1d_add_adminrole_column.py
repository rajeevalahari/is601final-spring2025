"""add AdminRole ENUM and admin_role column

Revision ID: 9c123a0c4b1d
Revises: 25d814bc83ed
Create Date: 2025‑05‑05 22:10:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "9c123a0c4b1d"
down_revision: Union[str, None] = "25d814bc83ed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1) Create the new ENUM type with a single value
    op.execute('CREATE TYPE "AdminRole" AS ENUM (\'SUPERADMIN\');')

    # 2) Add nullable column to users table
    op.add_column(
        "users",
        sa.Column(
            "admin_role",
            sa.Enum(name="AdminRole"),
            nullable=True,
        ),
    )

    # 3) Optional index for quick look‑ups
    op.create_index("ix_users_admin_role", "users", ["admin_role"])


def downgrade() -> None:
    op.drop_index("ix_users_admin_role", table_name="users")
    op.drop_column("users", "admin_role")
    op.execute('DROP TYPE "AdminRole";')
