"""create role_change_audit table"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "9a2f3d1e6b7c"
down_revision = "9c123a0c4b1d"   # ← replace with your latest revision id
branch_labels = None
depends_on = None


def upgrade() -> None:
    userrole_enum = postgresql.ENUM(
        "ANONYMOUS", "AUTHENTICATED", "MANAGER", "ADMIN",
        name="UserRole", create_type=False
    )

    op.create_table(
        "role_change_audit",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("changed_by", sa.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("old_role", userrole_enum, nullable=False),
        sa.Column("new_role", userrole_enum, nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("role_change_audit")
