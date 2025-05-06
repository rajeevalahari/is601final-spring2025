from builtins import bool, int, str
from datetime import datetime
from enum import Enum
import uuid

from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Boolean,
    func,
    Enum as SQLAlchemyEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Column, DateTime, ForeignKey
from sqlalchemy.orm import mapped_column
from sqlalchemy.sql import func

from app.database import Base


# ────────────────────────────────────────────────────────────
# ENUM TYPES
# ────────────────────────────────────────────────────────────
class AdminRole(Enum):
    """High‑privilege admin roles."""
    SUPERADMIN = "SUPERADMIN"


class UserRole(Enum):
    """Standard application roles."""
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"


# ────────────────────────────────────────────────────────────
# MODEL
# ────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    __mapper_args__ = {"eager_defaults": True}

    # Core identifiers
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nickname: Mapped[str] = Column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = Column(String(255), unique=True, nullable=False, index=True)

    # Profile
    first_name: Mapped[str] = Column(String(100), nullable=True)
    last_name: Mapped[str] = Column(String(100), nullable=True)
    bio: Mapped[str] = Column(String(500), nullable=True)
    profile_picture_url: Mapped[str] = Column(String(255), nullable=True)
    linkedin_profile_url: Mapped[str] = Column(String(255), nullable=True)
    github_profile_url: Mapped[str] = Column(String(255), nullable=True)

    # Role columns
    role: Mapped[UserRole] = Column(SQLAlchemyEnum(UserRole, name="UserRole", create_constraint=True), nullable=False)
    admin_role: Mapped[AdminRole | None] = mapped_column(
        SQLAlchemyEnum(AdminRole, name="AdminRole", create_constraint=True),
        nullable=True,
        default=None,
        index=True,
    )

    # Status flags
    is_professional: Mapped[bool] = Column(Boolean, default=False)
    professional_status_updated_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = Column(Integer, default=0)
    is_locked: Mapped[bool] = Column(Boolean, default=False)

    # Metadata
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Auth
    verification_token = Column(String, nullable=True)
    email_verified: Mapped[bool] = Column(Boolean, default=False, nullable=False)
    hashed_password: Mapped[str] = Column(String(255), nullable=False)

    # ─────────── utility methods ───────────
    def __repr__(self) -> str:
        return (
            f"<User {self.nickname} "
            f"role={self.role.name} "
            f"admin_role={self.admin_role.name if self.admin_role else None}>"
        )

    def lock_account(self):
        self.is_locked = True

    def unlock_account(self):
        self.is_locked = False

    def verify_email(self):
        self.email_verified = True

    def has_role(self, role_name: UserRole) -> bool:
        return self.role == role_name

    def update_professional_status(self, status: bool):
        self.is_professional = status
        self.professional_status_updated_at = func.now()

class RoleChangeAudit(Base):
    """
    Records every role change:
      • user_id     – user whose role changed
      • changed_by  – superadmin who made the change
      • old_role/new_role – values from UserRole
      • changed_at  – timestamp
    """
    __tablename__ = "role_change_audit"
    __mapper_args__ = {"eager_defaults": True}

    id = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    changed_by = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    old_role = Column(SQLAlchemyEnum(UserRole, name="UserRole"), nullable=False)
    new_role = Column(SQLAlchemyEnum(UserRole, name="UserRole"), nullable=False)

    changed_at = Column(DateTime(timezone=True), server_default=func.now())