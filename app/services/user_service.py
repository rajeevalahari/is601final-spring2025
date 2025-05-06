from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
from typing import Optional, Dict, List
from uuid import UUID

import logging
from pydantic import ValidationError
from sqlalchemy import func, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_settings
from app.models.user_model import (
    User,
    UserRole,
    AdminRole,
    RoleChangeAudit,          # NEW
)
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import (
    generate_verification_token,
    hash_password,
    verify_password,
)
from app.services.email_service import EmailService

settings = get_settings()
logger = logging.getLogger(__name__)


class UserService:
    # ─────────────────────────────────────────────────────────────
    # INTERNAL HELPERS
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    # ─────────────────────────────────────────────────────────────
    # BASIC QUERIES
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    # ─────────────────────────────────────────────────────────────
    # USER CREATION / UPDATE / DELETE
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def create(
        cls,
        session: AsyncSession,
        user_data: Dict[str, str],
        email_service: EmailService,
    ) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()
            if await cls.get_by_email(session, validated_data["email"]):
                logger.error("User with given email already exists.")
                return None

            validated_data["hashed_password"] = hash_password(validated_data.pop("password"))
            new_user = User(**validated_data)

            # unique nickname
            nickname = generate_nickname()
            while await cls.get_by_nickname(session, nickname):
                nickname = generate_nickname()
            new_user.nickname = nickname

            # first user becomes SUPERADMIN
            user_count = await cls.count(session)
            if user_count == 0:
                new_user.role = UserRole.ADMIN
                new_user.admin_role = AdminRole.SUPERADMIN
                new_user.email_verified = True
            else:
                new_user.role = UserRole.ANONYMOUS
                new_user.verification_token = generate_verification_token()
                await email_service.send_verification_email(new_user)

            session.add(new_user)
            await session.commit()
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def update(
        cls,
        session: AsyncSession,
        user_id: UUID,
        update_data: Dict[str, str],
    ) -> Optional[User]:
        try:
            validated = UserUpdate(**update_data).model_dump(exclude_unset=True)
            if "password" in validated:
                validated["hashed_password"] = hash_password(validated.pop("password"))

            query = (
                update(User)
                .where(User.id == user_id)
                .values(**validated)
                .execution_options(synchronize_session="fetch")
            )
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                await session.refresh(updated_user)
            return updated_user
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            return False
        await session.delete(user)
        await session.commit()
        return True

    # ─────────────────────────────────────────────────────────────
    # LIST & COUNT
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def list_users(cls, session: AsyncSession, skip=0, limit=10) -> List[User]:
        result = await cls._execute_query(session, select(User).offset(skip).limit(limit))
        return result.scalars().all() if result else []

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        result = await session.execute(select(func.count()).select_from(User))
        return result.scalar()

    # ─────────────────────────────────────────────────────────────
    # AUTH / LOGIN
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        user = await cls.get_by_email(session, email)
        if not user or not user.email_verified or user.is_locked:
            return None

        if verify_password(password, user.hashed_password):
            user.failed_login_attempts = 0
            user.last_login_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            return user

        # wrong password
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_login_attempts:
            user.is_locked = True
        session.add(user)
        await session.commit()
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return bool(user and user.is_locked)

    # ─────────────────────────────────────────────────────────────
    # RBAC: CHANGE ROLE  (with audit)
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def change_role(
        cls,
        session: AsyncSession,
        *,
        target_user_id: UUID,
        new_role: UserRole,
        acting_user_id: UUID,
    ) -> Optional[User]:
        """SUPERADMIN can change any user's role and the change is audited."""
        acting_user = await cls.get_by_id(session, acting_user_id)
        if not acting_user or acting_user.admin_role != AdminRole.SUPERADMIN:
            raise PermissionError("SUPERADMIN privilege required")

        target_user = await cls.get_by_id(session, target_user_id)
        if not target_user:
            return None

        old_role = target_user.role
        target_user.role = new_role

        audit = RoleChangeAudit(
            user_id=target_user_id,
            changed_by=acting_user_id,
            old_role=old_role,
            new_role=new_role,
        )
        session.add(audit)
        session.add(target_user)
        await session.commit()
        await session.refresh(target_user)
        return target_user

    # ─────────────────────────────────────────────────────────────
    # OTHER HELPERS
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            return False
        user.hashed_password = hash_password(new_password)
        user.failed_login_attempts = 0
        user.is_locked = False
        session.add(user)
        await session.commit()
        return True

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None
            user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0
            session.add(user)
            await session.commit()
            return True
        return False
    
        # ─────────────────────────────────────────────────────────────
    # PUBLIC WRAPPER FOR /register  (needed by user_routes)
    # ─────────────────────────────────────────────────────────────
    @classmethod
    async def register_user(
        cls,
        session: AsyncSession,
        user_data: Dict[str, str],
        email_service: EmailService,
    ) -> Optional[User]:
        """Backward‑compat wrapper used by /register endpoint."""
        return await cls.create(session, user_data, email_service)
