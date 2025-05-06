from builtins import Exception, dict, str
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import decode_token
from settings.config import Settings
from app.models.user_model import AdminRole

# ──────────────────────────────────────────────────────────
# FACTORY HELPERS
# ──────────────────────────────────────────────────────────
def get_settings() -> Settings:
    """Return application settings (reads .env via Pydantic)."""
    return Settings()


def get_email_service() -> EmailService:
    """Return a singleton‑style EmailService with a TemplateManager."""
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)


async def get_db() -> AsyncSession:
    """Provide an async DB session per request."""
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=500, detail=str(e)) from e


# ──────────────────────────────────────────────────────────
# AUTH HELPERS
# ──────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Decode JWT and return minimal user dict with id, role, admin_role.
    Accepts both `user_id` (new) or `sub` (fallback) as identifier.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if payload is None:
        raise credentials_exception

    user_id: str = payload.get("user_id") or payload.get("sub")
    user_role: str = payload.get("role")
    admin_role: str | None = payload.get("admin_role")

    if user_id is None or user_role is None:
        raise credentials_exception

    return {"id": user_id, "role": user_role, "admin_role": admin_role}


def require_role(allowed_roles: list[str]):
    """
    Dependency factory: allow only users whose `role` is in allowed_roles.
    Usage: current_user = Depends(require_role(["ADMIN", "MANAGER"]))
    """

    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Operation not permitted")
        return current_user

    return role_checker


def require_superadmin(current: dict = Depends(get_current_user)):
    """Allow only SUPERADMIN accounts (via admin_role claim)."""
    if current.get("admin_role") != AdminRole.SUPERADMIN.name:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SUPERADMIN privilege required",
        )
    return current
