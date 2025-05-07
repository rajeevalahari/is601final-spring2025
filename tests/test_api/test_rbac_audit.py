import pytest
from uuid import UUID
from uuid import uuid4
from datetime import timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.services.jwt_service import create_access_token
from app.dependencies import get_settings
from app.models.user_model import RoleChangeAudit, UserRole
from app.services.user_service import UserService

settings = get_settings()


async def get_auth_headers(user):
    token = create_access_token(
        data={
            "user_id": str(user.id),
            "sub": user.email,
            "role": user.role.name,
            "admin_role": user.admin_role.name if user.admin_role else None,
        },
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_superadmin_can_change_role_and_audit(db_session: AsyncSession, admin_user, user):
    # Superadmin changes a user to MANAGER via API
    headers = await get_auth_headers(admin_user)
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.patch(
            f"/users/{user.id}/role",
            json={"new_role": UserRole.MANAGER.name},
            headers=headers,
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["user_id"] == str(user.id)
    assert body["new_role"] == UserRole.MANAGER.name

    # Audit record was created
    q = select(RoleChangeAudit).where(RoleChangeAudit.user_id == user.id)
    result = await db_session.execute(q)
    audit = result.scalars().first()
    assert audit is not None
    assert audit.changed_by == admin_user.id
    assert audit.old_role == UserRole.AUTHENTICATED
    assert audit.new_role == UserRole.MANAGER


@pytest.mark.asyncio
async def test_role_history_endpoint_for_superadmin(db_session: AsyncSession, admin_user, user):
    # Seed one audit entry
    await UserService.change_role(
        db_session,
        target_user_id=user.id,
        new_role=UserRole.MANAGER,
        acting_user_id=admin_user.id,
    )

    headers = await get_auth_headers(admin_user)
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get(f"/users/{user.id}/role-history", headers=headers)

    assert resp.status_code == 200
    entries = resp.json()
    assert isinstance(entries, list) and entries
    entry = entries[0]
    assert entry["old_role"] == UserRole.AUTHENTICATED.name
    assert entry["new_role"] == UserRole.MANAGER.name
    assert entry["changed_by"] == str(admin_user.id)
    assert "changed_at" in entry


@pytest.mark.asyncio
async def test_non_superadmin_cannot_change_or_view(manager_user, user, async_client):
    # Manager tries to PATCH and GET history
    headers = await get_auth_headers(manager_user)

    resp1 = await async_client.patch(
        f"/users/{user.id}/role",
        json={"new_role": UserRole.ADMIN.name},
        headers=headers,
    )
    resp2 = await async_client.get(
        f"/users/{user.id}/role-history", headers=headers
    )

    assert resp1.status_code == 403
    assert resp2.status_code == 403


@pytest.mark.asyncio
async def test_change_role_nonexistent_user_returns_404(admin_user, async_client):
    headers = await get_auth_headers(admin_user)
    fake_id = UUID(int=0)
    resp = await async_client.patch(
        f"/users/{fake_id}/role",
        json={"new_role": UserRole.ADMIN.name},
        headers=headers,
    )
    assert resp.status_code == 404

@pytest.mark.asyncio
async def test_role_history_empty_returns_200(admin_user, async_client):
    """Fresh user with no audit rows => 200 + empty list."""
    # auth header for superadmin
    token = create_access_token(
        data={
            "user_id": str(admin_user.id),
            "sub": admin_user.email,
            "role": admin_user.role.name,
            "admin_role": admin_user.admin_role.name,
        },
        expires_delta=None,
    )
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.get(f"/users/{admin_user.id}/role-history", headers=headers)

    assert resp.status_code == 200
    assert resp.json() == [] 

@pytest.mark.asyncio
async def test_role_history_nonexistent_returns_404(admin_user, async_client):
    token = create_access_token(
        data={
            "user_id": str(admin_user.id),
            "sub": admin_user.email,
            "role": admin_user.role.name,
            "admin_role": admin_user.admin_role.name,
        },
        expires_delta=None,
    )
    headers = {"Authorization": f"Bearer {token}"}

    fake_id = uuid4()
    resp = await async_client.get(f"/users/{fake_id}/role-history", headers=headers)

    assert resp.status_code == 404
    assert resp.json()["detail"] == "User not found"

@pytest.mark.asyncio
async def test_change_role_invalid_enum(admin_user, async_client):
    token = create_access_token(
        data={
            "user_id": str(admin_user.id),
            "sub": admin_user.email,
            "role": admin_user.role.name,
            "admin_role": admin_user.admin_role.name,
        },
        expires_delta=None,
    )
    headers = {"Authorization": f"Bearer {token}"}

    fake_id = uuid4()
    resp = await async_client.patch(
        f"/users/{fake_id}/role",
        json={"new_role": "GODMODE"},     # invalid
        headers=headers,
    )

    # FastAPI returns 422 for request‑body validation errors
    assert resp.status_code == 422