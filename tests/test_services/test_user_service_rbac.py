import pytest
from uuid import uuid4
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.user_service import UserService
from app.models.user_model import UserRole, AdminRole, RoleChangeAudit


@pytest.mark.asyncio
async def test_change_role_requires_superadmin(db_session, user, manager_user):
    # Non-superadmin cannot invoke the service
    with pytest.raises(PermissionError):
        await UserService.change_role(
            db_session,
            target_user_id=user.id,
            new_role=UserRole.ADMIN,
            acting_user_id=manager_user.id,
        )


@pytest.mark.asyncio
async def test_change_role_nonexistent_user_returns_none(db_session, admin_user):
    fake_id = uuid4()
    result = await UserService.change_role(
        db_session,
        target_user_id=fake_id,
        new_role=UserRole.MANAGER,
        acting_user_id=admin_user.id,
    )
    assert result is None


@pytest.mark.asyncio
async def test_change_role_creates_audit_entry(db_session, admin_user, user):
    # Count existing entries
    cnt_before = await db_session.scalar(
        select(func.count()).select_from(RoleChangeAudit)
    )

    # Perform the role change
    new = await UserService.change_role(
        db_session,
        target_user_id=user.id,
        new_role=UserRole.MANAGER,
        acting_user_id=admin_user.id,
    )
    assert new.role == UserRole.MANAGER

    # One more audit row
    cnt_after = await db_session.scalar(
        select(func.count()).select_from(RoleChangeAudit)
    )
    assert cnt_after == cnt_before + 1

    # Verify the latest audit record
    rec = (await db_session.execute(
        select(RoleChangeAudit)
        .where(RoleChangeAudit.user_id == user.id)
        .order_by(RoleChangeAudit.changed_at.desc())
        .limit(1)
    )).scalars().first()
    assert rec.changed_by == admin_user.id
    assert rec.old_role == UserRole.AUTHENTICATED
    assert rec.new_role == UserRole.MANAGER

@pytest.mark.asyncio
async def test_skip_audit_if_role_unchanged(db_session, admin_user):
    # count rows before
    cnt_before = await db_session.scalar(select(func.count()).select_from(RoleChangeAudit))

    # same role → should be ignored
    await UserService.change_role(
        db_session,
        target_user_id=admin_user.id,
        new_role=UserRole.ADMIN,
        acting_user_id=admin_user.id,
    )
    cnt_after = await db_session.scalar(select(func.count()).select_from(RoleChangeAudit))

    assert cnt_before == cnt_after

@pytest.mark.asyncio
async def test_change_role_noop_does_not_create_audit(db_session, admin_user, user):
    """
    QA‑05 • Calling change_role() with the user’s **current** role must be a NO‑OP:
           – the User table is untouched
           – **no extra RoleChangeAudit row** is inserted
    """
    # Step‑1: put the user into MANAGER once (creates 1 audit entry)
    await UserService.change_role(
        db_session,
        target_user_id=user.id,
        new_role=UserRole.MANAGER,
        acting_user_id=admin_user.id,
    )

    cnt_before = await db_session.scalar(
        select(func.count()).select_from(RoleChangeAudit)
    )

    # Step‑2: call again with the *same* role – should NOT insert a new audit row
    await UserService.change_role(
        db_session,
        target_user_id=user.id,
        new_role=UserRole.MANAGER,          # same as current
        acting_user_id=admin_user.id,
    )

    cnt_after = await db_session.scalar(
        select(func.count()).select_from(RoleChangeAudit)
    )

    assert cnt_before == cnt_after, "idempotent call must not create extra audit row"