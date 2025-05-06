"""
User routes – CRUD, auth, RBAC (Superadmin)
"""

from builtins import dict, int, len, str
from datetime import timedelta
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    status,
    Request,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import (
    get_db,
    get_email_service,
    get_settings,
    require_role,
    require_superadmin,
)
from app.schemas.pagination_schema import EnhancedPagination  # noqa: F401
from app.schemas.token_schema import TokenResponse
from app.schemas.user_schemas import (
    UserCreate,
    UserListResponse,
    UserResponse,
    UserUpdate,
)
from app.schemas.rbac_schemas import RoleChangeRequest
from app.services.user_service import UserService
from app.services.jwt_service import create_access_token
from app.services.email_service import EmailService
from app.utils.link_generation import create_user_links, generate_pagination_links
from app.models.user_model import UserRole, AdminRole

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
settings = get_settings()

# ─────────────────────────── LOGIN & REGISTRATION ────────────────────────────
@router.post("/register/", response_model=UserResponse, tags=["Login and Registration"])
async def register(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    user = await UserService.register_user(session, user_data.model_dump(), email_service)
    if not user:
        raise HTTPException(status_code=400, detail="Email already exists")
    return user


@router.post("/login/", response_model=TokenResponse, tags=["Login and Registration"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db),
):
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(
            status_code=400,
            detail="Account locked due to too many failed login attempts.",
        )

    user = await UserService.login_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)

    # include user_id & admin_role in JWT
    access_token = create_access_token(
        data={
            "user_id": str(user.id),
            "sub": user.email,
            "role": user.role.name,
            "admin_role": user.admin_role.name if user.admin_role else None,
        },
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get(
    "/verify-email/{user_id}/{token}",
    status_code=status.HTTP_200_OK,
    name="verify_email",
    tags=["Login and Registration"],
)
async def verify_email(
    user_id: UUID,
    token: str,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    if await UserService.verify_email_with_token(db, user_id, token):
        return {"message": "Email verified successfully"}
    raise HTTPException(status_code=400, detail="Invalid or expired verification token")


# ─────────────────────────── RBAC – SUPERADMIN ONLY ──────────────────────────
@router.patch(
    "/users/{user_id}/role",
    tags=["RBAC (Superadmin)"],
    name="change_user_role",
)
async def change_user_role(
    user_id: UUID,
    body: RoleChangeRequest,
    db: AsyncSession = Depends(get_db),
    current_super=Depends(require_superadmin),
):
    try:
        user = await UserService.change_role(
            db,
            target_user_id=user_id,
            new_role=body.new_role,
            acting_user_id=current_super["id"],
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user_id": user.id, "new_role": user.role}


# ─────────────────────────── USER CRUD ENDPOINTS ─────────────────────────────
@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    name="get_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def get_user(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_construct(
        id=user.id,
        nickname=user.nickname,
        first_name=user.first_name,
        last_name=user.last_name,
        bio=user.bio,
        profile_picture_url=user.profile_picture_url,
        github_profile_url=user.github_profile_url,
        linkedin_profile_url=user.linkedin_profile_url,
        role=user.role,
        email=user.email,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        links=create_user_links(user.id, request),
    )


@router.put(
    "/users/{user_id}",
    response_model=UserResponse,
    name="update_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user_data = user_update.model_dump(exclude_unset=True)
    updated_user = await UserService.update(db, user_id, user_data)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_construct(
        id=updated_user.id,
        bio=updated_user.bio,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        nickname=updated_user.nickname,
        email=updated_user.email,
        role=updated_user.role,
        last_login_at=updated_user.last_login_at,
        profile_picture_url=updated_user.profile_picture_url,
        github_profile_url=updated_user.github_profile_url,
        linkedin_profile_url=updated_user.linkedin_profile_url,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        links=create_user_links(updated_user.id, request),
    )


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    name="delete_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    success = await UserService.delete(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/users/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    name="create_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def create_user(
    user: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    existing_user = await UserService.get_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    created_user = await UserService.create(db, user.model_dump(), email_service)
    if not created_user:
        raise HTTPException(status_code=500, detail="Failed to create user")

    return UserResponse.model_construct(
        id=created_user.id,
        bio=created_user.bio,
        first_name=created_user.first_name,
        last_name=created_user.last_name,
        profile_picture_url=created_user.profile_picture_url,
        nickname=created_user.nickname,
        email=created_user.email,
        role=created_user.role,
        last_login_at=created_user.last_login_at,
        created_at=created_user.created_at,
        updated_at=created_user.updated_at,
        links=create_user_links(created_user.id, request),
    )


@router.get(
    "/users/",
    response_model=UserListResponse,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def list_users(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    total_users = await UserService.count(db)
    users = await UserService.list_users(db, skip, limit)

    user_responses = [UserResponse.model_validate(u) for u in users]
    pagination_links = generate_pagination_links(request, skip, limit, total_users)

    return UserListResponse(
        items=user_responses,
        total=total_users,
        page=skip // limit + 1,
        size=len(user_responses),
        links=pagination_links,
    )
