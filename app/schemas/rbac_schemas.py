from pydantic import BaseModel, Field, validator          # ← add validator
from app.models.user_model import UserRole


class RoleChangeRequest(BaseModel):
    """
    Payload used by the RBAC PATCH endpoint.

    • Parses the incoming role string → UserRole enum  
    • Rejects attempts to set the special “ANONYMOUS” role
      (business rule from QA‑04).
    """
    new_role: UserRole = Field(..., example="MANAGER")

    # ────────────────────────────────────────────────────
    # QA‑04 fix – forbid ANONYMOUS
    # ────────────────────────────────────────────────────
    @validator("new_role")
    def _no_anonymous(cls, v: UserRole) -> UserRole:
        if v is UserRole.ANONYMOUS:
            raise ValueError("Setting role to ANONYMOUS is not permitted")
        return v
