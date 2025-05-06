from pydantic import BaseModel, Field
from app.models.user_model import UserRole


class RoleChangeRequest(BaseModel):
    new_role: UserRole = Field(..., example="MANAGER")
