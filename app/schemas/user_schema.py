from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.user import UserRole, UserStatus


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = UserRole.APP_USER


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: UserRole
    status: UserStatus
    created_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

