from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.key import KeyStatus


class KeyCreate(BaseModel):
    key_name: str = Field(min_length=1, max_length=128)
    key_type: str = Field(default="AES-256-GCM", pattern="^AES-256-GCM$")
    key_usage: str = Field(default="encrypt/decrypt", pattern="^encrypt/decrypt$")
    expires_at: Optional[datetime] = None


class KeyMetadata(BaseModel):
    id: str
    key_name: str
    key_type: str
    key_usage: str
    key_status: KeyStatus
    key_version: int
    created_by: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

