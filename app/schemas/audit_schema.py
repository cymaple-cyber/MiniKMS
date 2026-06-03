from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    result: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

