from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import UserRole
from app.schemas.audit_schema import AuditLogOut
from app.services.audit_service import list_logs
from app.utils.permissions import require_roles

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs", response_model=list[AuditLogOut])
def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    admin=Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    return list_logs(db, limit=limit)

