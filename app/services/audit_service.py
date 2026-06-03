from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def _client_host(request: Optional[Request]) -> Optional[str]:
    if request is None or request.client is None:
        return None
    return request.client.host


def _user_agent(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    return request.headers.get("user-agent")


def record_event(
    db: Session,
    *,
    request: Optional[Request],
    user_id: Optional[int],
    action: str,
    target_type: str,
    target_id: Optional[str],
    result: str,
) -> AuditLog:
    log = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=_client_host(request),
        user_agent=_user_agent(request),
        result=result,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def list_logs(db: Session, *, limit: int = 100) -> list[AuditLog]:
    return (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .all()
    )

