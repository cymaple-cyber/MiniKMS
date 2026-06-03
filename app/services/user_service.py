from sqlalchemy.orm import Session

from app.models.user import User


def list_users(db: Session) -> list[User]:
    return db.query(User).order_by(User.id.asc()).all()

