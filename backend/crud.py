from sqlalchemy.orm import Session
import backend.models as models
import backend.schemas as schemas
from backend.auth import get_password_hash, verify_password


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.UserCreate, role: str = "user"):
    hashed = get_password_hash(user.password)
    db_user = models.User(email=user.email, password_hash=hashed, role=role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return None
    stored = getattr(user, "password_hash", None) or getattr(user, "hashed_password", None)
    if not stored or not verify_password(password, stored):
        return None
    return user


def create_suspicious(db: Session, user_id: int, item: schemas.SuspiciousCreate):
    db_item = models.SuspiciousQuery(qname=item.qname, confidence=item.confidence, user_id=user_id)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def get_user_suspicious(db: Session, user_id: int):
    return db.query(models.SuspiciousQuery).filter(models.SuspiciousQuery.user_id == user_id).all()


def get_all_suspicious(db: Session):
    return db.query(models.SuspiciousQuery).order_by(models.SuspiciousQuery.created_at.desc()).all()
