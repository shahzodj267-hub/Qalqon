from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.deps import get_current_user
from core import security
from core.config import settings
from core.db import get_db
from core.models import User, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    email: str
    role: str
    trial_ends_at: datetime | None
    paid_until: datetime | None
    has_access: bool


def _out(user: User) -> UserOut:
    return UserOut(
        email=user.email,
        role=user.role,
        trial_ends_at=user.trial_ends_at,
        paid_until=user.paid_until,
        has_access=user.has_access(),
    )


@router.post("/register", status_code=201, response_model=UserOut)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Bu email allaqachon ro'yxatdan o'tgan")
    user = User(
        email=email,
        password_hash=security.hash_password(body.password),
        role="user",
        trial_ends_at=utcnow() + timedelta(days=settings.trial_days),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Bu email allaqachon ro'yxatdan o'tgan")
    return _out(user)


@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    ok = security.verify_password(body.password, user.password_hash if user else security.DUMMY_HASH)
    if not user or not ok:
        raise HTTPException(401, "Email yoki parol noto'g'ri")
    return {"access_token": security.create_token(user.id), "token_type": "bearer"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return _out(user)
