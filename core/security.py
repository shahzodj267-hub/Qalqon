from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from core.config import settings

_hasher = PasswordHasher()
# Foydalanuvchi topilmasa ham xeshni tekshiramiz: javob vaqti emailning bor-yo'qligini oshkor qilmasin
DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def check_config() -> None:
    if len(settings.jwt_secret) < 32:
        raise RuntimeError("JWT_SECRET .env faylida yo'q yoki 32 belgidan qisqa")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def create_token(user_id: int, expires_minutes: int | None = None) -> str:
    check_config()
    minutes = settings.jwt_expire_minutes if expires_minutes is None else expires_minutes
    payload = {"sub": str(user_id), "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> int | None:
    """To'g'ri token bo'lsa user id, aks holda None."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        return int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None
