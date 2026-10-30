from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from core import security
from core.db import get_db
from core.models import User

bearer = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(401, "Token yo'q yoki yaroqsiz", headers={"WWW-Authenticate": "Bearer"})


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise _unauthorized()
    user_id = security.decode_token(creds.credentials)
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise _unauthorized()
    return user


def require_access(user: User = Depends(get_current_user)) -> User:
    if not user.has_access():
        raise HTTPException(402, "Sinov muddati tugagan. Davom etish uchun obuna kerak")
    return user
