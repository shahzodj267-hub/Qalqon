from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db import Base


def utcnow() -> datetime:
    """Naive UTC: SQLite vaqt zonasini saqlamaydi, shuning uchun hamma joyda bir xil format."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(10), default="user")  # "user" yoki "admin"
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    paid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def has_access(self) -> bool:
        if self.role == "admin":
            return True
        now = utcnow()
        return any(d is not None and d > now for d in (self.trial_ends_at, self.paid_until))
