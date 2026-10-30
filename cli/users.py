import typer

from core import security
from core.db import Base, SessionLocal, engine
from core.models import User

users_app = typer.Typer(help="Foydalanuvchilarni boshqarish")


@users_app.command("create-admin")
def create_admin(email: str):
    """Admin yaratadi (yoki mavjud foydalanuvchini admin qiladi). Parol so'raladi, ekranda ko'rinmaydi."""
    email = email.strip().lower()
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.role = "admin"
            db.commit()
            typer.secho(f"{email} endi admin (parol o'zgarmadi)", fg=typer.colors.GREEN)
            return
        password = typer.prompt("Parol (kamida 12 belgi)", hide_input=True, confirmation_prompt=True)
        if len(password) < 12:
            typer.secho("Parol juda qisqa", fg=typer.colors.RED)
            raise typer.Exit(1)
        db.add(User(email=email, password_hash=security.hash_password(password), role="admin"))
        db.commit()
        typer.secho(f"Admin yaratildi: {email}", fg=typer.colors.GREEN)
