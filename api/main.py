from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from api import auth
from api.deps import require_access
from core import models  # noqa: F401  (jadvallar ro'yxatdan o'tishi uchun)
from core import security
from core.db import Base, engine
from modules.threat_intel.aggregator import analyze


@asynccontextmanager
async def lifespan(app: FastAPI):
    security.check_config()  # JWT_SECRET yo'q bo'lsa, server ishga tushmaydi
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="Qalqon API", version="0.2.0", lifespan=lifespan)
app.include_router(auth.router)


class IocRequest(BaseModel):
    value: str = Field(min_length=1, max_length=300, description="IP, domen yoki fayl hash")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/ioc", dependencies=[Depends(require_access)])
def check_ioc(request: IocRequest):
    try:
        return analyze(request.value)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
