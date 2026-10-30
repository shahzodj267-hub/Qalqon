from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from modules.threat_intel.aggregator import analyze

app = FastAPI(title="Qalqon API", version="0.1.0")


class IocRequest(BaseModel):
    value: str = Field(min_length=1, max_length=300, description="IP, domen yoki fayl hash")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/ioc")
def check_ioc(request: IocRequest):
    try:
        return analyze(request.value)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
