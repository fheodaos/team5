from fastapi import FastAPI

from app.routers import auth, logs

app = FastAPI(title="Team5 API")

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(logs.router, prefix="/logs", tags=["logs"])
