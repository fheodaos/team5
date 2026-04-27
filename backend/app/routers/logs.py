from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_current_user, get_db
from app.models.log import Log
from app.models.user import User
from app.schemas.log import LogCreate, LogResponse

router = APIRouter()


@router.post("", response_model=LogResponse, status_code=201)
async def create_log(
    body: LogCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    log = Log(user_id=current_user.id, message=body.message)
    db.add(log)
    await db.commit()
    await db.refresh(log)
    return log


@router.get("", response_model=List[LogResponse])
async def get_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Log).where(Log.user_id == current_user.id))
    return result.scalars().all()
