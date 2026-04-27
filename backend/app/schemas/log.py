from datetime import datetime

from pydantic import BaseModel


class LogCreate(BaseModel):
    message: str


class LogResponse(BaseModel):
    id: int
    user_id: int
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}
