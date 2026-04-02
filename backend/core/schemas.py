from pydantic import BaseModel
from typing import Any, Optional

class APIResponse(BaseModel):
    status: str
    data: Optional[Any] = None
    error: Optional[dict] = None

class ErrorDetail(BaseModel):
    message: str
    code: Optional[str] = None
