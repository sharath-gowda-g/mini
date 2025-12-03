from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SuspiciousBase(BaseModel):
    qname: str
    confidence: Optional[float] = None


class SuspiciousCreate(SuspiciousBase):
    pass


class SuspiciousOut(SuspiciousBase):
    id: int
    created_at: datetime
    user_id: int

    class Config:
        orm_mode = True
