from pydantic import BaseModel, EmailStr, Field,constr
from typing import List

class UserSchemas(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class UserResponse(BaseModel):
    id: int
    email: EmailStr

    class Config:
        orm_mode = True

class PostCreate(BaseModel):
    text: str = Field(..., max_length=10000)

class PostResponse(BaseModel):
    id: int
    text: str
    owner_id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    refresh_token: str

class TokenResponse(BaseModel):
    refresh_token: str
    access_token: str
    token_type: str = "bearer"