from typing import Union
from datetime import datetime
from pydantic import BaseModel, EmailStr, constr

class UserBaseSchema(BaseModel):
    name: str
    email: EmailStr
    photo: Union[str, None] = None
    role: Union[str, None] = None
    created_at: Union[datetime, None] = None
    updated_at: Union[datetime, None] = None

    class Config:
        orm_mode = True

class UserResponseSchema(UserBaseSchema):
    id: str
    ...

class UserResponse(BaseModel):
    status: str
    user: UserResponseSchema