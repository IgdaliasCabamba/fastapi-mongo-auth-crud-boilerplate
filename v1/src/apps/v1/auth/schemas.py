from dataclasses import dataclass
from typing import Union
from datetime import datetime
from pydantic import BaseModel, EmailStr, constr
import random

@dataclass(frozen=True)
class ExampleMetadata:
    fake_user = random.randint(0, 99999)

class UserBaseSchema(BaseModel):
    name: str
    email: EmailStr
    photo: Union[str, None] = None
    role: Union[str, None] = None
    created_at: Union[datetime, None] = None
    updated_at: Union[datetime, None] = None

    class Config:
        schema_extra = {
            "example":{
                "name": "Celeste User",
                "email": f"celesteuser{ExampleMetadata.fake_user}@example.com",
                "password": "password123",
                "passwordConfirm": "password123",
            }
        }


class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=8)
    passwordConfirm: str
    verified: bool = False


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)
    
    class Config:
        schema_extra = {
            "example":{
                "email": f"celesteuser{ExampleMetadata.fake_user}@example.com",
                "password": "password123",
            }
        }
