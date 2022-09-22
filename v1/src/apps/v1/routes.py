from fastapi import FastAPI
from .auth import auth_router
from .user import users_router

v1_app = FastAPI()
v1_app.include_router(auth_router, prefix="/auth")
v1_app.include_router(users_router, prefix="/user")