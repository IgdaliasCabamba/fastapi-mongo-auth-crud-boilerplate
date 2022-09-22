from pydantic import BaseSettings, EmailStr

import os
import json
import pathlib

if os.environ.get("ENV_PROD", False):
    
    class Settings(BaseSettings):
        DATABASE_URL:str = os.environ["MONGODB_URI"]
        MONGO_INITDB_DATABASE: str = os.environ["MONGO_INITDB_DATABASE"]
        
        JWT_PUBLIC_KEY: str = os.environ["JWT_PUBLIC_KEY"]
        JWT_PRIVATE_KEY: str = os.environ["JWT_PRIVATE_KEY"]
        REFRESH_TOKEN_EXPIRES_IN: int = int(os.environ["REFRESH_TOKEN_EXPIRES_IN"])
        ACCESS_TOKEN_EXPIRES_IN: int = int(os.environ["ACCESS_TOKEN_EXPIRES_IN"])
        JWT_ALGORITHM: str = os.environ["JWT_ALGORITHM"]

        CLIENT_ORIGIN: str = os.environ["CLIENT_ORIGIN"]

        EMAIL_HOST: str = os.environ["EMAIL_HOST"]
        EMAIL_PORT: int = os.environ["EMAIL_PORT"]
        EMAIL_USERNAME: str = os.environ["EMAIL_USERNAME"]
        EMAIL_PASSWORD: str = os.environ["EMAIL_PASSWORD"]
        EMAIL_FROM: EmailStr = os.environ["EMAIL_FROM"]

        GOOGLE_AUTH_SECRET_KEY:str = os.environ["GOOGLE_AUTH_SECRET_KEY"]
        GOOGLE_AUTH_CLIENT_ID:str = os.environ["GOOGLE_AUTH_CLIENT_ID"]
        GOOGLE_AUTH_CLIENT_SECRET:str = os.environ["GOOGLE_AUTH_CLIENT_SECRET"]
        

else:
    os.environ["ENV_DEV"] = "1"

    class Settings(BaseSettings):
        DATABASE_URL: str
        MONGO_INITDB_DATABASE: str

        JWT_PUBLIC_KEY: str
        JWT_PRIVATE_KEY: str
        REFRESH_TOKEN_EXPIRES_IN: int
        ACCESS_TOKEN_EXPIRES_IN: int
        JWT_ALGORITHM: str

        CLIENT_ORIGIN: str

        EMAIL_HOST: str
        EMAIL_PORT: int
        EMAIL_USERNAME: str
        EMAIL_PASSWORD: str
        EMAIL_FROM: EmailStr

        GOOGLE_AUTH_SECRET_KEY:str
        GOOGLE_AUTH_CLIENT_ID:str
        GOOGLE_AUTH_CLIENT_SECRET:str

        class Config:
            env_file = './.env'


settings = Settings()