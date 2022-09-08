from .utils import config

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import user
from .apps import auth

app = FastAPI()

origins = [
    config.settings.CLIENT_ORIGIN,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins= origins, #["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount(path='/api/v1/auth', app=auth.auth_app, name='Auth')
user.init(app)

@app.get("/api/v1")
def root():
    return {"message": "hello from @akumbu-api-v1"}
