from .utils import config

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from .apps.v1.routes import v1_app

app = FastAPI()

ALLOWED_HOSTS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount(path='/api/v1', app=v1_app, name='APIv1')

@app.get("/api")
async def api_root():
    return {"message": "hello from @your-api"}

@app.get('/')
async def root():
    return RedirectResponse(url="/api")
