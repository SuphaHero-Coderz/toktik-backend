from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import src.db_services as _services
from .routers import users, videos, processing, s3

app = FastAPI()

_services.create_database()

load_dotenv()


origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users.router)
app.include_router(videos.router)
app.include_router(processing.router)
app.include_router(s3.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}

