import json
import os

import fastapi
import redis
import boto3
import botocore
import base64
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError
from botocore.signers import CloudFrontSigner
from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

import schemas as _schemas
import fastapi as _fastapi
import db_services as _services
import sqlalchemy.orm as _orm
import fastapi.security as _security
from typing import List

app = FastAPI()

_services.create_database()

load_dotenv()

s3 = boto3.client('s3', 
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY"),
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
)

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

@app.get("/")
def read_root():
    return {"Hello": "World"}

#Redis credentials used to connect with Redis message broker
class RedisResource:
    REDIS_QUEUE_LOCATION = os.getenv('REDIS_QUEUE', 'localhost')
    CHUNK_QUEUE = 'queue:chunk'
    ENCODE_QUEUE = 'queue:encode'
    THUMBNAIL_QUEUE = 'queue:thumbnail'

    host, *port_info = REDIS_QUEUE_LOCATION.split(':')
    port = tuple()
    if port_info:
        port, *_ = port_info
        port = (int(port),)

    conn = redis.Redis(host=host, *port)


# create a subscriber for receiving message from workers
sub = RedisResource.conn.pubsub(ignore_subscribe_messages=True)
sub.subscribe("encode")
sub.subscribe("chunk")
sub.subscribe("thumbnail")

class VideoInformation(BaseModel):
    object_key: str

#push chunking work into workqueue
@app.post("/chunk")
def chunk(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.CHUNK_QUEUE,
        json.dumps(vid_info.__dict__))
    #loop to detect message publish by workers
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

# push encode work into workqueue
@app.post("/encode")
def encode(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.ENCODE_QUEUE,
        json.dumps(vid_info.__dict__))
    #loop to detect message publish by workers
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

# push thumbnail work into workqueue
@app.post("/thumbnail")
def thumbnail(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.THUMBNAIL_QUEUE,
        json.dumps(vid_info.__dict__))
    #loop to detect message publish by workers
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

@app.get("/generate_presigned_url/{object_key}")
async def generate_presigned_url(object_key: str):
    """
    Generates a presigned URL for upload to S3
    """
    try:
        # Generate a presigned URL for the S3 object
        presigned_url = s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': os.getenv("BUCKET_NAME"),
                'Key': object_key,
                'ContentType': 'video/*'
            },
            ExpiresIn=3600,
            HttpMethod="PUT"
        )

        return {"presigned_url": presigned_url}

    except NoCredentialsError:
        return {"error": "AWS credentials not available."}

@app.post("/process_video/")
async def process_video(vid_info: VideoInformation):
    msg = encode(vid_info)
    msg_data = json.loads(msg['data'])
    if msg_data['status'] == 1:
        thumbnail(vid_info)
        chunk(vid_info)


@app.get("/view_video/{object_key}")
async def view_video(object_key: str):
    def rsa_signer(message):
        cloudfront_private_key_base64 = os.getenv("CLOUDFRONT_PRIVATE_KEY_BASE64")
        private_key = serialization.load_pem_private_key(
            base64.b64decode(cloudfront_private_key_base64),
            password=None,
            backend=default_backend()
        )
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

    def sign_m3u8(object_key: str):
        key_id = os.getenv("CLOUDFRONT_KEY_ID")
        cloudfront_origin = os.getenv("CLOUDFRONT_ORIGIN_URL")
        url_to_chunks = f"{cloudfront_origin}/{object_key}/chunks/"
        expire_date = datetime.utcnow() + timedelta(minutes=2)
        cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)
        signed_url = cloudfront_signer.generate_presigned_url(url_to_chunks + "encoded.m3u8", date_less_than=expire_date)
        return signed_url

    signed_m3u8_url = sign_m3u8(object_key)
    token = "?" + signed_m3u8_url.split("?")[1]
    m3u8_url = signed_m3u8_url.split("?")[0]

    return { "m3u8_url" : m3u8_url, "token" : token }

@app.post("/api/users")
async  def create_user(user: _schemas.UserCreate, db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    db_user = await _services.get_user_by_username(user.username, db)
    if db_user:
        raise _fastapi.HTTPException(status_code=400, detail="Username already in use")
    return await _services.create_user(user, db)

@app.post("/api/token")
async def generate_token(form_data: _security.OAuth2PasswordRequestForm = fastapi.Depends(),
                         db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    user = await _services.authenticate_user(username=form_data.username, password=form_data.password, db=db)
    if not user:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    return await _services.create_token(user)

@app.get("/api/users/me", response_model=_schemas.User)
async def get_current_user(user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    return user

@app.get("/api/users/{user_id}", response_model=_schemas.User)
async def get_user(
        user_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_user(user_id=user_id, current_user=current_user, db=db)

@app.delete("/api/users/{user_id}", status_code=204)
async def delete_user(
        user_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    await _services.delete_user(user_id=user_id, current_user=current_user, db=db)
    return {"message", "Successfully Deleted"}

@app.post("/api/videos", response_model=_schemas.Video)
async def create_video(
        video: _schemas.VideoCreate,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.create_video(current_user=current_user, db=db, video=video)

@app.get("/api/get_all_videos", response_model=List[_schemas.Video])
async def get_all_videos(db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_all_videos(db=db)

@app.get("/api/videos", response_model=List[_schemas.Video])
async def get_videos(
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_videos(current_user=current_user, db=db)

@app.get("/api/videos/{video_id}", response_model=_schemas.Video)
async def get_video(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_video(video_id=video_id, current_user=current_user, db=db)

@app.delete("/api/videos/{video_id}", status_code=204)
async def delete_video(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
        await _services.delete_video(video_id=video_id, current_user=current_user, db=db)
        return {"message", "Successfully Deleted"}

@app.put("/api/videos/{video_id}", status_code=200)
async def update_video(
        video_id: int,
        video: _schemas.VideoCreate,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
        await _services.update_video(video_id=video_id, video=video, current_user=current_user, db=db)
        return {"message", "Successfully Updated"}
