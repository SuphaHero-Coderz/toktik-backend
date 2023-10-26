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

import src.schemas as _schemas
import fastapi as _fastapi
import src.db_services as _services
import sqlalchemy.orm as _orm
from typing import List
from .routers import users, videos, processing
from schemas import VideoInformation

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

app.include_router(users.router)
app.include_router(videos.router)
app.include_router(processing.router)

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

#push chunking work into workqueue
@app.post("/chunk")
def chunk(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.CHUNK_QUEUE,
        json.dumps(vid_info.__dict__))
    # print("chunk")
    return {"message": "OK"}

# push encode work into workqueue
@app.post("/encode")
def encode(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.ENCODE_QUEUE,
        json.dumps(vid_info.__dict__))
    # print("encode")
    return {"message": "OK"}

# push thumbnail work into workqueue
@app.post("/thumbnail")
def thumbnail(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.THUMBNAIL_QUEUE,
        json.dumps(vid_info.__dict__))
    # print("thumbnail")
    return {"message": "OK"}

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
async def process_video(
        vid_info: VideoInformation,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    vid_info_db = _schemas.VideoCreate(
            object_key = vid_info.object_key,
            video_name = vid_info.video_name,
            video_description = vid_info.video_description,
            video_thumbnail = f"{os.getenv('CLOUDFRONT_ORIGIN_URL')}/{vid_info.object_key}/thumbnail.jpg",
            processed = False)
    await _services.create_video(db=db, current_user=current_user, video=vid_info_db)
    encode(vid_info)
    return {"message", "OK"}
  

@app.post("/update_video_status")
async def update_video_status(vid_info: VideoInformation,
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    print("update_video_status")
    await _services.update_video_status(video_info=vid_info, db=db)
    return {"message", "OK"}

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
