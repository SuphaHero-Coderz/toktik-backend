
import json
import os
import redis
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import boto3
from botocore.exceptions import NoCredentialsError

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

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

sub = RedisResource.conn.pubsub()
sub.subscribe("encode")
sub.subscribe("chunk")
sub.subscribe("thumbnail")

class Item(BaseModel):
    name: str

@app.post("/chunk")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.CHUNK_QUEUE,
        json.dumps(item.__dict__))
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

@app.post("/encode")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.ENCODE_QUEUE,
        json.dumps(item.__dict__))
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

@app.post("/thumbnail")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.THUMBNAIL_QUEUE,
        json.dumps(item.__dict__))
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

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

@app.get("/generate_presigned_url/{object_key}")
async def generate_presigned_url(object_key: str):
    try:
        # Generate a presigned URL for the S3 object
        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': os.getenv("BUCKET_NAME"),
                'Key': object_key,
            },
            ExpiresIn=3600  # The URL will expire in 1 hour
        )

        return {"presigned_url": presigned_url}

    except NoCredentialsError:
        return {"error": "AWS credentials not available."}
