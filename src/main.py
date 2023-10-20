
import json
import os
import redis
import boto3
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError

app = FastAPI()

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

# Redis credentials used to connect with Redis message broker
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
sub = RedisResource.conn.pubsub()
sub.subscribe("encode")
sub.subscribe("chunk")
sub.subscribe("thumbnail")

class Item(BaseModel):
    name: str

class VideoInformation(BaseModel):
    object_key: str

# push chunking work into workqueue
@app.post("/chunk")
def chunk(item: Item):
    RedisResource.conn.rpush(
        RedisResource.CHUNK_QUEUE,
        json.dumps(item.__dict__))
    #loop to detect message publish by workers
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

# push encode work into workqueue
@app.post("/encode")
def encode(item: Item):
    RedisResource.conn.rpush(
        RedisResource.ENCODE_QUEUE,
        json.dumps(item.__dict__))
    #loop to detect message publish by workers
    while True:
        msg = sub.get_message()
        if msg:
            print(f"new message in channel {msg['channel']}: {msg['data']}")
            break
    return msg

# push thumbnail work into workqueue
@app.post("/thumbnail")
def thumbnail(item: Item):
    RedisResource.conn.rpush(
        RedisResource.THUMBNAIL_QUEUE,
        json.dumps(item.__dict__))
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
    object_key = vid_info.object_key
    encode(Item(object_key))
