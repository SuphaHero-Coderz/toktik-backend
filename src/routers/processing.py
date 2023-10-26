import json
import os

import fastapi as _fastapi
import sqlalchemy.orm as _orm
from fastapi import APIRouter
import redis
from dotenv import load_dotenv

import src.db_services as _services
import src.schemas as _schemas
from src.schemas import VideoInformation

router = APIRouter(tags=["processing"])

load_dotenv()



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
@router.post("/chunk")
def chunk(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.CHUNK_QUEUE,
        json.dumps(vid_info.__dict__))
    # print("chunk")
    return {"message": "OK"}

# push encode work into workqueue
@router.post("/encode")
def encode(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.ENCODE_QUEUE,
        json.dumps(vid_info.__dict__))
    # print("encode")
    return {"message": "OK"}

# push thumbnail work into workqueue
@router.post("/thumbnail")
def thumbnail(vid_info: VideoInformation):
    RedisResource.conn.rpush(
        RedisResource.THUMBNAIL_QUEUE,
        json.dumps(vid_info.__dict__))
    # print("thumbnail")
    return {"message": "OK"}

@router.post("/process_video/")
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

