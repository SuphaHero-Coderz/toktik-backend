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

class RedisResource:
    """
    Redis credentials used to connect with Redis message broker
    """
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

@router.post("/api/chunk")
def chunk(vid_info: VideoInformation):
    """
    Pushes chunking job into work queue.

    Args:
        vid_info (VideoInformation): video information

    Returns: object
    """
    RedisResource.conn.rpush(RedisResource.CHUNK_QUEUE, json.dumps(vid_info.__dict__))

    return { "message": "OK" }

@router.post("/api/encode")
def encode(vid_info: VideoInformation):
    """
    Pushes encoding job into work queue.

    Args:
        vid_info (VideoInformation): video information

    Returns: object
    """
    RedisResource.conn.rpush(RedisResource.ENCODE_QUEUE, json.dumps(vid_info.__dict__))
    
    return { "message": "OK" }

@router.post("/api/thumbnail")
def thumbnail(vid_info: VideoInformation):
    """
    Pushes thumbnail generation job into work queue.

    Args:
        vid_info (VideoInformation): video information

    Returns: object
    """
    RedisResource.conn.rpush(RedisResource.THUMBNAIL_QUEUE, json.dumps(vid_info.__dict__))
    return { "message": "OK" }

@router.post("/api/process_video/")
async def process_video(vid_info: VideoInformation, current_user: _schemas.User = _fastapi.Depends(_services.get_current_user), db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Processes a video once it has been uploaded (begins by encoding it)

    Args:
        vid_info (VideoInformation): video information
        current_user (_schemas.User, optional): current user. Defaults to _fastapi.Depends(_services.get_current_user).
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Returns: object
    """
    vid_info_db = _schemas.VideoCreate(
        object_key = vid_info.object_key,
        video_name = vid_info.video_name,
        video_description = vid_info.video_description,
        video_thumbnail = f"{os.getenv('CLOUDFRONT_ORIGIN_URL')}/{vid_info.object_key}/thumbnail.jpg",
        processed = False,
        views = 1,
        likes = 0
    )

    await _services.create_video(db=db, current_user=current_user, video=vid_info_db)
    await _services.create_like(db=db, current_user=current_user, video_info=vid_info_db)

    encode(vid_info)

    return {"message", "OK"}

