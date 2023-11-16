import fastapi as _fastapi
import sqlalchemy.orm as _orm
from fastapi import APIRouter
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
import json

import src.db_services as _services
import src.schemas as _schemas
from src.schemas import VideoInformation
from typing import List
from botocore.signers import CloudFrontSigner

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.encoders import jsonable_encoder
import base64
import redis

router = APIRouter(tags=["videos"])

load_dotenv()
class RedisResource:
    REDIS_QUEUE_LOCATION = os.getenv('REDIS_QUEUE', 'localhost')
    host, *port_info = REDIS_QUEUE_LOCATION.split(':')
    port = tuple()
    if port_info:
        port, *_ = port_info
        port = (int(port),)

    conn = redis.Redis(host=host, *port)


@router.post("/api/videos", response_model=_schemas.Video)
async def create_video(
        video: _schemas.VideoCreate,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.create_video(current_user=current_user, db=db, video=video)

@router.get("/api/get_all_videos", response_model=List[_schemas.Video])
async def get_all_videos(db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_all_videos(db=db)

@router.get("/api/videos", response_model=List[_schemas.Video])
async def get_videos(
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_videos(current_user=current_user, db=db)

@router.get("/api/videos/{video_id}", response_model=_schemas.Video)
async def get_video(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_video(video_id=video_id, current_user=current_user, db=db)

@router.get("/api/increment_video_views/{video_id}")
async def increment_video_views(
        video_id: int,
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    await _services.increment_video_views(video_id=video_id, db=db)
    all_videos = await _services.get_all_videos(db=db)
    all_videos_json = json.dumps([video.dict() for video in all_videos], default=str)
    RedisResource.conn.publish("backend_videos", all_videos_json)

@router.get("/api/process_video_like/{video_id}")
async def process_video_like(
        video_id: int, 
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    await _services.process_video_like(video_id=video_id, current_user=current_user, db=db)
    all_videos = await _services.get_all_videos(db=db)
    all_videos_json = json.dumps([video.dict() for video in all_videos], default=str)
    RedisResource.conn.publish("backend_videos", all_videos_json)

    liked = await _services.get_liked_status(video_id=video_id, current_user=current_user, db=db)

    # If our video is liked
    if bool(liked):
        # Get the video information / video owner id
        video = await _services.get_video(video_id=video_id, current_user=current_user, db=db)

        # Create a new notification object
        notification = _schemas.NotificationCreate(description=f"{current_user.username} liked your video '{video.video_name}'!")
        await _services.create_notification(notification_obj=notification, user_id=video.owner_id, current_user=current_user, db=db)

        # Send updated notifications to websocket
        all_notifications = await _services.get_all_notifications(user_id=video.owner_id, current_user=current_user, db=db)
        all_notifications_json = json.dumps([{"current_user_id" : current_user.id, "video_owner_id" : video.owner_id, "video_id" : video.id}] + [notification.dict() for notification in all_notifications], default=str)
        RedisResource.conn.publish("new_notification", all_notifications_json)

@router.get("/api/get_liked_status/{video_id}")
async def get_liked_status(
     video_id: int,
     current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
     db: _orm.Session = _fastapi.Depends(_services.get_db_session)
):
    liked = await _services.get_liked_status(video_id=video_id, current_user=current_user, db=db)

    return { "liked" : bool(liked) }

@router.delete("/api/videos/{video_id}", status_code=204)
async def delete_video(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
        await _services.delete_video(video_id=video_id, current_user=current_user, db=db)
        return {"message", "Successfully Deleted"}

@router.put("/api/videos/{video_id}", status_code=200)
async def update_video(
        video_id: int,
        video: _schemas.VideoCreate,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
        await _services.update_video(video_id=video_id, video=video, current_user=current_user, db=db)
        return {"message", "Successfully Updated"}

@router.post("/api/update_video_status")
async def update_video_status(vid_info: VideoInformation,
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    await _services.update_video_status(video_info=vid_info, db=db)
    return {"message", "OK"}

@router.get("/api/get_views/{video_id}")
async def get_views(video_id: int,
                    current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
                    db: _orm.Session = _fastapi.Depends(_services.get_db_session),
                    ):
    video = await _services.get_video(video_id=video_id,current_user=current_user, db=db)
    return video.views


@router.get("/api/view_video/{object_key}")
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

@router.post("/api/comments", response_model=_schemas.CommentCreate)
async def create_comment(
        comment: _schemas.CommentCreate,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
        new_comment = await _services.create_comment(comment=comment, current_user=current_user, db=db)
        new_comments = await _services.get_video_comment(video_id=comment.video_id
                                                                           , current_user=current_user
                                                                           , db=db)
        new_comments_json = json.dumps([comment.dict() for comment in new_comments])
        RedisResource.conn.publish("backend_comments", new_comments_json)

        video = await _services.get_video(video_id=comment.video_id, current_user=current_user, db=db)

        notification = _schemas.NotificationCreate(description=f"{current_user.username} commented on your video '{video.video_name}'!")
        await _services.create_notification(notification_obj=notification, user_id=video.owner_id, current_user=current_user, db=db)

        all_notifications = await _services.get_all_notifications(user_id=video.owner_id, current_user=current_user, db=db)
        all_notifications_json = json.dumps([{"current_user_id" : current_user.id, "video_owner_id" : video.owner_id, "video_id" : video.id}] + [notification.dict() for notification in all_notifications], default=str)
        RedisResource.conn.publish("new_notification", all_notifications_json)
        return new_comment

@router.get("/api/get_video_comments/{video_id}", response_model=List[_schemas.Comment])
async def get_video_comments(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_video_comment(video_id=video_id, current_user=current_user, db=db)

@router.get("/api/get_all_current_user_notifications", response_model=List[_schemas.Notification])
async def get_all_notifications(
     current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
     db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
     return await _services.get_all_current_user_notifications(current_user=current_user, db=db)

@router.get("/api/read_all_notifications")
async def get_all_notifications(
     current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
     db: _orm.Session = _fastapi.Depends(_services.get_db_session)):

     await _services.read_all_notifications(current_user=current_user, db=db)
     return { "message" : "OK" }