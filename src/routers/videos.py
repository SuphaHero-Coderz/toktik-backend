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
async def create_video(video: _schemas.VideoCreate, current_user: _schemas.User = _fastapi.Depends(_services.get_current_user), db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Creates a video object in the database

    Args:
        video (_schemas.VideoCreate): video information
        current_user (_schemas.User): the current user
        db (_orm.Session): database session

    Returns: video object
    """
    return await _services.create_video(current_user=current_user, db=db, video=video)

@router.get("/api/get_all_videos", response_model=List[_schemas.Video])
async def get_all_videos(db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Gets all videos in the database in order of views

    Args:
        db (_orm.Session): the database session

    Returns: list of all Video objects
    """
    return await _services.get_all_videos(db=db)

@router.get("/api/get_videos/", response_model=List[_schemas.Video])
async def get_more_videos(offset: int, length: int, db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Gets more videos after loading a specific amount

    Args:
        offset (int): offset
        length (int): length
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Returns: list of additional Video objects
    """
    all_videos = await _services.get_all_videos(db=db)
    end = offset + length

    if end > len(all_videos):
        return all_videos[offset:]

    return all_videos[offset: end]

@router.get("/api/videos", response_model=List[_schemas.Video])
async def get_videos(
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Gets all videos belonging to the current user

    Args:
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: list of all Video objects owned by current user
    """
    return await _services.get_videos(current_user=current_user, db=db)

@router.get("/api/videos/{video_id}", response_model=_schemas.Video)
async def get_video(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    I'm not sure how this differs from select_video but I feel like removing it is a bad idea.

    Args:
        video_id (int): video id to get
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: video object
    """
    return await _services.get_video(video_id=video_id, current_user=current_user, db=db)

@router.get("/api/increment_video_views/{video_id}")
async def increment_video_views(
        video_id: int,
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Increments the views of a video

    Args:
        video_id (int): video id to increment views of
        db (_orm.Session): database session

    Returns: Video object
    """
    await _services.increment_video_views(video_id=video_id, db=db)

    all_videos = await _services.get_all_videos(db=db)
    all_videos_json = json.dumps([video.dict() for video in all_videos], default=str)

    RedisResource.conn.publish("backend_videos", all_videos_json)

@router.get("/api/process_video_like/{video_id}")
async def process_video_like(
        video_id: int, 
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Processes the liking of a video -- i.e., increments likes if liked and decrements if unliked.
    Then will handle notification/subscription process.

    Args:
        video_id (int): the id of video that was liked
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: video object
    """
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
        
        # If the user not subscribed to video (and also not owner), subscribe them upon like
        subscribed = await _services.is_subscribed_to(video.id, current_user, db)
        if video.owner_id != current_user.id and not subscribed:
            subscription = _schemas.SubscriptionCreate(video_id=video.id)
            await _services.create_subscription(subscription_obj=subscription, current_user=current_user, db=db)

        # Send relevant info to socket
        notification_json = json.dumps([{"current_user_id" : current_user.id, "video_owner_id" : video.owner_id}] + [notification.dict()], default=str)
        RedisResource.conn.publish("new_notification", notification_json)

@router.get("/api/get_liked_status/{video_id}")
async def get_liked_status(
     video_id: int,
     current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
     db: _orm.Session = _fastapi.Depends(_services.get_db_session)
):
    """
    Gets the liked status of a video (liked or not by current user)

    Args:
        video_id (int): id of video
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns:
        bool: whether or not video is liked
    """
    liked = await _services.get_liked_status(video_id=video_id, current_user=current_user, db=db)

    return { "liked" : bool(liked) }

@router.put("/api/videos/{video_id}", status_code=200)
async def update_video(
    video_id: int,
    video: _schemas.VideoCreate,
    current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
    db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Updates a video with new information

    Args:
        video_id (int): video id to update
        video (_schemas.VideoCreate): new video info
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: Video object
    """
    await _services.update_video(video_id=video_id, video=video, current_user=current_user, db=db)
    return {"message", "Successfully Updated"}

@router.post("/api/update_video_status")
async def update_video_status(vid_info: VideoInformation,
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Marks a video as processed

    Args:
        video_info (_schemas.VideoInformation): video information object
        db (_orm.Session): database session
    """
    await _services.update_video_status(video_info=vid_info, db=db)
    return {"message", "OK"}

@router.get("/api/get_views/{video_id}")
async def get_views(video_id: int,
                    current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
                    db: _orm.Session = _fastapi.Depends(_services.get_db_session),
                    ):
    """
    Get views for a video

    Args:
        video_id (int): video id
        current_user (_schemas.User, optional): current user. Defaults to _fastapi.Depends(_services.get_current_user).
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Returns: views of the video
    """
    video = await _services.get_video(video_id=video_id,current_user=current_user, db=db)
    return video.views

@router.get("/api/get_likes/{video_id}")
async def get_likes(video_id: int,
                    current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
                    db: _orm.Session = _fastapi.Depends(_services.get_db_session),
                    ):
    """
    Get likes for a video

    Args:
        video_id (int): video id
        current_user (_schemas.User, optional): current user. Defaults to _fastapi.Depends(_services.get_current_user).
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Returns: views of the video
    """
    video = await _services.get_video(video_id=video_id,current_user=current_user, db=db)
    return video.likes


@router.get("/api/view_video/{object_key}")
async def view_video(object_key: str):
    """
    Handles signing of HLS stream chunks for video streaming

    Args:
        object_key (str): object key of video
    """
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
    """
    Creates a comment object in the database. 
    Also handles notification/subscription process.

    Args:
        comment (_schemas.CommentCreate): comment info
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: Comment object
    """
    new_comment = await _services.create_comment(comment=comment, current_user=current_user, db=db)
    new_comments = await _services.get_video_comment(video_id=comment.video_id, current_user=current_user, db=db)
    new_comments_json = json.dumps([comment.dict() for comment in new_comments])
    RedisResource.conn.publish("backend_comments", new_comments_json)

    video = await _services.get_video(video_id=comment.video_id, current_user=current_user, db=db)

    # Create a new notification for the owner of the video
    notification = _schemas.NotificationCreate(description=f"{current_user.username} commented on your video '{video.video_name}'!")
    await _services.create_notification(notification_obj=notification, user_id=video.owner_id, current_user=current_user, db=db)

    # Also create notifications for everyone subscribed to the video
    notification = _schemas.NotificationCreate(description=f"{current_user.username} commented on '{video.video_name}'!")
    await _services.create_notification_for_subscribers_of(notification_obj=notification, video_id=video.id, current_user=current_user, db=db)
    
    # If the user not subscribed to video (and also not owner), subscribe them upon comment
    subscribed = await _services.is_subscribed_to(video.id, current_user, db)
    if video.owner_id != current_user.id and not subscribed:
        subscription = _schemas.SubscriptionCreate(video_id=video.id)
        await _services.create_subscription(subscription_obj=subscription, current_user=current_user, db=db)

    # Get list of all subscribers of the video
    subscribers = await _services.get_all_subscribers_of(video_id=video.id, current_user=current_user, db=db)

    # Send relevant info to socket
    notification_json = json.dumps([{"current_user_id" : current_user.id, "video_owner_id" : video.owner_id, "subscribers" : [s.user_id for s in subscribers]}] + [notification.dict()], default=str)
    RedisResource.conn.publish("new_notification", notification_json)

    return new_comment

@router.get("/api/get_video_comments/{video_id}", response_model=List[_schemas.Comment])
async def get_video_comments(
        video_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Gets all comments of a video

    Args:
        video_id (int): id of video
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: list of Comment objects
    """
    return await _services.get_video_comment(video_id=video_id, current_user=current_user, db=db)

@router.get("/api/get_all_current_user_notifications", response_model=List[_schemas.Notification])
async def get_all_notifications(
     current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
     db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
     return await _services.get_all_current_user_notifications(current_user=current_user, db=db)

@router.get("/api/read_all_notifications")
async def get_all_notifications(current_user: _schemas.User = _fastapi.Depends(_services.get_current_user), db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Gets all notification objects for current user by latest timestamp

    Args:
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: list of Notification objects
    """

    await _services.read_all_notifications(current_user=current_user, db=db)
    return { "message" : "OK" }

@router.get("/api/get_socket_info")
async def get_all_subscriptions(current_user: _schemas.User = _fastapi.Depends(_services.get_current_user), db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Gets subscription info for socket (userid and subscriptions)

    Args:
        current_user (_schemas.User, optional): current user. Defaults to _fastapi.Depends(_services.get_current_user).
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Returns: user id and subscriptions object
    """
    subscriptions = await _services.get_all_current_user_subscriptions(current_user=current_user, db=db)
     
    return { "user_id" : current_user.id, "subscriptions" : subscriptions }