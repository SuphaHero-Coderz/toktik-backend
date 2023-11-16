import src.database as _database
import sqlalchemy.orm as _orm
import src.models as _models
import src.schemas as _schemas
import passlib.hash as _hash
import jwt as _jwt
import fastapi as _fastapi
import fastapi.security as _security
from dotenv import load_dotenv
import datetime
import os
from datetime import timezone

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")

from fastapi.security import OAuth2
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi import Request, Response
from fastapi.security.utils import get_authorization_scheme_param
from fastapi import HTTPException
from fastapi import status
from typing import Optional
from typing import Dict


class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.cookies.get("access_token")  #changed to accept access token from httpOnly Cookie
        authorization_refresh: str = request.cookies.get("refresh_token")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization_refresh or not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param

oauth2schema = OAuth2PasswordBearerWithCookie(tokenUrl="/api/token")

def create_database():
    return _database.Base.metadata.create_all(bind=_database.engine)

def get_db_session():
    db = _database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async  def get_user_by_username(username: str, db :_orm.Session):
    """
    Gets a User by their username

    Args:
        username (str): user's username
        db (_orm.Session): database session

    Returns: User object
    """
    return db.query(_models.User).filter(_models.User.username == username).first()

async  def create_user(user: _schemas.UserCreate, db: _orm.Session):
    """
    Creates a new User in the database

    Args:
        user (_schemas.UserCreate): user information object
        db (_orm.Session): database session

    Returns: User object
    """
    user_obj = _models.User(username=user.username, hashed_password=_hash.bcrypt.hash(user.hashed_password))

    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)

    return user_obj

async def authenticate_user(username: str, password: str, db: _orm.Session):
    """
    Authenticates a user given username/password pair

    Args:
        username (str): given username
        password (str): given description
        db (_orm.Session): database session

    Returns: User object
    """
    user = await get_user_by_username(username=username, db=db)

    if not user:
        return False

    if not user.verify_password(password=password):
        return False

    return user

async def create_token(user: _models.User):
    """
    Creates a JWT token for a user

    Args:
        user (_models.User): the user requiring authentication

    Returns: JWT token
    """
    data = {
        "id": user.id,
        "username": user.username,
        "hashed_password": user.hashed_password,
        "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=600)
    }
    token = _jwt.encode(data, JWT_SECRET)

    return token

async def create_refresh_token(user: _models.User):
    """
    Creates a JWT refresh token for a user

    Args:
        user (_models.User): the user requiring authentication

    Returns: JWT refresh token
    """
    data = {
        "id": user.id,
        "username": user.username,
        "hashed_password": user.hashed_password,
        "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=300)
    }
    refresh_token = _jwt.encode(data, JWT_REFRESH_SECRET)

    return refresh_token

async def get_current_user(request: Request, db: _orm.Session = _fastapi.Depends(get_db_session), token: str = _fastapi.Depends(oauth2schema)):
    """
    Gets the current user

    Args:
        request (Request): request
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(get_db_session).
        token (str, optional): authentication token. Defaults to _fastapi.Depends(oauth2schema).

    Raises:
        HTTPException

    Returns: Authenticated User
    """
    try:
        payload = _jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(_models.User).get(payload["id"])
    except  _jwt.ExpiredSignatureError:
        try:
            refresh_token = request.cookies.get("refresh_token").split(" ")[1]
            payload = _jwt.decode(refresh_token, JWT_REFRESH_SECRET, algorithms=["HS256"])
        except AttributeError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )
        except _jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )
        user = db.query(_models.User).get(payload["id"])
        token = await create_token(user)

        return _schemas.AuthUser.model_validate({"id": user.id, "username": user.username, "hashed_password": user.hashed_password, "token": token})

    return _schemas.AuthUser.model_validate({"id": user.id, "username": user.username, "hashed_password": user.hashed_password, "token": token})

async def create_video(video: _schemas.VideoCreate, current_user: _schemas.User, db: _orm.Session):
    """
    Creates a video object in the database

    Args:
        video (_schemas.VideoCreate): video information
        current_user (_schemas.User): the current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: if user is not authenticated

    Returns: video object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    video_obj = _models.Video(object_key=video.object_key, video_name = video.video_name, video_description=video.video_description, video_thumbnail=video.video_thumbnail, processed=False, owner_id=current_user.id)

    db.add(video_obj)
    db.commit()
    db.refresh(video_obj)

    return video_obj

async def select_video(video_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Selects a video by id

    Args:
        video_id (int): id of video to select
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: if no video corresponding to id found

    Returns: Video object
    """
    video = db.query(_models.Video).filter(_models.Video.id == video_id).first()

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    return video

async def get_all_videos(db: _orm.Session):
    """
    Gets all videos in the database in order of views

    Args:
        db (_orm.Session): the database session

    Returns: list of all Video objects
    """
    videos = db.query(_models.Video).filter_by(processed=True).order_by(_models.Video.views.desc())

    return list(map(_schemas.Video.model_validate, videos))

async def get_videos(current_user: _schemas.User, db: _orm.Session):
    """
    Gets all videos belonging to the current user

    Args:
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: list of all Video objects owned by current user
    """
    videos = db.query(_models.Video).filter_by(owner_id=current_user.id)

    return list(map(_schemas.Video.model_validate, videos))

async def get_video(video_id: int , current_user: _schemas.User, db: _orm.Session):
    """
    I'm not sure how this differs from select_video but I feel like removing it is a bad idea.

    Args:
        video_id (int): video id to get
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns: video object
    """
    video = await select_video(video_id=video_id , current_user=current_user, db=db)

    return _schemas.Video.model_validate(video)

async def update_video(video_id: int, video: _schemas.VideoCreate, current_user: _schemas.User, db: _orm.Session):
    """
    Updates a video with new information

    Args:
        video_id (int): video id to update
        video (_schemas.VideoCreate): new video info
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user not authenticated

    Returns: Video object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    video_db = await select_video(video_id=video_id , current_user=current_user, db=db)

    video_db.object_key = video.object_key
    video_db.video_name = video.video_name
    video_db.video_description =  video.video_description

    db.commit()
    db.refresh(video_db)

    return _schemas.Video.model_validate(video_db)

async def increment_video_views(video_id: int, db: _orm.Session):
    """
    Increments the views of a video

    Args:
        video_id (int): video id to increment views of
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case video corresponding to id not found

    Returns: Video object
    """
    video = db.query(_models.Video).filter_by(id=video_id).first()

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    video.views += 1

    db.commit()
    db.refresh(video)

    return _schemas.Video.model_validate(video)

async def create_like(video_info: _schemas.VideoCreate, current_user: _schemas.User, db: _orm.Session):
    """
    Creates a new like object current user on provided video

    Args:
        video_info (_schemas.VideoCreate): video information that like was made on
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: if user is not logged on

    Returns: like object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    video = db.query(_models.Video).filter(_models.Video.object_key == video_info.object_key).first()
    like_obj = _models.Like(user_id=current_user.id, video_id=video.id)

    db.add(like_obj)
    db.commit()
    db.refresh(like_obj)

    return like_obj

async def process_video_like(video_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Processes the liking of a video -- i.e., increments likes if liked and decrements if unliked

    Args:
        video_id (int): the id of video that was liked
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case video is not found

    Returns: video object
    """
    video = db.query(_models.Video).filter_by(id=video_id).first()
    like = db.query(_models.Like).filter_by(video_id=video_id, user_id=current_user.id).first()

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    if bool(like.liked):
        video.likes -= 1
        like.liked = False
    else:
        video.likes += 1
        like.liked = True

    db.commit()
    db.refresh(video)
    db.refresh(like)

    return _schemas.Video.model_validate(video)

async def get_liked_status(video_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Gets the liked status of a video (liked or not by current user)

    Args:
        video_id (int): id of video
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Returns:
        bool: whether or not video is liked
    """
    like = db.query(_models.Like).filter_by(video_id=video_id, user_id=current_user.id).first()

    if like is None:
        like_obj = _models.Like(user_id=current_user.id, video_id=video_id)

        db.add(like_obj)
        db.commit()
        db.refresh(like_obj)

        like = db.query(_models.Like).filter_by(video_id=video_id, user_id=current_user.id).first()

    return like.liked

async def update_video_status(video_info: _schemas.VideoInformation, db: _orm.Session):
    """
    Marks a video as processed

    Args:
        video_info (_schemas.VideoInformation): video information object
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case video not found
    """
    video = db.query(_models.Video).filter(_models.Video.object_key == video_info.object_key).first()

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    video.processed = True

    db.commit()
    db.refresh(video)

async def create_comment(comment: _schemas.CommentCreate, current_user: _schemas.User, db: _orm.Session):
    """
    Creates a comment object in the database

    Args:
        comment (_schemas.CommentCreate): comment info
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user not authenticated
        _fastapi.HTTPException: in case video not found

    Returns: Comment object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    video_id = comment.video_id
    video = await select_video(video_id=video_id, current_user=current_user, db=db)

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    content = comment.content
    comment_obj = _models.Comment(user_id=current_user.id, video_id=video_id, content=content)

    db.add(comment_obj)
    db.commit()
    db.refresh(comment_obj)

    return _schemas.CommentCreate.model_validate(comment_obj)

async def get_video_comment(video_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Gets all comments of a video

    Args:
        video_id (int): id of video
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user not authenticated
        _fastapi.HTTPException: in case video not found

    Returns: list of Comment objects
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    video = await select_video(video_id=video_id, current_user=current_user, db=db)

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    comments = db.query(_models.Comment).filter(_models.Comment.video_id == video_id).order_by(_models.Comment.date_commented.desc())
    return list(map(_schemas.Comment.model_validate, comments))


async def create_notification(notification_obj: _schemas.NotificationCreate, user_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Creates notification object in database

    Args:
        notification_obj (_schemas.NotificationCreate): notification info
        user_id (int): user id to 'notify'
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user not authenticated

    Returns: notification object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    
    notification_obj = _models.Notification(user_id=user_id, description=notification_obj.description, read=False)

    db.add(notification_obj)
    db.commit()
    db.refresh(notification_obj)

    return _schemas.NotificationCreate.model_validate(notification_obj)

async def create_notification_for_subscribers_of(notification_obj: _schemas.NotificationCreate, video_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Creates notification objects for all subscribers of a video id

    Args:
        notification_obj (_schemas.NotificationCreate): notification info
        video_id (int): video id users subscribed to
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user not authenticated

    Returns: notification object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    subscriptions = db.query(_models.Subscription).filter(_models.Subscription.video_id == video_id)

    for subscription in subscriptions:
        await create_notification(notification_obj, subscription.user_id, current_user, db)

    return _schemas.NotificationCreate.model_validate(notification_obj)

async def get_all_notifications(user_id: int, current_user: _schemas.User, db: _orm.Session, max=50):
    """
    Gets all notification objects for user with id `user_id` by latest timestamp

    Args:
        user_id (int): user id to get notifications for
        current_user (_schemas.User): current user
        db (_orm.Session): database session
        max (int, optional): cap on notifications. Defaults to 50.

    Raises:
        _fastapi.HTTPException: in case user not authenticated

    Returns: list of Notification objects
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    
    notifications = db.query(_models.Notification).filter(_models.Notification.user_id == user_id).order_by(_models.Notification.timestamp.desc())
    return list(map(_schemas.Notification.model_validate, notifications))[:max]

async def get_all_current_user_notifications(current_user: _schemas.User, db: _orm.Session, max=50):
    """
    Gets all notification objects for current user by latest timestamp

    Args:
        current_user (_schemas.User): current user
        db (_orm.Session): database session
        max (int, optional): cap on notifications. Defaults to 50.

    Raises:
        _fastapi.HTTPException: in case user not authenticated

    Returns: list of Notification objects
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    
    notifications = db.query(_models.Notification).filter(_models.Notification.user_id == current_user.id).order_by(_models.Notification.timestamp.desc())
    return list(map(_schemas.Notification.model_validate, notifications))[:max]

async def read_all_notifications(current_user: _schemas.User, db: _orm.Session):
    """
    Mark all unread notifications as read

    Args:
        current_user (_schemas.User): current user
        db (_orm.Session): database session
    """
    if current_user is None:
        return []
    
    unread_notifications = db.query(_models.Notification).filter_by(user_id=current_user.id, read=False)

    for notification in unread_notifications:
        notification.read = True

    db.commit()
    
    for notification in unread_notifications:
        db.refresh(notification)
    
async def is_subscribed_to(video_id: int, current_user: _schemas.User, db: _orm.Session) -> bool:
    """
    Checks to see if a user is subscribed to a video

    Args:
        video_id (int): video id to check
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case current user not authenticated

    Returns:
        bool: subscription status
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    subscribed = db.query(_models.Subscription).filter_by(video_id=video_id, user_id=current_user.id).first() is not None

    return subscribed

async def get_all_subscribers_of(video_id: int, current_user: _schemas.User, db: _orm.Session):
    """
    Gets all subscribers of video with id `video_id`

    Args:
        video_id (int): video id to get subscribers of
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user is not authenticated

    Returns:
        _type_: _description_
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    
    subscriptions = db.query(_models.Subscription).filter(_models.Subscription.video_id == video_id)

    return list(map(_schemas.Subscription.model_validate, subscriptions))


async def create_subscription(subscription_obj: _schemas.SubscriptionCreate, current_user: _schemas.User, db: _orm.Session):
    """
    Create subscription object for current user

    Args:
        subscription_obj (_schemas.SubscriptionCreate): subscription info
        current_user (_schemas.User): current user
        db (_orm.Session): database

    Raises:
        _fastapi.HTTPException: in case user is not authenticated

    Returns: Subscription object
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    
    subscription = _models.Subscription(user_id=current_user.id, video_id=subscription_obj.video_id)

    db.add(subscription)
    db.commit()
    db.refresh(subscription)

    return _schemas.SubscriptionCreate.model_validate(subscription)

async def get_all_current_user_subscriptions(current_user: _schemas.User, db: _orm.Session):
    """
    Get all subscriptions of the current user

    Args:
        current_user (_schemas.User): current user
        db (_orm.Session): database session

    Raises:
        _fastapi.HTTPException: in case user is not authenticated

    Returns: array of Subscription objects
    """
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    
    subscriptions = db.query(_models.Subscription).filter(_models.Subscription.user_id == current_user.id)
    return list(map(_schemas.Subscription.model_validate, subscriptions))
