import database as _database
import sqlalchemy.orm as _orm
import models as _models
import schemas as _schemas
import passlib.hash as _hash
import jwt as _jwt
import fastapi as _fastapi
import fastapi.security as _security
from dotenv import load_dotenv
import os

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
oauth2schema = _security.OAuth2PasswordBearer(tokenUrl="/api/token")

def create_database():
    return _database.Base.metadata.create_all(bind=_database.engine)

def get_db_session():
        db = _database.SessionLocal()
        try:
            yield db
        finally:
            db.close()

async  def get_user_by_username(username: str, db :_orm.Session):
    return db.query(_models.User).filter(_models.User.username == username).first()

async  def create_user(user: _schemas.UserCreate, db: _orm.Session):
    user_obj = _models.User(username=user.username, hashed_password=_hash.bcrypt.hash(user.hashed_password))
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    return user_obj

async def authenticate_user(username: str, password: str, db: _orm.Session):
    user = await get_user_by_username(username=username, db=db)

    if not user:
        return False

    if not user.verify_password(password=password):
        return False

    return user

async def create_token(user: _models.User):
    user_obj = _schemas.User.model_validate({"id": user.id, "username": user.username, "hashed_password": user.hashed_password})

    token = _jwt.encode(user_obj.model_dump(), JWT_SECRET)

    return dict(access_token=token, token_type="bearer")

async def get_current_user(db: _orm.Session = _fastapi.Depends(get_db_session),
                           token: str = _fastapi.Depends(oauth2schema)):
    try:
        payload = _jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(_models.User).get(payload["id"])
    except:
        raise _fastapi.HTTPException(
            status_code=401, detail="Invalid Username or Password"
        )
    return _schemas.User.model_validate({"id": user.id, "username": user.username, "hashed_password": user.hashed_password})

async def select_user(user_id: int, current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    user = db.query(_models.User).get(user_id)
    if user is None:
        raise _fastapi.HTTPException(status_code=404, detail="User not found")
    return user

async def get_user(user_id: int , current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    user = await select_user(user_id=user_id, current_user=current_user, db=db)
    return _schemas.User.model_validate({"id": user.id, "username": user.username, "hashed_password": user.hashed_password})

async def delete_user(user_id: int, current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    user = await select_user(user_id=user_id, current_user=current_user, db=db)
    db.delete(user)
    db.commit()

async def create_video(video: _schemas.VideoCreate, current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    video_obj = _models.Video(object_key=video.object_key, video_name = video.video_name, video_description=video.video_description, video_thumbnail=video.video_thumbnail, processed=False, owner_id=current_user.id)
    db.add(video_obj)
    db.commit()
    db.refresh(video_obj)
    return video_obj

async def select_video(video_id: int, current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    video = db.query(_models.Video).filter_by(owner_id=current_user.id).filter(_models.Video.id == video_id).first()
    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")
    return video

async def get_all_videos(db: _orm.Session):
    videos = db.query(_models.Video).all()
    return list(map(_schemas.Video.model_validate, videos))

async def get_videos(current_user: _schemas.User, db: _orm.Session):
    videos = db.query(_models.Video).filter_by(owner_id=current_user.id)
    return list(map(_schemas.Video.model_validate, videos))

async def get_video(video_id: int , current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    video = await select_video(video_id=video_id , current_user=current_user, db=db)
    return _schemas.Video.model_validate(video)

async def update_video(video_id: int, video: _schemas.VideoCreate, current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    video_db = await select_video(video_id=video_id , current_user=current_user, db=db)
    video_db.object_key = video.object_key
    video_db.video_name = video.video_name
    video_db.video_description =  video.video_description

    db.commit()
    db.refresh(video_db)

    return _schemas.Video.model_validate(video_db)

async def update_video_status(video_info: _schemas.VideoInformation, db: _orm.Session):
    video = db.query(_models.Video).filter(_models.Video.object_key == video_info.object_key).first()

    if video is None:
        raise _fastapi.HTTPException(status_code=404, detail="Video not found")

    video.processed = True

    db.commit()
    db.refresh(video)

async def delete_video(video_id: int,  current_user: _schemas.User, db: _orm.Session):
    if current_user is None:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    video = await select_video(video_id=video_id , current_user=current_user, db=db)
    db.delete(video)
    db.commit()




