import fastapi as _fastapi
import sqlalchemy.orm as _orm
from fastapi import APIRouter
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

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

router = APIRouter(tags=["videos"])

load_dotenv()

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
    print("update_video_status")
    await _services.update_video_status(video_info=vid_info, db=db)
    return {"message", "OK"}

@router.get("/view_video/{object_key}")
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
