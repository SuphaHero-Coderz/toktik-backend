import fastapi as _fastapi
import sqlalchemy.orm as _orm
from fastapi import APIRouter

import src.db_services as _services
import src.schemas as _schemas
from typing import List

router = APIRouter(tags=["videos"])

@router.post("/api/videos", response_model=_schemas.Video)
async def create_video(
        video: _schemas.VideoCreate,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.create_video(current_user=current_user, db=db, video=video)

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