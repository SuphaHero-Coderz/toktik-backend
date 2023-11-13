from typing import List, Optional
import pydantic as _pydantic
import datetime as _dt

class _UserBase(_pydantic.BaseModel):
    model_config = _pydantic.ConfigDict(from_attributes = True)
    username: str

class UserCreate(_UserBase):
    hashed_password: str

    class Config:
        orm_mode = True
        from_attributes = True

class User(_UserBase):
    id: int

    class Config:
        orm_mode = True
        from_attributes=True

class AuthUser(_UserBase):
    id: int
    token: str
    class Config:
        orm_mode = True
        from_attributes=True

class _VideoBase(_pydantic.BaseModel):
    model_config = _pydantic.ConfigDict(from_attributes=True)
    object_key: str
    video_name: str
    video_description: str
    video_thumbnail: str
    processed: bool
    views: int
    likes: int

class VideoCreate(_VideoBase):
    pass

class Video(_VideoBase):
    id: Optional[int] = _pydantic.Field(default=None, primary_key=True)
    owner_id: int
    date_uploaded: _dt.datetime


    class Config:
        orm_mode = True
        from_attributes = True

class VideoInformation(_pydantic.BaseModel):
    object_key: str
    video_name: str
    video_description: str

class _LikeBase(_pydantic.BaseModel):
    model_config = _pydantic.ConfigDict(from_attributes = True)
    user_id: int
    video_id: int
    liked: bool

class Like(_LikeBase):
    id: Optional[int] = _pydantic.Field(default=None, primary_key=True)
