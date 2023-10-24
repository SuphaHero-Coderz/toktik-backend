from typing import Optional
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

class _VideoBase(_pydantic.BaseModel):
    model_config = _pydantic.ConfigDict(from_attributes=True)
    object_key: str
    video_name: str
    video_description: str
    processed: bool

class VideoCreate(_VideoBase):
    pass

class Video(_VideoBase):
    id: Optional[int] = _pydantic.Field(default=None, primary_key=True)
    owner_id: int
    date_uploaded: _dt.datetime


    class Config:
        orm_mode = True
        from_attributes = True
