import pydantic as _pydantic
import datetime as _dt

class _UserBase(_pydantic.BaseModel):
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
        from_attributes = True

class _VideoBase(_pydantic.BaseModel):
    object_key: str
    video_name: str
    video_description: str

class VideoCreate(_VideoBase):
    pass

class Video(_VideoBase):
    id: int
    owner_id: int
    date_uploaded: _dt.datetime

    class Config:
        orm_mode = True