import sqlalchemy as _sql
import  passlib.hash as _hash
import sqlalchemy.orm as _orm
import src.database as _database
import datetime as _dt
import os

class User(_database.Base):
    __tablename__ = "users"
    id = _sql.Column(_sql.Integer, primary_key=True, index=True)
    username = _sql.Column(_sql.String, unique=True, index=True)
    hashed_password = _sql.Column(_sql.String)

    videos = _orm.relationship("Video", back_populates="owner")

    # verify that the password given is the same as the hashed_password being kept
    def verify_password(self, password: str):
        return _hash.bcrypt.verify(password, self.hashed_password)

class Video(_database.Base):
    __tablename__ = "videos"
    id = _sql.Column(_sql.Integer, primary_key=True, index=True)
    owner_id = _sql.Column(_sql.Integer, _sql.ForeignKey("users.id"))
    object_key = _sql.Column(_sql.String, index=True)
    video_name = _sql.Column(_sql.String, index=True)
    video_description = _sql.Column(_sql.String, default="")
    video_thumbnail = _sql.Column(_sql.String, default=os.getenv("CLOUDFRONT_ORIGIN_URL"))
    date_uploaded = _sql.Column(_sql.DateTime, default=_dt.datetime.utcnow)
    processed = _sql.Column(_sql.Boolean, default=False)
    views = _sql.Column(_sql.Integer, default=1)
    likes = _sql.Column(_sql.Integer, default=0)

    owner = _orm.relationship("User", back_populates="videos")

class Like(_database.Base):
    __tablename__ = "likes"
    id = _sql.Column(_sql.Integer, primary_key=True, index=True)
    video_id = _sql.Column(_sql.Integer, _sql.ForeignKey("videos.id"))
    user_id = _sql.Column(_sql.Integer, _sql.ForeignKey("users.id"))
    liked = _sql.Column(_sql.Boolean, default=False)