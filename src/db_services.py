import database as _database
import sqlalchemy.orm as _orm
import models as _models
import schemas as _schemas
import passlib.hash as _hash

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