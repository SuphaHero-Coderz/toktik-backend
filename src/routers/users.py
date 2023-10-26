from fastapi import APIRouter
from ..schemas import  UserCreate, User
from ..db_services import get_db_session, authenticate_user, create_token, get_user, delete_user, get_user_by_username, get_current_user
import fastapi as _fastapi
import sqlalchemy.orm as _orm
import fastapi.security as _security


router = APIRouter(tags=["users"])
@router.post("/api/users")
async  def create_user(user: UserCreate, db: _orm.Session = _fastapi.Depends(get_db_session)):
    db_user = await get_user_by_username(user.username, db)
    if db_user:
        raise _fastapi.HTTPException(status_code=400, detail="Username already in use")
    user = await create_user(user, db)
    return await create_token(user)

@router.post("/api/token")
async def generate_token(form_data: _security.OAuth2PasswordRequestForm = _fastapi.Depends(),
                         db: _orm.Session = _fastapi.Depends(get_db_session)):
    user = await authenticate_user(username=form_data.username, password=form_data.password, db=db)
    if not user:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    return await create_token(user)

@router.get("/api/users/me", response_model= User)
async def get_current_user(user: User = _fastapi.Depends(get_current_user)):
    return user

@router.get("/api/users/{user_id}", response_model= User)
async def get_user(
        user_id: int,
        current_user: User = _fastapi.Depends(get_current_user),
        db: _orm.Session = _fastapi.Depends(get_db_session)):
    return await get_user(user_id=user_id, current_user=current_user, db=db)

@router.delete("/api/users/{user_id}", status_code=204)
async def delete_user(
        user_id: int,
        current_user: User = _fastapi.Depends(get_current_user),
        db: _orm.Session = _fastapi.Depends(get_db_session)):
    await delete_user(user_id=user_id, current_user=current_user, db=db)
    return {"message", "Successfully Deleted"}