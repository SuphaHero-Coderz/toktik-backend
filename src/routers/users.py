import fastapi as _fastapi
import fastapi.security as _security
import sqlalchemy.orm as _orm
from fastapi import APIRouter
from fastapi import Response, Request

import src.db_services as _services
import src.schemas as _schemas

router = APIRouter(tags=["users"])
@router.post("/api/users")
async  def create_user(user: _schemas.UserCreate, db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    db_user = await _services.get_user_by_username(user.username, db)
    if db_user:
        raise _fastapi.HTTPException(status_code=400, detail="Username already in use")
    user = await _services.create_user(user, db)
    access_token = await _services.create_token(user)
    refresh_token = await _services.create_refresh_token(user)
    content = {"access_token": access_token, "token_type": "bearer"}
    response = _fastapi.responses.JSONResponse(content=content)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    response.set_cookie(key="refresh_token", value=f"Bearer {refresh_token}", httponly=True)
    return response


@router.post("/api/token")
async def generate_token(form_data: _security.OAuth2PasswordRequestForm = _fastapi.Depends(),
                         db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    user = await _services.authenticate_user(username=form_data.username, password=form_data.password, db=db)
    if not user:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")
    access_token = await _services.create_token(user)
    refresh_token = await _services.create_refresh_token(user)
    content = {"access_token": access_token, "token_type": "bearer"}
    response = _fastapi.responses.JSONResponse(content=content)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    response.set_cookie(key="refresh_token", value=f"Bearer {refresh_token}", httponly=True)
    return response

@router.get("/api/users/me", response_model=_schemas.User)
async def get_current_user(user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    return user

@router.get("/api/users/{user_id}", response_model=_schemas.User)
async def get_user(
        user_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    return await _services.get_user(user_id=user_id, current_user=current_user, db=db)

@router.delete("/api/users/{user_id}", status_code=204)
async def delete_user(
        user_id: int,
        current_user: _schemas.User = _fastapi.Depends(_services.get_current_user),
        db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    await _services.delete_user(user_id=user_id, current_user=current_user, db=db)
    return {"message", "Successfully Deleted"}
@router.get("/api/logout")
async def logout(response: Response, current_user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message", "ok"}
