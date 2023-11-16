import fastapi as _fastapi
import fastapi.security as _security
import sqlalchemy.orm as _orm
from fastapi import APIRouter
from fastapi import Response

import src.db_services as _services
import src.schemas as _schemas

router = APIRouter(tags=["users"])

@router.post("/api/users")
async  def create_user(user: _schemas.UserCreate, db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Creates a user

    Args:
        user (_schemas.UserCreate): user information
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Raises:
        _fastapi.HTTPException: in case username already taken

    Returns: JWT token / refresh token
    """

    # Verify that username not taken
    db_user = await _services.get_user_by_username(user.username, db)

    if db_user:
        raise _fastapi.HTTPException(status_code=400, detail="Username already in use")

    # Create user and generate access/refresh tokens
    user = await _services.create_user(user, db)
    access_token = await _services.create_token(user)
    refresh_token = await _services.create_refresh_token(user)
    content = {"access_token": access_token, "token_type": "bearer"}

    # Create response with tokens as cookies
    response = _fastapi.responses.JSONResponse(content=content)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    response.set_cookie(key="refresh_token", value=f"Bearer {refresh_token}", httponly=True)

    return response

@router.post("/api/token")
async def generate_token(form_data: _security.OAuth2PasswordRequestForm = _fastapi.Depends(), db: _orm.Session = _fastapi.Depends(_services.get_db_session)):
    """
    Generates a JWT token / refresh token on login

    Args:
        form_data (_security.OAuth2PasswordRequestForm, optional): login form info. Defaults to _fastapi.Depends().
        db (_orm.Session, optional): database session. Defaults to _fastapi.Depends(_services.get_db_session).

    Raises:
        _fastapi.HTTPException: in the case of invalid credentials

    Returns: JWT token / refresh token
    """
    # Verify user credentials correct
    user = await _services.authenticate_user(username=form_data.username, password=form_data.password, db=db)

    if not user:
        raise _fastapi.HTTPException(status_code=401, detail="Invalid Credentials")

    # Generate access/refresh tokens
    access_token = await _services.create_token(user)
    refresh_token = await _services.create_refresh_token(user)
    content = {"access_token": access_token, "token_type": "bearer"}

    # Create response with token as cookies
    response = _fastapi.responses.JSONResponse(content=content)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    response.set_cookie(key="refresh_token", value=f"Bearer {refresh_token}", httponly=True)

    return response

@router.get("/api/users/me", response_model=_schemas.User)
async def get_current_user(response: Response, user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    """
    Get current user

    Args:
        response (Response): token information
        user (_schemas.User, optional): user object. Defaults to _fastapi.Depends(_services.get_current_user).

    Returns: User object
    """
    response.set_cookie(key="access_token", value=f"Bearer {user.token}", httponly=True)

    return _schemas.User.model_validate({"id": user.id, "username": user.username, "token": user.token})

@router.get("/api/logout")
async def logout(response: Response, current_user: _schemas.User = _fastapi.Depends(_services.get_current_user)):
    """
    Logs a user out by deleting their cookies

    Args:
        response (Response): response object
        current_user (_schemas.User, optional): current user. Defaults to _fastapi.Depends(_services.get_current_user).

    Returns: object
    """
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    return {"message", "ok"}
