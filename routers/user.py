from fastapi import APIRouter, Depends, HTTPException, Security, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
import cachetools
from auth_helper.authorization import Authorization
from db.config_db import get_session
import crud
from schemas import user_post_schemas
from typing import List

router = APIRouter()
security = HTTPBearer()
auth_handler = Authorization()

cache = cachetools.TTLCache(maxsize=100, ttl=300)

@router.post('/register', response_model=user_post_schemas.UserResponse)
def register(user_details: user_post_schemas.UserSchemas, db: Session = Depends(get_session)):
    existing_user = crud.get_user_by_email(db, user_details.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    try:
        user = crud.create_user(db, user_details)
        return user
    except Exception as e:
        db.rollback()
        error_msg = f"Failed to register user. Error: {str(e)}"
        raise HTTPException(status_code=500, detail=error_msg)

@router.post('/authenticate', response_model=user_post_schemas.Token)
def authenticate(user_details: user_post_schemas.UserSchemas, db: Session = Depends(get_session)):
    user = crud.get_user_by_email(db, user_details.email)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid username or password')

    if not auth_handler.verify_password(user_details.password, user.password):
        raise HTTPException(status_code=401, detail='Invalid username or password')

    access_token = auth_handler.encode_token(str(user.id))
    refresh_token = auth_handler.encode_refresh_token(str(user.id))
    return {'access_token': access_token, 'refresh_token': refresh_token}

@router.get('/token/refresh', response_model=user_post_schemas.TokenResponse)
def token_refresh(credentials: HTTPAuthorizationCredentials = Security(security)):
    refresh_token = credentials.credentials
    new_access_token, new_refresh_token = auth_handler.refresh_token(refresh_token)
    if not new_access_token or not new_refresh_token:
        raise HTTPException(status_code=401, detail='Invalid refresh token')
    return {
        'access_token': new_access_token,
        'refresh_token': new_refresh_token,
        'token_type': 'bearer'
    }

# Article Routes

@router.post("/articles", response_model=user_post_schemas.PostResponse)
def add_article(post: user_post_schemas.PostCreate, request: Request, credentials: HTTPAuthorizationCredentials = Security(security),
                db: Session = Depends(get_session)):
    if request.headers.get('content-length') and int(request.headers['content-length']) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large")

    id = auth_handler.decode_token(credentials.credentials)
    user = crud.get_user_by_id(db, id=id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return crud.create_post(db=db, post=post, user_id=user.id)

@router.get("/articles", response_model=List[user_post_schemas.PostResponse])
def get_articles(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_session)):
    id = auth_handler.decode_token(credentials.credentials)
    user = crud.get_user_by_id(db, id=id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if id in cache:
        return cache[id]
    posts = crud.get_posts_by_user(db, user_id=user.id)
    cache[id] = posts
    return posts

@router.delete("/articles/{article_id}", response_model=str)
def delete_article(article_id: int, credentials: HTTPAuthorizationCredentials = Security(security),
                   db: Session = Depends(get_session)):
    id = auth_handler.decode_token(credentials.credentials)
    user = crud.get_user_by_id(db, id=id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    crud.delete_post(db, post_id=article_id, user_id=user.id)
    return "Article deleted successfully"
