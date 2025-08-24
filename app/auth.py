from uuid import UUID
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import status, FastAPI, HTTPException, Depends, Security, Request
import jwt #pip install pyjwt https://pypi.org/project/PyJWT/
from pydantic import BaseModel
from fastapi.encoders import jsonable_encoder
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.models import User
from typing import Annotated
import bcrypt
# for Render hosting environment 

import json
import os
from dotenv import load_dotenv
load_dotenv()
CONFIG_PATH = os.getenv('config_path')

with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)

JWT_SECRET = config['JWT_SECRET']
ALGORITHM = config['ALGORITHM']
ACCESS_TOKEN_EXPIRE_MINUTES = config['ACCESS_TOKEN_EXPIRE_MINUTES']
REFRESH_TOKEN_EXPIRE_DAYS = config['REFRESH_TOKEN_EXPIRE_DAYS']
API_URL = config['API_URL']
FRONTEND_URL = config['FRONTEND_URL']

# local debug

# from app.certificates.secrecy import JWT_SECRET, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS

# API_URL = "http://localhost:8000"
# FRONTEND_URL = "http://localhost:3000"





bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if the hashed password matches the provided password
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return False
    
    return user

def create_access_token(username: str, user_id: UUID, role: str, expires_delta: timedelta) -> str:
    encode = {'sub': username, 'id': str(user_id), 'role' : role}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, JWT_SECRET, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/token")

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid or expired")
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid or expired")
    
# oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/users/token")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get('sub').strip()
        user_id_raw: str = payload.get('id').strip()
        
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')
        user_id = UUID(user_id_raw)
        return {'username': username, 'id': user_id}
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')

user_dependency = Annotated[dict, Depends(get_current_user)]

# custom credentials extraction class

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if credentials.scheme.lower() != "bearer":
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication scheme.")
            token = credentials.credentials
            if not self.verify_jwt(token):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")
            return token
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization code.")

    def verify_jwt(self, token: str) -> bool:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username is None:
                return False
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False




jwt_bearer = JWTBearer()