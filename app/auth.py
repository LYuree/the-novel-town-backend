from fastapi import Request, HTTPException, status, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

import jwt  # PyJWT
import json
import bcrypt  # bcrypt password checking

from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.models import User  # Your SQLAlchemy User model
from app.database import get_db  # Your DB session dependency

# Load secrets/config from a file (adjust path as needed)
with open('/etc/secrets/secrecy.config.json', 'r') as f:
    config = json.load(f)

JWT_SECRET = config['JWT_SECRET']
ALGORITHM = config['ALGORITHM']
ACCESS_TOKEN_EXPIRE_MINUTES = config['ACCESS_TOKEN_EXPIRE_MINUTES']
REFRESH_TOKEN_EXPIRE_DAYS = config['REFRESH_TOKEN_EXPIRE_DAYS']

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/token")


# Password verification function using bcrypt
async def authenticate_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        # Password does not match
        return False
    return user


def create_access_token(username: str, user_id: UUID, role: str, expires_delta: timedelta) -> str:
    """
    Create a JWT access token that includes the username, user UUID (as string), and role, with expiration.
    """
    payload = {
        'sub': username,
        'id': str(user_id),  # UUID must be converted to string for JWT
        'role': role,
        'exp': datetime.utcnow() + expires_delta
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)
    return token


def verify_token(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Verify JWT token validity and return payload dict.
    Raises HTTP 401 if invalid.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Token is invalid or expired")
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token is invalid or expired")


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Decode JWT token, validate required fields, convert user ID to UUID,
    and return a dict with username and UUID user ID.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id_raw = payload.get('id')
        if username is None or user_id_raw is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')

        # Convert user ID string to UUID
        user_id = UUID(user_id_raw)
        return {'username': username, 'id': user_id}
    except (jwt.InvalidTokenError, ValueError):
        # ValueError can be raised by UUID() if malformed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')


# Type alias for Dependency Injection
user_dependency = Annotated[dict, Depends(get_current_user)]


class JWTBearer(HTTPBearer):
    """
    Custom bearer token validator class to validate JWT tokens.
    Can be used as a FastAPI Security dependency.
    """

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> str:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        if credentials:
            if credentials.scheme.lower() != "bearer":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication scheme."
                )
            token = credentials.credentials
            if not self.verify_jwt(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token."
                )
            return token
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization code."
            )

    def verify_jwt(self, token: str) -> bool:
        """
        Verify the JWT token is valid and not expired.
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username is None:
                return False
            return True
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return False


# Instance of JWTBearer for use as a dependency
jwt_bearer = JWTBearer()

