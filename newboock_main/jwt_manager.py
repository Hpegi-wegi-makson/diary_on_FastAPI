from datetime import datetime, timedelta
import hashlib
from jose import jwt, JWTError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from database import User, RefreshToken
from dependencies import get_db
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = HTTPBearer()


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, expires_days: int = 7):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=expires_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token=Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        token_type = payload.get("type")
        if token_type != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def store_refresh_token(db: Session, user_id: int, token: str, expires_at: datetime) -> RefreshToken:
    token_hash = hash_refresh_token(token)
    refresh = RefreshToken(
        token_hash=token_hash,
        user_id=user_id,
        expires_at=expires_at
    )
    db.add(refresh)
    db.commit()
    db.refresh(refresh)
    return refresh


def revoke_refresh_token(db: Session, token: str) -> None:
    token_hash = hash_refresh_token(token)
    refresh = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if refresh and refresh.revoked_at is None:
        refresh.revoked_at = datetime.utcnow()
        db.commit()
