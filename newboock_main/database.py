from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.context import CryptContext

engine = create_engine("sqlite:///database.db", echo=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    permissions = Column(String, nullable=False)

    tasks = relationship("Task", back_populates="owner")

class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    due_date = Column(DateTime, nullable=True)
    is_done = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="tasks")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String, unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")

def create_user(db, email: str, password: str, permissions: str):
    user = User(email=email, password=hash_password(password), permissions=permissions)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def get_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()
