# schemas.py
from pydantic import BaseModel, EmailStr

class Registration(BaseModel):
    email: EmailStr
    password: str

class Login(BaseModel):
    email: EmailStr
    password: str
