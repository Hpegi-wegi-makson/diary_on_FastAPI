# main.py
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from database import SessionLocal, create_user, get_user_by_email, User
from schemas import Registration, Login
from jwt_manager import create_access_token, get_current_user, check_role
from config import USER_ROLE, ADMIN_ROLE, MODERATOR_ROLE

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------ REGISTRATION ------------------
@app.post("/registration")
def registration(user: Registration, db: Session = Depends(get_db)):
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email уже зарегистрирован")
    new_user = create_user(db, user.email, user.password, role=USER_ROLE)
    return {"id": new_user.id, "email": new_user.email, "role": new_user.role}

# ------------------ LOGIN ------------------
@app.post("/login")
def login(user: Login, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user or not db_user.password:
        raise HTTPException(status_code=400, detail="Пользователя с таким Email не найдено")
    from database import verify_password
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Password неправильный")

    access_token = create_access_token({"id": db_user.id, "email": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# ------------------ GET ME (USER) ------------------
@app.get("/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email, "role": current_user.role}

# ------------------ ADMIN ONLY ------------------
@app.get("/admin")
def admin_panel(current_user: User = Depends(check_role(ADMIN_ROLE))):
    return {"message": f"Hello {current_user.email}, you are admin!"}

