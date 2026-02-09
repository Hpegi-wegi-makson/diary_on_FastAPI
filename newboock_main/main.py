from datetime import datetime, timezone
from typing import Optional
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Query, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from database import create_user, get_user_by_email, verify_password, User, Task, RefreshToken
from dependencies import get_db
from schemas import Registration, Login, TaskOut, TaskUpdate, TaskIn, RefreshRequest
from jwt_manager import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_refresh_token,
    store_refresh_token,
    revoke_refresh_token
)
from permissions import init_permissions_by_role, check_permission
from jose import jwt, JWTError
from config import SECRET_KEY, ALGORITHM

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
#----------------------для html-----------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "title": "Вход",
            "user": None
        }
    )
#-------------для html-----------------------------------
@app.get("/register", response_class=HTMLResponse)
def registration_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "title": "Регистрация",
            "user": None
        }
    )
# ------------------ REGISTRATION ------------------
@app.post("/registration")
def registration(user: Registration, db: Session = Depends(get_db)):
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    permissions = init_permissions_by_role("user")
    new_user = create_user(db, user.email, user.password, permissions)
    return {
        "id": new_user.id,
        "email": new_user.email,
        "permissions": new_user.permissions
    }


# ------------------ LOGIN ------------------
@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"id": user.id})

    response = RedirectResponse(url="/navbooks", status_code=302)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax"
    )

    return response

@app.get("/navbooks", response_class=HTMLResponse)
def navbooks(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    return templates.TemplateResponse(
        "navbooks.html",
        {
            "request": request,
            "user": current_user.email,
            "total": 0,
            "done_count": 0,
            "tasks": []
        }
    )


@app.post("/token/refresh")
def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    token_hash = hash_refresh_token(request.refresh_token)
    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )
    if not stored or stored.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Refresh token revoked")

    revoke_refresh_token(db, request.refresh_token)
    new_access = create_access_token({"id": user_id})
    new_refresh = create_refresh_token({"id": user_id})
    new_payload = jwt.decode(new_refresh, SECRET_KEY, algorithms=[ALGORITHM])
    new_expires_at = datetime.fromtimestamp(new_payload["exp"], tz=timezone.utc)
    store_refresh_token(db, user_id, new_refresh, new_expires_at)

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer"
    }


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# ------------------ ME ------------------
@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "permissions": current_user.permissions
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


# ------------------ ADMIN EXAMPLE ------------------
@app.get("/admin")
def admin_only(current_user: User = Depends(check_permission("admin.panel"))):
    return {"message": "Admin access granted"}


# ------------------ TASKS ------------------
@app.post("/tasks", response_model=TaskOut)
def create_task(
    task: TaskIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("task.create"))
):
    new_task = Task(
        title=task.title,
        description=task.description,
        due_date=task.due_date,
        owner_id=current_user.id
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task


@app.get("/tasks", response_model=list[TaskOut])
def get_tasks(
    is_done: Optional[bool] = None,
    due_before: Optional[datetime] = None,
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("task.read"))
):
    query = db.query(Task).filter(Task.owner_id == current_user.id)
    if is_done is not None:
        query = query.filter(Task.is_done == is_done)
    if due_before is not None:
        query = query.filter(Task.due_date <= due_before)

    tasks = query.order_by(Task.created_at.desc()).offset(offset).limit(limit).all()
    return tasks


@app.patch("/tasks/{task_id}", response_model=TaskOut)
def update_task(
    task_id: int,
    task_data: TaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("task.update"))
):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your task")
    for field, value in task_data.dict(exclude_unset=True).items():
        setattr(task, field, value)
    db.commit()
    db.refresh(task)
    return task


@app.delete("/tasks/{task_id}")
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("task.delete"))
):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your task")
    db.delete(task)
    db.commit()
    return {"status": "deleted"}


@app.get("/tasks/{task_id}", response_model=TaskOut)
def get_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("task.read"))
):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your task")
    return task