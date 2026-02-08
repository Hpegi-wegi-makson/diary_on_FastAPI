from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from database import SessionLocal, create_user, get_user_by_email, verify_password, User, Task
from schemas import Registration, Login, TaskOut, TaskUpdate, TaskIn
from jwt_manager import create_access_token, create_refresh_token, get_current_user
from permissions import init_permissions_by_role, check_permission

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
def login(user: Login, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid password")

    access_token = create_access_token({"id": db_user.id})
    refresh_token = create_refresh_token({"id": db_user.id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# ------------------ ME ------------------
@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "permissions": current_user.permissions
    }


# ------------------ ADMIN EXAMPLE ------------------
@app.get("/admin")
def admin_only(current_user: User = Depends(check_permission("admin.panel"))):
    return {"message": "Admin access granted"}


# ------------------ TASKS ------------------
@app.post("/tasks", response_model=TaskOut)
def create_task(task: TaskIn, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
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