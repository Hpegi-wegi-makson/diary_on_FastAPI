from fastapi import Depends, HTTPException
from jwt_manager import get_current_user
from database import User
from config import ROLE_PERMISSIONS


def init_permissions_by_role(role: str) -> str:
    perms = ROLE_PERMISSIONS.get(role)
    if not perms:
        return ""
    return ",".join(perms)


def check_permission(required_permission: str):
    def checker(current_user: User = Depends(get_current_user)):
        if not current_user.permissions:
            raise HTTPException(status_code=403, detail="Permissions not set")

        user_permissions = current_user.permissions.split(",")
        if "*" in user_permissions:
            return current_user
        if required_permission not in user_permissions:
            raise HTTPException(status_code=403, detail="Permission denied")
        return current_user

    return checker