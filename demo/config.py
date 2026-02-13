import os

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-env")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

ROLE_PERMISSIONS = {
    "user": [
        "task.read",
        "task.create",
        "task.update",
        "task.delete"
    ],
    "moderator": [
        "comment.delete"
    ],
    "admin": ["*"]
}
