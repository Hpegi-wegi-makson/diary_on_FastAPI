SECRET_KEY = "dowqdoj1209r21u0r23jfp3;2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

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