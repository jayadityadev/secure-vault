from pydantic import BaseModel
from bcrypt import hashpw, gensalt, checkpw

class User(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    return hashpw(password.encode(), gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return checkpw(password.encode(), hashed.encode())
