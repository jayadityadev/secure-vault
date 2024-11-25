from fastapi import APIRouter, HTTPException, Depends
from app.database.db import db
from app.models.user import User
from app.models.user import hash_password, verify_password

router = APIRouter()

@router.post("/signup")
async def signup(user: User):
    if await db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists.")
    
    hashed_password = hash_password(user.password)
    await db.users.insert_one({"username": user.username, "password": hashed_password})
    return {"message": "Signup successful!"}

@router.post("/login")
async def login(user: User):
    stored_user = await db.users.find_one({"username": user.username})
    if not stored_user or not verify_password(user.password, stored_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return {"message": "Login successful!"}
