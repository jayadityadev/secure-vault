from fastapi import FastAPI
from app.routers import auth, encryption

app = FastAPI()

# Include routers for modular functionality
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(encryption.router, prefix="/data", tags=["Encryption"])
