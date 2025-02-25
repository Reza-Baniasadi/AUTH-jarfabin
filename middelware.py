from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import crud, schemas, models
from database import engine, Base, get_db
from auth import create_access_token, verify_password, hash_password, decode_access_token
from config import settings
from utils import logger, is_rate_limited
import httpx


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Crypto API")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

origins = ["https://yourfrontend.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def secure_headers(request: Request, call_next):
    ip = request.client.host
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response