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