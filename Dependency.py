from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session
import os, time, uuid
import crud, models
from database import get_db
from auth import decode_access_token
import logging

logger = logging.getLogger("pid_secure")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

_active_pids = {}


def pid_secure(required_roles: list = []):
    async def dependency(request: Request, token: str, db: Session = Depends(get_db)):
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        email = payload.get("sub")
        user = crud.get_user_by_email(db, email=email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")