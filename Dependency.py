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