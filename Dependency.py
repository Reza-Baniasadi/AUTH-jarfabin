from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session
import os, time, uuid
import crud, models
from database import get_db
from auth import decode_access_token
import logging
from fastapi import APIRouter, Depends


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
        
        if required_roles and user.role not in required_roles:
            raise HTTPException(status_code=403, detail="Insufficient privileges")

        pid = str(uuid.uuid4())
        _active_pids[pid] = {
            "user_email": email,
            "start_time": time.time(),
            "endpoint": request.url.path
        }

        logger.info(f"PID {pid} - User {email} accessed {request.url.path}")

        def revoke():
            if pid in _active_pids:
                logger.warning(f"PID {pid} revoked for user {email}")
                _active_pids.pop(pid)

        return {"user": user, "pid": pid, "revoke": revoke}

    return dependency




router = APIRouter(prefix="/pid", tags=["pid-secure"])

@router.get("/data")
def secure_data(session=Depends(pid_secure(required_roles=["user","admin"]))):
    user = session["user"]
    pid = session["pid"]
    revoke = session["revoke"]


    return {"msg": f"Hello {user.email}, your session PID is {pid}"}
