from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session
import hashlib, hmac, time, json
from auth import decode_access_token
from database import get_db
import crud
from config import settings
import redis, logging


def super_secure_dependency(required_roles: list = [], endpoint_salt: str = "default"):

    async def dependency(request: Request, token: str, db: Session = Depends(get_db)):
        ip = request.client.host

        key = f"ratelimit:{ip}:{request.url.path}"
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, 30)  
        if count > 5:
            logger.warning(f"Behavioral rate limit triggered: {ip} on {request.url.path}")
            raise HTTPException(status_code=429, detail="Too many requests on this endpoint")

        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        email = payload.get("sub")
        user = crud.get_user_by_email(db, email=email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if required_roles and user.role not in required_roles:
            raise HTTPException(status_code=403, detail="Insufficient privileges")

        signature = request.headers.get("X-SIGNATURE")
        body_bytes = await request.body()
        secret_key = f"{user.id}-{endpoint_salt}"
        expected_sig = hmac.new(secret_key.encode(), body_bytes, hashlib.sha256).hexdigest()
        if signature != expected_sig:
            logger.warning(f"Invalid request signature: {ip} user {email}")
            raise HTTPException(status_code=401, detail="Invalid request signature")

        if "/admin/" in request.url.path and user.role != "admin":
            logger.warning(f"Honeypot triggered: {ip} attempted admin path")
            raise HTTPException(status_code=403, detail="Forbidden path detected")

        logger.info(f"{ip} - {email} accessed {request.url.path} successfully")

        return user
    return dependency