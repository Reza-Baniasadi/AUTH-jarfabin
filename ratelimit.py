import redis
from config import settings


redis_client = redis.StrictRedis.from_url(settings.REDIS_URL, decode_responses=True)

def is_rate_limited(ip: str, limit: int = 10, window: int = 60) -> bool:
    key = f"ratelimit:{ip}"
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, window)
    return count > limit