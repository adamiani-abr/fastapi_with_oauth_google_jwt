import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
import logging_config
import redis
from dotenv import load_dotenv
from redis import Redis

logging_config.setup_logging(os.getenv("LOG_LEVEL", "WARNING"))
logger = logging.getLogger(__name__)

load_dotenv()


class JWTTokenManager:
    """Class for managing JWT tokens and Redis storage."""

    def __init__(self) -> None:
        self.__redis_storage: Redis = self.__connect_to_redis()
        self.__load_jwt_environment_variables()

    def __connect_to_redis(self) -> redis.Redis:
        """Connect to Redis using environment variables."""
        try:
            REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
            REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
            REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
            REDIS_SSL: bool = os.getenv("REDIS_SSL", "false").lower() == "true"
        except KeyError as e:
            logger.critical(f"Missing required environment variable: {e}")
            raise
        except ValueError as e:
            logger.critical(f"Invalid integer in environment: {e}")
            raise

        try:
            return redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                ssl=REDIS_SSL,
                decode_responses=True,  # decode responses to strings
            )
        except redis.RedisError as e:
            logger.critical(f"Redis connection failed: {e}")
            raise
        except Exception as e:
            logger.critical(f"Redis connection failed (unknown exception): {e}")
            raise

    def __load_jwt_environment_variables(self) -> None:
        """Load JWT-related environment variables."""
        try:
            self.__jwt_secret: str = os.getenv("JWT_SECRET_KEY", "")
            self.__jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
            self.__access_ttl_seconds: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_SECONDS", "900"))  # 15 minutes
            self.__refresh_ttl_seconds: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_SECONDS", "86400"))  # 1 day
        except KeyError as e:
            logger.critical(f"Missing required environment variable: {e}")
            raise
        except ValueError as e:
            logger.critical(f"Invalid integer in environment: {e}")
            raise

    def decode_access_token(self, token: str) -> dict[str, Any]:
        """
        Decode and verify a JWT access token, raising ExpiredSignatureError or PyJWTError
        on failure.
        """
        return jwt.decode(
            token,
            self.__jwt_secret,
            algorithms=[self.__jwt_algorithm],
        )

    def create_access_token(self, subject: str, extra: Dict[str, Any] | None = None) -> str:
        """Create a JWT access token with the given subject and optional extra claims."""
        now = datetime.now(timezone.utc)
        payload: Dict[str, Any] = {"sub": subject, "iat": now, "exp": now + timedelta(seconds=self.__access_ttl_seconds)}
        if extra:
            payload.update(extra)
        return jwt.encode(payload, self.__jwt_secret, algorithm=self.__jwt_algorithm)

    def create_refresh_token(self, user_id: str) -> str:
        """Create a one-time refresh token and store it in Redis."""
        token = secrets.token_urlsafe(32)

        # * store one-time refresh token in Redis
        self.__redis_storage.set(f"refresh:{token}", user_id, ex=self.__refresh_ttl_seconds)
        return token

    def verify_refresh_token(self, token: str) -> str:
        """Verify the refresh token and return the user ID."""
        key = f"refresh:{token}"
        user_id = self.__redis_storage.get(key)
        if not user_id:
            raise ValueError("Invalid or expired refresh token")
        self.__redis_storage.delete(key)  # enforce single-use
        return user_id

    def delete_refresh_token_from_redis(self, token: str) -> None:
        """Delete the refresh token from Redis storage."""
        key = f"refresh:{token}"
        self.__redis_storage.delete(key)
