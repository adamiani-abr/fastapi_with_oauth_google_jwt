import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
import logging_config  # pylint: disable=import-error
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from requests.exceptions import RequestException, Timeout

# * configure logging
logging_config.setup_logging(os.getenv("LOG_LEVEL", "WARNING"))
logger = logging.getLogger(__name__)

# * load environment variables
load_dotenv()

try:
    # OAuth2/OpenID settings
    GOOGLE_OAUTH_TOKEN_URL: str = os.environ["GOOGLE_OAUTH_TOKEN_URL"]
    GOOGLE_OAUTH_USERINFO_URL: str = os.environ["GOOGLE_OAUTH_USERINFO_URL"]
    GOOGLE_CLIENT_ID: str = os.environ["GOOGLE_OAUTH_CLIENT_ID"]
    GOOGLE_CLIENT_SECRET: str = os.environ["GOOGLE_OAUTH_CLIENT_SECRET"]
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google")
    WEB_FRONTEND_URL: str = os.environ["WEB_FRONTEND_URL"]

    # JWT settings
    JWT_SECRET_KEY: str = os.environ["JWT_SECRET_KEY"]
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_SECONDS: int = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))
except KeyError as e:
    logger.critical(f"Missing required environment variable: {e}")
    raise
except ValueError as e:
    logger.critical(f"Invalid environment variable value: {e}")
    raise

app = FastAPI()

# *********************************************************** #
# security scheme for extracting Bearer tokens
# HTTPBearer -
#   - validates request’s Authorization header - ensures it starts with Bearer
#   - strips “Bearer ” prefix and returns HTTPAuthorizationCredentials object with .credentials = "<the-token-string>"
#   - if no header or malformed - raises 401
bearer_scheme = HTTPBearer()
# *********************************************************** #


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> Dict[str, Any]:
    """
    FastAPI dependency - bearer_scheme: verifies JWT exists, well-formed, and extracts token from header
    Raises 401 if invalid or expired.
    """
    token = creds.credentials  # extracted token from Authorization header using `bearer_scheme` dependency
    try:
        claims = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

    return {"email": claims.get("sub"), "name": claims.get("name")}


@app.get("/login/google")
async def login_google() -> Dict[str, str]:
    """Returns a Google OAuth login URL."""
    url = (
        "https://accounts.google.com/o/oauth2/auth"
        f"?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        f"&scope=openid%20profile%20email"
    )
    return {"auth_url": url}


@app.get("/auth/google")
async def auth_google(code: str) -> RedirectResponse:
    """Handles Google OAuth callback, issues a JWT, and redirects to the frontend with token."""
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    try:
        token_resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=token_data, timeout=5)
        token_resp.raise_for_status()
        token_response = token_resp.json()
    except Timeout:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "Token endpoint timed out")
    except RequestException as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Token endpoint error: {e}")
    except ValueError:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Invalid JSON from token endpoint")

    access_token = token_response.get("access_token")
    if not access_token:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "No access token from provider")

    try:
        user_resp = requests.get(
            GOOGLE_OAUTH_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5,
        )
        user_resp.raise_for_status()
        user_info = user_resp.json()
    except Timeout:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "Userinfo endpoint timed out")
    except RequestException as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Userinfo error: {e}")
    except ValueError:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Invalid JSON from userinfo endpoint")

    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_info.get("email"),
        "name": user_info.get("name"),
        "iat": now,
        "exp": now + timedelta(seconds=JWT_EXPIRE_SECONDS),
    }
    jwt_token: str = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    redirect_url = f"{WEB_FRONTEND_URL}/google-login?token={jwt_token}"
    return RedirectResponse(redirect_url)


@app.post("/verify")
async def verify(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Verifies a JWT access token (via Depends) and returns user info.
    """
    return {"user": current_user}


@app.post("/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, str]:
    """
    Logout client-side - no server-side state to clear.
    TODO: implement server-side logout (e.g., token revocation, blacklist) using Redis (AWS Elasticache)
    """
    return {"message": "Logged out"}
