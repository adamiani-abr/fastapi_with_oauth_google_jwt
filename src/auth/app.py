import logging
import os
from typing import Any

import logging_config
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import ExpiredSignatureError, PyJWTError
from jwt_token_manager import JWTTokenManager
from pydantic import BaseModel
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
except KeyError as e:
    logger.critical(f"Missing required environment variable: {e}")
    raise
except ValueError as e:
    logger.critical(f"Invalid environment variable value: {e}")
    raise

app = FastAPI()
jwt_token_manager = JWTTokenManager()

# *********************************************************** #
# security scheme for extracting Bearer tokens
# HTTPBearer -
#   - validates request’s Authorization header - ensures it starts with Bearer
#   - strips “Bearer ” prefix and returns HTTPAuthorizationCredentials object with .credentials = "<the-token-string>"
#   - if no header or malformed - raises 401
bearer_scheme = HTTPBearer()
# *********************************************************** #


class TokenPair(BaseModel):
    """
    Response model containing a freshly issued access token and its corresponding refresh token.

    Attributes:
        access_token (str): A JWT access token which clients use to authenticate subsequent requests.
        refresh_token (str): An opaque token stored server-side (in Redis) used to obtain new access tokens.
        token_type (str): The type of the token, typically "bearer".
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """
    Request model for exchanging a valid refresh token for a new token pair.

    Attributes:
        refresh_token (str): The refresh token presented by the client for verification and rotation.
    """

    refresh_token: str


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict[str, Any]:
    token = creds.credentials
    try:
        claims = jwt_token_manager.decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return {"email": claims["sub"], "name": claims.get("name")}


@app.get("/login/google")
async def login_google() -> dict[str, str]:
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
    """
    Google OAuth callback endpoint:
     1) Exchange code → Google tokens
     2) Fetch userinfo
     3) Issue our access & refresh tokens
     4) Redirect to frontend with tokens
    """
    # * 1) Exchange code → Google tokens
    google_tokens = _exchange_code_for_google_tokens(code)
    provider_token = google_tokens.get("access_token")
    if not provider_token:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "No access token from provider")

    # * 2) Fetch userinfo
    user_info = _fetch_google_user_info(provider_token)
    user_email = user_info.get("email", "")
    user_name = user_info.get("name", "")
    if not user_email:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "No email in user info")

    # * 3) Issue our access & refresh tokens
    access_token, refresh_token = _issue_tokens(user_email, user_name)

    # * 4) Redirect to frontend with tokens
    redirect_url = _build_redirect_url(access_token, refresh_token)
    return RedirectResponse(redirect_url)


@app.post("/token/refresh", response_model=TokenPair)
async def refresh_token(req: RefreshRequest) -> TokenPair:
    """
    Endpoint to refresh the access token using a valid refresh token.
    The refresh token is verified and a new access token is issued.
    """
    try:
        user_id = jwt_token_manager.verify_refresh_token(req.refresh_token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    new_access = jwt_token_manager.create_access_token(subject=user_id)
    new_refresh = jwt_token_manager.create_refresh_token(user_id)
    return TokenPair(access_token=new_access, refresh_token=new_refresh)


@app.post("/verify")
async def verify(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """
    Verifies a JWT access token (via Depends) and returns user info.
    """
    return {"user": current_user}


@app.post("/logout")
async def logout(
    req: RefreshRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, str]:
    """
    Log out the authenticated user by revoking their refresh token.

    This endpoint requires:
      - A valid JWT access token in the Authorization header (via get_current_user)
      - A JSON body with the `refresh_token` to revoke

    On success, deletes that refresh token from Redis so it can no longer be used
    """
    try:
        # * attempt to revoke refresh token - ignore if already gone
        jwt_token_manager.verify_refresh_token(req.refresh_token)
    except ValueError:
        # * token invalid or already expired/revoked
        pass

    return {"message": "Logged out"}


def _exchange_code_for_google_tokens(code: str) -> dict[str, Any]:
    """
    Exchange OAuth2 authorization code for Google tokens.
    Raises HTTPException on network or response errors.
    """
    data: dict[str, str] = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    try:
        resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=data, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Timeout:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "Token endpoint timed out")
    except RequestException as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Token endpoint error: {e}")
    except ValueError:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Invalid JSON from token endpoint")


def _fetch_google_user_info(provider_token: str) -> dict[str, Any]:
    """
    Fetch user profile from Google UserInfo endpoint.
    Raises HTTPException on network or response errors.
    """
    headers = {"Authorization": f"Bearer {provider_token}"}
    try:
        resp = requests.get(GOOGLE_OAUTH_USERINFO_URL, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Timeout:
        raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "Userinfo endpoint timed out")
    except RequestException as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Userinfo error: {e}")
    except ValueError:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Invalid JSON from userinfo endpoint")


def _issue_tokens(user_email: str, user_name: str, authorizer: str = "google") -> tuple[str, str]:
    """
    Generate our own JWT access token and opaque refresh token.
    """
    access = jwt_token_manager.create_access_token(subject=user_email, extra={"name": user_name, "authorizer": authorizer})
    refresh = jwt_token_manager.create_refresh_token(user_email)
    return access, refresh


def _build_redirect_url(access_token: str, refresh_token: str) -> str:
    """
    Build the frontend redirect URL carrying both tokens as query params.
    """
    return f"{WEB_FRONTEND_URL}/google-login?access_token={access_token}&refresh_token={refresh_token}"
