import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, Optional

import logging_config
import requests
from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

# * configure logging
logging_config.setup_logging(os.getenv("LOG_LEVEL", "WARNING"))
logger = logging.getLogger(__name__)

# * load environment variables
load_dotenv()

# * Configuration variables
AUTH_SERVICE_URL: str = os.environ["AUTH_SERVICE_URL"]
COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
JWT_ACCESS_TOKEN_COOKIE_NAME: str = os.getenv("JWT_ACCESS_TOKEN_COOKIE_NAME", "access_token")
JWT_REFRESH_TOKEN_COOKIE_NAME: str = os.getenv("JWT_REFRESH_TOKEN_COOKIE_NAME", "refresh_token")

# * make sure matches auth service config values for token TTLs (refer to README.md for possible issues if different)
JWT_ACCESS_TOKEN_EXPIRE_SECONDS: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_SECONDS", "900"))  # 15 minutes
JWT_REFRESH_TOKEN_EXPIRE_SECONDS: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_SECONDS", "86400"))  # 1 day

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]


# ****************************************************** #
# * Helper functions for token and cookie handling *
def _get_cookie(name: str) -> str | None:
    """Retrieve a cookie value or None."""
    return request.cookies.get(name)


def _verify_access_token() -> dict[str, Any] | None:
    """Validate the JWT access token via the auth service."""
    token = _get_cookie(JWT_ACCESS_TOKEN_COOKIE_NAME)
    if not token:
        return None
    return verify_token(token)


def _refresh_tokens() -> tuple[str, str] | None:
    """Attempt to rotate tokens using the refresh token endpoint."""
    refresh = _get_cookie(JWT_REFRESH_TOKEN_COOKIE_NAME)
    if not refresh:
        return None
    try:
        resp = requests.post(
            f"{AUTH_SERVICE_URL}/token/refresh",
            json={"refresh_token": refresh},
            timeout=3,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["access_token"], data["refresh_token"]
    except Exception as e:
        logger.warning(f"Refresh token failed: {e}")
        return None


def _set_auth_cookies(
    response: WerkzeugResponse,
    access_token: str,
    refresh_token: str,
) -> None:
    """Set HTTP-only cookies for both access and refresh tokens."""
    response.set_cookie(
        JWT_ACCESS_TOKEN_COOKIE_NAME,
        access_token,
        httponly=True,
        # secure=COOKIE_SECURE,
        # domain=request.host,
        path="/",
        max_age=JWT_ACCESS_TOKEN_EXPIRE_SECONDS,
    )
    response.set_cookie(
        JWT_REFRESH_TOKEN_COOKIE_NAME,
        refresh_token,
        httponly=True,
        # secure=COOKIE_SECURE,
        # domain=request.host,
        path="/",
        max_age=JWT_REFRESH_TOKEN_EXPIRE_SECONDS,
    )


def _clear_auth_cookies(response: WerkzeugResponse) -> None:
    """Remove authentication cookies on logout."""
    response.delete_cookie(JWT_ACCESS_TOKEN_COOKIE_NAME, path="/")
    response.delete_cookie(JWT_REFRESH_TOKEN_COOKIE_NAME, path="/")


# ****************************************************** #


def verify_token(token: str, timeout: int = 3) -> Optional[Dict[str, Any]]:
    """
    Call auth_service /verify with Bearer JWT header.
    Returns user dict on success, or None on any error.
    """
    try:
        resp = requests.post(
            f"{AUTH_SERVICE_URL}/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        resp.raise_for_status()  # automatically raises on 4xx/5xx
        body = resp.json()
        return body.get("user")
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else "unknown"
        logger.warning(f"Auth /verify HTTP {status}: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Auth /verify network error: {e}")
    except (ValueError, TypeError) as e:
        logger.error(f"Auth /verify JSON error: {e}")
    except Exception as e:
        logger.error(f"Auth /verify unexpected error: {e}")
    return None


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to enforce authentication on Flask view functions.

    This decorator will:
      1. Attempt to validate the JWT access token stored in a cookie.
      2. If the access token is missing or invalid, attempt to refresh it
         using the refresh token cookie by calling the auth service.
      3. On successful refresh, set new access and refresh token cookies
         and retry the original request.
      4. If both tokens fail, redirect the user to the login page.

    Args:
        f: The Flask view function to wrap.

    Returns:
        The wrapped view function that enforces login.
    """

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> WerkzeugResponse:
        """
        Wrapper that handles token validation, refresh logic, and redirection.

        Steps:
          1. Try the access token:
             - Read from JWT_ACCESS_TOKEN_COOKIE_NAME.
             - If valid, attach user info to `g.current_user` and call the view.
          2. Try the refresh token on failure:
             - Read from JWT_REFRESH_TOKEN_COOKIE_NAME.
             - POST to AUTH_SERVICE_URL/token/refresh.
             - If successful, set new cookies and redirect back to the same path.
          3. On any failure, redirect to the login page.

        Returns:
            A Flask Response object, either from the original view,
            a token-refresh redirect, or a login redirect.
        """
        # * 1) Try the access token
        user = _verify_access_token()
        if user:
            g.current_user = user
            return f(*args, **kwargs)

        # * 2) Try refresh token
        refreshed = _refresh_tokens()
        if refreshed:
            access_token, refresh_token = refreshed
            response = redirect(request.path)
            _set_auth_cookies(response, access_token, refresh_token)

            # * verify new access token before proceeding
            user = verify_token(access_token)
            if user:
                g.current_user = user
                return response

        # * 3) Redirect to login on failure
        return redirect(url_for("login"))

    return wrapper


def check_already_logged_in(f: Callable) -> Callable:
    """Decorator: if JWT present and valid, redirect to dashboard."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> WerkzeugResponse:
        token = request.cookies.get(JWT_ACCESS_TOKEN_COOKIE_NAME)
        if token and verify_token(token):
            logger.info("User already authenticated, redirecting to dashboard.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return wrapper


@app.route("/login")
@check_already_logged_in
def login() -> Any:
    """Render login page with Google OAuth link."""
    try:
        resp = requests.get(f"{AUTH_SERVICE_URL}/login/google", timeout=3)
        resp.raise_for_status()  # automatically raises on 4xx/5xx
        auth_url = resp.json().get("auth_url")
        if not auth_url:
            logger.error("Auth service returned empty auth_url field")
            return "Auth service error", 502
        return render_template("login.html", google_oauth_url=auth_url)
    except requests.exceptions.Timeout:
        logger.warning("Timeout fetching OAuth URL from auth service")
        return "Auth service timeout", 504
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else 502
        logger.error(f"Auth service HTTP error {status}: {e}")
        return f"Auth service error ({status})", status
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error contacting auth service: {e}")
        return "Auth service unavailable", 503
    except ValueError as e:
        logger.error(f"Invalid response from auth service: {e}")
        return "Auth service error", 502


@app.route("/")
@check_already_logged_in
def index() -> Any:
    """Homepage: show index.html, passing user if authenticated."""
    token = request.cookies.get(JWT_ACCESS_TOKEN_COOKIE_NAME)
    user = verify_token(token) if token else None
    if user:
        g.current_user = user
    return render_template("index.html", user=user)


@app.route("/google-login")
def google_login() -> WerkzeugResponse | tuple[str, int]:
    access_token = request.args.get("access_token")
    refresh_token = request.args.get("refresh_token")

    if not access_token or not refresh_token:
        return "Missing tokens", 400

    response = redirect(url_for("dashboard"))
    _set_auth_cookies(response, access_token, refresh_token)
    return response


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard() -> Any:
    """Protected dashboard view."""
    user = g.current_user
    return (
        f"<h1>Dashboard — {user['name']}</h1>"
        '<form action="/logout" method="post"><button>Logout</button></form>'
        '<form action="/settings" method="post"><button>Settings</button></form>'
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings() -> Any:
    """Protected settings view."""
    user = g.current_user
    return (
        f"<h1>Settings — {user['name']}</h1>"
        '<form action="/logout" method="post"><button>Logout</button></form>'
        '<form action="/dashboard" method="post"><button>Dashboard</button></form>'
    )


@app.route("/logout", methods=["GET", "POST"])
def logout() -> WerkzeugResponse:
    """Clears JWT cookies and notifies auth service (optional)."""
    access_token = request.cookies.get(JWT_ACCESS_TOKEN_COOKIE_NAME)
    if access_token:
        try:
            resp = requests.post(
                f"{AUTH_SERVICE_URL}/logout",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=3,
            )
            resp.raise_for_status()  # automatically raises on 4xx/5xx
            logger.info("Notified auth service of logout.")
        except Exception as e:
            logger.warning(f"Logout notification failed: {e}")
    response = redirect(url_for("index"))
    _clear_auth_cookies(response)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT_FLASK", "5000")))
