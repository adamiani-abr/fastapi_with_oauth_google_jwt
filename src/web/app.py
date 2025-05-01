import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, Optional

import logging_config  # pylint: disable=import-error
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
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

# * JWT cookie settings
JWT_COOKIE_NAME: str = os.getenv("JWT_COOKIE_NAME", "access_token")
JWT_EXPIRE_SECONDS: int = int(os.getenv("JWT_EXPIRE_SECONDS", os.getenv("SESSION_EXPIRE_TIME_SECONDS", "3600")))


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


def login_required(f: Callable) -> Callable:
    """Decorator: ensure user has valid JWT and set g.current_user."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> WerkzeugResponse:
        token = request.cookies.get(JWT_COOKIE_NAME)
        if not token:
            return redirect(url_for("login"))
        user = verify_token(token)
        if not user:
            return redirect(url_for("login"))
        g.current_user = user
        return f(*args, **kwargs)

    return wrapper


def check_already_logged_in(f: Callable) -> Callable:
    """Decorator: if JWT present and valid, redirect to dashboard."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> WerkzeugResponse:
        token = request.cookies.get(JWT_COOKIE_NAME)
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
    token = request.cookies.get(JWT_COOKIE_NAME)
    user = verify_token(token) if token else None
    if user:
        g.current_user = user
    return render_template("index.html", user=user)


@app.route("/google-login")
def google_login() -> WerkzeugResponse | tuple[str, int]:
    """Callback after Google OAuth: set JWT cookie and redirect."""
    token = request.args.get("token")
    if not token:
        return "Missing token", 400
    response = redirect(url_for("dashboard"))
    response.set_cookie(
        JWT_COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        domain=request.host,
        path="/",
        max_age=JWT_EXPIRE_SECONDS,
    )
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
    """Clears JWT cookie and notifies auth service (optional)."""
    token = request.cookies.get(JWT_COOKIE_NAME)
    if token:
        try:
            resp = requests.post(
                f"{AUTH_SERVICE_URL}/logout",
                headers={"Authorization": f"Bearer {token}"},
                timeout=3,
            )
            resp.raise_for_status()  # automatically raises on 4xx/5xx
            logger.info("Notified auth service of logout.")
        except Exception as e:
            logger.warning(f"Logout notification failed: {e}")
    response = redirect(url_for("index"))
    response.delete_cookie(JWT_COOKIE_NAME, path="/")
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT_FLASK", "5000")))
