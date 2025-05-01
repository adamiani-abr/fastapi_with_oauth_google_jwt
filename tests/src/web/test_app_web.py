import importlib
import os
from typing import Generator

import pytest
import requests_mock
from flask import Flask
from flask.testing import FlaskClient
from pytest import MonkeyPatch


@pytest.fixture(autouse=True)  # `autouse=True` -> all tests automatically use
def setup_env(monkeypatch: MonkeyPatch) -> None:
    """
    Configure environment variables for the web front-end before import.
    This ensures JWT_COOKIE_NAME and other settings are applied.
    """
    env_vars = {
        "AUTH_SERVICE_URL": "http://auth:8000",
        "SECRET_KEY": "flask-secret",
        "JWT_COOKIE_NAME": "session_id",
        "SESSION_EXPIRE_TIME_SECONDS": "3600",
    }
    for key, val in env_vars.items():
        monkeypatch.setenv(key, val)


@pytest.fixture
def mock_api() -> Generator[requests_mock.Mocker, None, None]:
    """
    Fixture to provide a requests_mock Mocker for HTTP stubbing.
    """
    with requests_mock.Mocker() as m:
        yield m


@pytest.fixture
def app() -> Flask:
    """
    Import and configure the Flask application after environment variables are set.
    Reloading the module ensures patched env vars are used.
    """
    from src.web import app as web_app_module  # type: ignore

    importlib.reload(web_app_module)
    web_app_module.app.config["TESTING"] = True
    return web_app_module.app


@pytest.fixture
def client(app: Flask) -> Generator[FlaskClient, None, None]:
    """
    Create a Flask test client using the configured app fixture.
    """
    with app.test_client() as client_instance:
        yield client_instance


def test_login_renders_auth_url(mock_api: requests_mock.Mocker, client: FlaskClient) -> None:
    """
    When hitting /login, the front-end should fetch the OAuth URL and render it.
    """
    expected = "https://accounts.google.com/o/oauth2/auth?foo=bar"
    mock_api.get(
        f"{os.environ['AUTH_SERVICE_URL']}/login/google",
        json={"auth_url": expected},
        status_code=200,
    )

    response = client.get("/login")
    assert response.status_code == 200
    assert expected in response.get_data(as_text=True)


def test_index_not_logged_in_shows_login_link(client: FlaskClient) -> None:
    """
    A request to index without a valid session cookie should show the login link.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "login" in response.get_data(as_text=True).lower()


def test_index_logged_in_redirects_to_dashboard(
    mock_api: requests_mock.Mocker,
    client: FlaskClient,
) -> None:
    """
    With a valid session cookie and successful /verify, index should redirect to dashboard.
    """
    mock_api.post(
        f"{os.environ['AUTH_SERVICE_URL']}/verify",
        json={"user": {"email": "u@x", "name": "TestUser"}},
        status_code=200,
    )
    client.set_cookie("access_token", "dummy")

    response = client.get("/")
    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_google_login_sets_cookie_and_redirects(client: FlaskClient) -> None:
    """
    The /google-login callback should set the JWT cookie and redirect to dashboard.
    """
    response = client.get("/google-login?access_token=abc123&refresh_token=xyz456")
    assert response.status_code in (301, 302)
    assert "/dashboard" in response.headers["Location"]
    set_cookie = response.headers.get("Set-Cookie", "")
    assert "access_token=abc123" in set_cookie


def test_dashboard_redirects_when_not_authenticated(client: FlaskClient) -> None:
    """
    Accessing /dashboard without a session cookie should redirect to login.
    """
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_dashboard_success_when_authenticated(
    mock_api: requests_mock.Mocker,
    client: FlaskClient,
) -> None:
    """
    A valid session cookie and successful /verify should allow access to /dashboard.
    """
    mock_api.post(
        f"{os.environ['AUTH_SERVICE_URL']}/verify",
        json={"user": {"email": "u@x", "name": "Alice"}},
        status_code=200,
    )
    client.set_cookie("access_token", "s1")
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Alice" in response.get_data(as_text=True)


def test_settings_redirects_when_not_authenticated(client: FlaskClient) -> None:
    """
    Accessing /settings without authentication should redirect to login.
    """
    response = client.get("/settings")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_settings_success_when_authenticated(
    mock_api: requests_mock.Mocker,
    client: FlaskClient,
) -> None:
    """
    A valid session cookie and successful /verify should allow access to /settings.
    """
    mock_api.post(
        f"{os.environ['AUTH_SERVICE_URL']}/verify",
        json={"user": {"email": "u@x", "name": "Bob"}},
        status_code=200,
    )
    client.set_cookie("access_token", "s2")
    response = client.get("/settings")
    assert response.status_code == 200
    body = response.get_data(as_text=True).lower()
    assert "settings" in body and "bob" in body


def test_logout_clears_cookie_and_redirects(
    mock_api: requests_mock.Mocker,
    client: FlaskClient,
) -> None:
    """
    The /logout endpoint should clear the session cookie and redirect back to index.
    """
    mock_api.post(f"{os.environ['AUTH_SERVICE_URL']}/logout", status_code=200)
    client.set_cookie("access_token", "s3")

    response_get = client.get("/logout")
    assert response_get.status_code in (301, 302, 200)
    assert "access_token=;" in response_get.headers.get("Set-Cookie", "")

    response_post = client.post("/logout")
    assert response_post.status_code in (301, 302, 200)
    assert "access_token=;" in response_post.headers.get("Set-Cookie", "")
