import importlib

import jwt as jwt_lib
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from pytest import MonkeyPatch
from requests.exceptions import RequestException, Timeout


@pytest.fixture(autouse=True)  # `autouse=True` -> all tests automatically use
def setup_env(monkeypatch: MonkeyPatch) -> None:
    """
    Configure environment variables for the auth service before import.

    Ensures GOOGLE and JWT settings are in place when the app module loads.
    """
    env_vars = {
        "GOOGLE_OAUTH_TOKEN_URL": "http://test/token",
        "GOOGLE_OAUTH_USERINFO_URL": "http://test/userinfo",
        "GOOGLE_OAUTH_CLIENT_ID": "cid",
        "GOOGLE_OAUTH_CLIENT_SECRET": "secret",
        "WEB_FRONTEND_URL": "http://frontend",
        "JWT_SECRET_KEY": "jwtsecret",
        "JWT_ALGORITHM": "HS256",
        "JWT_EXPIRE_SECONDS": "3600",
    }
    for key, val in env_vars.items():
        monkeypatch.setenv(key, val)


@pytest.fixture
def client() -> TestClient:
    """
    Import and configure the FastAPI app after env vars are set.

    Reloading the module ensures it picks up patched variables.
    """
    auth_module = importlib.import_module("src.auth.app")
    importlib.reload(auth_module)
    return TestClient(auth_module.app)


def test_auth_google_no_token(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """
    If the OAuth provider returns no access_token, expect 502.
    """

    class FakeTokenResp:
        """Simulate a token response with no access_token."""

        def raise_for_status(self) -> None:
            """Simulate a successful response."""

        def json(self) -> dict:
            """Simulate a response with no access_token."""
            return {}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: FakeTokenResp())
    resp = client.get("/auth/google?code=none")
    assert resp.status_code == status.HTTP_502_BAD_GATEWAY


def test_auth_google_userinfo_errors(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """
    Errors fetching userinfo map to the correct HTTP codes.
    """

    class FakeTokenResp:
        """Simulate a token response with no access_token."""

        def raise_for_status(self) -> None:
            """Simulate a successful response."""

        def json(self) -> dict:
            """Simulate a response with an access_token."""
            return {"access_token": "tok"}

    monkeypatch.setattr("requests.post", lambda *args, **kwargs: FakeTokenResp())
    for exc, code in [
        (Timeout(), status.HTTP_504_GATEWAY_TIMEOUT),
        (RequestException("err"), status.HTTP_502_BAD_GATEWAY),
    ]:
        monkeypatch.setattr("requests.get", lambda *args, **kwargs: (_ for _ in ()).throw(exc))
        resp = client.get("/auth/google?code=abc")
        assert resp.status_code == code


def test_verify_missing_header(client: TestClient) -> None:
    """
    No Authorization header => HTTP 403 Forbidden via HTTPBearer.
    """
    resp = client.post("/verify")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["detail"] == "Not authenticated"


def test_verify_expired_token(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """
    ExpiredSignatureError from jwt.decode => HTTP 401 Token has expired.
    """
    from jwt import ExpiredSignatureError

    monkeypatch.setattr(jwt_lib, "decode", lambda *args, **kwargs: (_ for _ in ()).throw(ExpiredSignatureError()))
    resp = client.post("/verify", headers={"Authorization": "Bearer expired"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Token expired"


def test_verify_invalid_token(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """
    Any other PyJWTError => HTTP 401 Invalid token.
    """
    from jwt import PyJWTError

    monkeypatch.setattr(jwt_lib, "decode", lambda *args, **kwargs: (_ for _ in ()).throw(PyJWTError()))
    resp = client.post("/verify", headers={"Authorization": "Bearer invalid"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.json()["detail"] == "Invalid token"


def test_verify_success(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """
    A valid JWT => HTTP 200 OK and correct user info.
    """
    fake_claims = {"sub": "hello@world", "name": "Hello"}
    monkeypatch.setattr(jwt_lib, "decode", lambda token, key, algorithms: fake_claims)
    resp = client.post("/verify", headers={"Authorization": "Bearer goodtoken"})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"user": {"email": "hello@world", "name": "Hello"}}


def test_logout_requires_auth(client: TestClient) -> None:
    """
    POST /logout without token => HTTP 403 Forbidden.
    """
    resp = client.post("/logout")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["detail"] == "Not authenticated"
