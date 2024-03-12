
from unittest.mock import Mock, patch, AsyncMock

import pytest # type: ignore
from sqlalchemy import select

from src.database.models import User
from tests.conftest import TestingSessionLocal


user_data = {"username": "john", "mail": "eva@i.ua", "password": "123456789"}


def test_signup(client, monkeypatch):
    mock_send_email = Mock()
    monkeypatch.setattr("src.routes.auth.send_email", mock_send_email)
    response = client.post("api/auth/signup", json=user_data)
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["username"] == user_data["username"]
    assert data["mail"] == user_data["mail"]
    assert "password" not in data
    assert "avatar" in data
    assert mock_send_email.call_count == 1


def test_signup_exist_user(client, monkeypatch):
    mock_send_email = Mock()
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
    monkeypatch.setattr("src.routes.auth.send_email", mock_send_email)
    response = client.post("api/auth/signup", json=user_data)
    assert response.status_code == 409, response.text
    data = response.json()
    assert data["detail"] =="Account allready exist"


def test_login_not_confirmed(client, monkeypatch):
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
    response = client.post("api/auth/login",
                           data={"username": user_data.get("mail"), "password": user_data.get("password")})
    assert response.status_code == 401, response.text
    data = response.json()
    assert data["detail"] == "Email not confirmed"


@pytest.mark.asyncio
async def test_login(client, monkeypatch):
    async with TestingSessionLocal() as session:
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
        current_user = await session.execute(select(User).where(User.mail == user_data.get("mail")))
        current_user = current_user.scalar_one_or_none()
        if current_user:
            current_user.confirmed = True
            await session.commit()
    response = client.post("api/auth/login",
                           data={"username": user_data.get("mail"), 
                           "password": user_data.get("password")})
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "token_type" in data


def test_login_wrong_password(client, monkeypatch):
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
    response = client.post("api/auth/login",
                           data={"username": user_data.get("mail"), "password": "password"})
    assert response.status_code == 401, response.text
    data = response.json()
    assert data["detail"] == "Invalid pass"


def test_login_wrong_email(client, monkeypatch):
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
    response = client.post("api/auth/login",
                           data={"username": "mail", "password": user_data.get("password")})
    assert response.status_code == 401, response.text
    data = response.json()
    assert data["detail"] == "Invalid user"


def test_login_validation_error(client, monkeypatch):
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
    monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
    response = client.post("api/auth/login",
                           data={"password": user_data.get("password")})
    assert response.status_code == 422, response.text
    data = response.json()
    assert "detail" in data



