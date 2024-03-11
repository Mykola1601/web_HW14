
from unittest.mock import Mock, patch, AsyncMock

import pytest # type: ignore
from sqlalchemy import select

from src.database.models import User
from tests.conftest import TestingSessionLocal
# from src.conf import messages


user_data = {"username": "eva", "mail": "eva@i.ua", "password": "123456789"}


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



# def test_not_confirmed_login(client):
#     response = client.post("api/auth/login",
#                            data={"username": user_data.get("email"), "password": user_data.get("password")})
#     assert response.status_code == 401, response.text
#     data = response.json()
#     assert data["detail"] == "Email not confirmed"






