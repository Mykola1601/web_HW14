
import pytest

from unittest.mock import Mock, patch, AsyncMock

from src.services.auth import auth_service


# def test_get_contacts(client, get_token, monkeypatch):
#     with patch.object(auth_service, 'cache') as redis_mock:
#         redis_mock.get.return_value = None
#         monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
#         monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
#         monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
#         token = get_token
#         headers = {"Authorization": f"Bearer {token}"}
#         response = client.get("api/contacts", headers=headers)
#         assert response.status_code == 200, response.text
#         data = response.json()
#         assert len(data) == 0
