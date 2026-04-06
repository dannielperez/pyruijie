"""Shared test fixtures."""

import pytest
import respx

from pyruijie import RuijieClient

BASE_URL = "https://cloud-us.ruijienetworks.com"


@pytest.fixture()
def mock_api():
    """respx mock router scoped to the Ruijie base URL."""
    with respx.mock(base_url=BASE_URL) as router:
        yield router


def _stub_auth(router: respx.MockRouter) -> None:
    """Add a successful auth response to a respx router."""
    router.post("/service/api/oauth20/client/access_token").respond(
        json={"code": 0, "accessToken": "test-token-abc123"}
    )


@pytest.fixture()
def authed_client(mock_api):
    """Return a RuijieClient that is already authenticated against mocks."""
    _stub_auth(mock_api)
    client = RuijieClient(app_id="test-app", app_secret="test-secret")
    client.authenticate()
    return client, mock_api
