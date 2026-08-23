from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from warden.scanners.zap_client import ZapClient, ZapClientError


def test_zap_client_init() -> None:
    """Verify ZapClient initialization."""
    client = ZapClient("http://zap.local:8080/", "secret-key")
    assert client.base_url == "http://zap.local:8080"
    assert client.api_key == "secret-key"


@patch("urllib.request.urlopen")
def test_zap_client_connectivity_success(mock_urlopen: MagicMock) -> None:
    """Verify check_connectivity succeeds when ZAP returns version."""
    client = ZapClient("http://zap.local")
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"version": "2.14.0"}'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    assert client.check_connectivity() is True


@patch("urllib.request.urlopen")
def test_zap_client_connectivity_failure(mock_urlopen: MagicMock) -> None:
    """Verify check_connectivity returns False on error."""
    client = ZapClient("http://zap.local")
    mock_urlopen.side_effect = Exception("Connection Refused")

    assert client.check_connectivity() is False


@patch("urllib.request.urlopen")
def test_zap_client_start_spider(mock_urlopen: MagicMock) -> None:
    """Verify start_spider requests the correct endpoint and returns scan ID."""
    client = ZapClient("http://zap.local", "secret")
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"scan": "3"}'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    scan_id = client.start_spider("http://target.local")
    assert scan_id == "3"


@patch("urllib.request.urlopen")
def test_zap_client_api_error_handling(mock_urlopen: MagicMock) -> None:
    """Verify HTTP error messages from ZAP are correctly parsed."""
    client = ZapClient("http://zap.local")

    mock_fp = MagicMock()
    mock_fp.read.return_value = b'{"message": "ZAP API Specific Error Message"}'

    mock_urlopen.side_effect = HTTPError(
        url="http://zap.local", code=400, msg="Bad Request", hdrs=None, fp=mock_fp
    )

    with pytest.raises(ZapClientError) as excinfo:
        client.start_spider("http://target.local")
    assert "ZAP API error: ZAP API Specific Error Message" in str(excinfo.value)
