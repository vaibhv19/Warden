from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from warden.models.target import TargetConfig
from warden.target_validator import (
    TargetValidationError,
    check_target_reachability,
    validate_target_config,
)


def test_validate_target_config_authorized() -> None:
    """Verify validate_target_config succeeds with authorized target."""
    target = TargetConfig(
        id="t1", name="Authorized", base_url="http://localhost", is_authorized=True
    )
    # Should not raise exception
    validate_target_config(target)


def test_validate_target_config_unauthorized() -> None:
    """Verify validate_target_config raises TargetValidationError if unauthorized."""
    mock_target = MagicMock(spec=TargetConfig)
    mock_target.is_authorized = False
    mock_target.base_url = "http://localhost"

    with pytest.raises(TargetValidationError) as excinfo:
        validate_target_config(mock_target)
    assert "Target is not authorized" in str(excinfo.value)


@patch("urllib.request.urlopen")
def test_check_target_reachability_success(mock_urlopen: MagicMock) -> None:
    """Verify check_target_reachability succeeds when target returns 200 OK."""
    target = TargetConfig(
        id="t2", name="OK", base_url="http://localhost", is_authorized=True
    )
    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Should not raise exception
    check_target_reachability(target)


@patch("urllib.request.urlopen")
def test_check_target_reachability_http_error_500(mock_urlopen: MagicMock) -> None:
    """Verify check_target_reachability raises TargetValidationError on 500 error."""
    target = TargetConfig(
        id="t3", name="Error", base_url="http://localhost", is_authorized=True
    )
    mock_urlopen.side_effect = HTTPError(
        url="http://localhost", code=500, msg="Server Error", hdrs=None, fp=None
    )

    with pytest.raises(TargetValidationError) as excinfo:
        check_target_reachability(target)
    assert "Target health check failed with status: 500" in str(excinfo.value)


@patch("urllib.request.urlopen")
def test_check_target_reachability_http_error_401(mock_urlopen: MagicMock) -> None:
    """Verify check_target_reachability succeeds on 401 Unauthorized (reachable)."""
    target = TargetConfig(
        id="t4", name="AuthReq", base_url="http://localhost", is_authorized=True
    )
    mock_urlopen.side_effect = HTTPError(
        url="http://localhost", code=401, msg="Unauthorized", hdrs=None, fp=None
    )

    # Should not raise error since 401 means target is reachable
    check_target_reachability(target)


@patch("urllib.request.urlopen")
def test_check_target_reachability_url_error(mock_urlopen: MagicMock) -> None:
    """Verify check_target_reachability raises TargetValidationError on URLError."""
    target = TargetConfig(
        id="t5", name="Unreachable", base_url="http://localhost", is_authorized=True
    )
    mock_urlopen.side_effect = URLError("DNS Failure")

    with pytest.raises(TargetValidationError) as excinfo:
        check_target_reachability(target)
    assert "Target is unreachable: DNS Failure" in str(excinfo.value)
