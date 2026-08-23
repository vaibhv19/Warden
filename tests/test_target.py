import pytest
from pydantic import ValidationError

from warden.models.target import TargetAuthContext, TargetConfig


def test_target_authorization_enforced() -> None:
    """Verify target model raises validation error if unauthorized."""
    with pytest.raises(ValidationError) as excinfo:
        TargetConfig(
            id="target-1",
            name="Test Target",
            base_url="http://test.local",
            is_authorized=False,
        )
    assert "Target is not authorized" in str(excinfo.value)


def test_valid_target_creation() -> None:
    """Verify TargetConfig is successfully created when authorized."""
    auth = TargetAuthContext(
        auth_type="basic",
        credentials={"username": "testuser", "password": "password123"},
    )
    target = TargetConfig(
        id="target-2",
        name="Authorized Target",
        base_url="http://auth.local",
        is_authorized=True,
        auth_context=auth,
        scan_metadata={"depth": "shallow"},
    )
    assert target.id == "target-2"
    assert target.name == "Authorized Target"
    assert str(target.base_url) == "http://auth.local/"
    assert target.is_authorized is True
    assert target.auth_context is not None
    assert target.auth_context.auth_type == "basic"
    assert target.auth_context.credentials["username"] == "testuser"
    assert target.scan_metadata["depth"] == "shallow"


def test_invalid_url_target() -> None:
    """Verify TargetConfig validates url structure."""
    with pytest.raises(ValidationError):
        TargetConfig(
            id="target-3",
            name="Invalid URL",
            base_url="not-a-valid-url",
            is_authorized=True,
        )
