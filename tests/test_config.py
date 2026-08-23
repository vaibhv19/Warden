import pytest
from pydantic import ValidationError

from warden.config import Settings, get_settings


def test_default_config_loading() -> None:
    """Verify settings can load with standard defaults."""
    settings = Settings()
    assert settings.warden_env == "dev"
    assert settings.timeout_seconds == 30
    assert str(settings.zap_base_url) == "http://localhost:8080"


def test_env_validation() -> None:
    """Verify validation constraints on configuration values."""
    with pytest.raises(ValidationError) as excinfo:
        Settings(WARDEN_ENV="invalid_env")
    assert "WARDEN_ENV must be one of" in str(excinfo.value)

    with pytest.raises(ValidationError) as excinfo:
        Settings(TIMEOUT_SECONDS=-5)
    assert "TIMEOUT_SECONDS must be a positive integer" in str(excinfo.value)


def test_get_settings_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify get_settings correctly grabs environment variables."""
    monkeypatch.setenv("WARDEN_ENV", "prod")
    monkeypatch.setenv("TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("ZAP_BASE_URL", "http://zap.local:9090")

    settings = get_settings()
    assert settings.warden_env == "prod"
    assert settings.timeout_seconds == 45
    assert str(settings.zap_base_url) == "http://zap.local:9090/"
