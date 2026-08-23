import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field, HttpUrl, field_validator

# Load environment variables from .env if present
load_dotenv()


class Settings(BaseModel):
    """Configuration settings for Warden, loaded from the environment."""

    model_config = {
        "populate_by_name": True,
    }

    warden_env: str = Field(default="dev", alias="WARDEN_ENV")
    zap_base_url: HttpUrl = Field(default="http://localhost:8080", alias="ZAP_BASE_URL")
    zap_api_key: Optional[str] = Field(default=None, alias="ZAP_API_KEY")
    timeout_seconds: int = Field(default=30, alias="TIMEOUT_SECONDS")
    output_dir: Path = Field(default=Path("./reports"), alias="OUTPUT_DIR")

    @field_validator("warden_env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        v = v.lower()
        if v not in {"dev", "test", "prod"}:
            raise ValueError("WARDEN_ENV must be one of: dev, test, prod")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("TIMEOUT_SECONDS must be a positive integer")
        return v


def get_settings() -> Settings:
    """Helper function to load and validate settings from environment variables."""
    raw_settings = {}
    for field_name, field in Settings.model_fields.items():
        alias = field.alias or field_name
        if alias in os.environ:
            raw_settings[field_name] = os.environ[alias]
    return Settings(**raw_settings)
