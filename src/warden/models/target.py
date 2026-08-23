from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class TargetAuthContext(BaseModel):
    """Encapsulates authentication credentials and options for target scans."""

    auth_type: str = Field(
        ..., description="Authentication type: e.g., bearer, basic, cookie, custom"
    )
    credentials: Dict[str, str] = Field(
        default_factory=dict,
        description="Dictionary containing required auth parameters",
    )


AUTHORIZATION_DESC = (
    "Must be explicitly set to True to confirm authorization for testing"
)


class TargetConfig(BaseModel):
    """Validation domain model representing an authorized scan target."""

    id: str = Field(..., description="Unique identifier for the target")
    name: str = Field(..., description="Friendly name of the target environment")
    base_url: HttpUrl = Field(..., description="The authorized target base URL")
    is_authorized: bool = Field(
        default=False,
        description=AUTHORIZATION_DESC,
    )
    auth_context: Optional[TargetAuthContext] = Field(default=None)
    auth_context_b: Optional[TargetAuthContext] = Field(default=None)
    scan_metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("is_authorized")
    @classmethod
    def enforce_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "Target is not authorized. Warden only executes tests against "
                "explicitly authorized targets."
            )
        return v
