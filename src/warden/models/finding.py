from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Foundational domain model representing a security vulnerability finding."""

    id: str = Field(..., description="Unique identifier for the vulnerability finding")
    target_id: str = Field(
        ..., description="ID of the target where this finding was discovered"
    )
    name: str = Field(..., description="Name of the vulnerability")
    severity: Severity = Field(default=Severity.INFO)
    description: str = Field(..., description="Detailed description of the finding")
    remediation: Optional[str] = Field(
        default=None, description="Suggested mitigation steps"
    )
    evidence: Optional[str] = Field(
        default=None, description="Evidence payload or response snippet"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context or tool-specific parameters",
    )
