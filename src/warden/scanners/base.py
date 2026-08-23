from abc import ABC, abstractmethod
from typing import Any, List, Optional

from warden.models.finding import Finding
from warden.models.target import TargetConfig


class BaseScanner(ABC):
    """Abstract Base Class for all security scanning modules in Warden."""

    def __init__(self, target: TargetConfig, zap_client: Optional[Any] = None) -> None:
        if not target.is_authorized:
            raise ValueError(
                f"Target '{target.name}' must be authorized for security scanning."
            )
        self.target = target
        self.zap_client = zap_client

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the scanner."""
        pass

    @abstractmethod
    def run(self) -> List[Finding]:
        """Executes the scanner's tests against the target environment.

        Returns:
            List[Finding]: List of discovered vulnerability findings.
        """
        pass
