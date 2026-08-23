import urllib.error
import urllib.request
from urllib.parse import urlparse

from warden.models.target import TargetConfig


class TargetValidationError(Exception):
    """Exception raised for target validation, reachability, or eligibility failures."""

    pass


def validate_target_config(target: TargetConfig) -> None:
    """Ensure the target config is valid and explicitly authorized."""
    if not target.is_authorized:
        raise TargetValidationError("Target is not authorized")
    if not target.base_url:
        raise TargetValidationError("Target URL is invalid")


def check_target_reachability(target: TargetConfig, timeout: int = 10) -> None:
    """Verifies that the target is reachable and returns a valid HTTP response."""
    url_str = str(target.base_url)
    parsed = urlparse(url_str)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError(f"Target URL has invalid scheme: {parsed.scheme}")

    req = urllib.request.Request(
        url_str, headers={"User-Agent": "Warden Security Suite Verification"}
    )

    try:
        # Use urlopen to verify reachability
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.getcode()
            if status >= 500:
                raise TargetValidationError(
                    f"Target health check failed with status: {status}"
                )
    except urllib.error.HTTPError as e:
        # HTTPError indicates a response was received (reachable),
        # but status is 4xx or 5xx
        if e.code >= 500:
            raise TargetValidationError(
                f"Target health check failed with status: {e.code}"
            )
    except urllib.error.URLError as e:
        raise TargetValidationError(f"Target is unreachable: {e.reason}")
    except TimeoutError:
        raise TargetValidationError("Target timed out")
    except Exception as e:
        raise TargetValidationError(f"Target is unreachable: {e}")
