import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class ZapClientError(Exception):
    """Exception raised for ZAP communication or execution errors."""

    pass


class ZapClient:
    """A lightweight REST client for interacting with the OWASP ZAP API."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(
        self, path: str, params: Optional[Dict[str, Any]] = None, is_post: bool = False
    ) -> Dict[str, Any]:
        """Performs HTTP requests to the ZAP API JSON endpoint."""
        url = f"{self.base_url}/JSON/{path.lstrip('/')}"

        query_params = params or {}
        if self.api_key:
            query_params["apikey"] = self.api_key

        data = None
        if query_params:
            encoded_params = urllib.parse.urlencode(query_params)
            if is_post:
                data = encoded_params.encode("utf-8")
            else:
                url = f"{url}?{encoded_params}"

        req = urllib.request.Request(url, data=data)
        if self.api_key:
            req.add_header("X-ZAP-API-Key", self.api_key)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read().decode("utf-8")
                return json.loads(content)
        except urllib.error.HTTPError as e:
            try:
                err_content = e.read().decode("utf-8")
                err_json = json.loads(err_content)
                msg = err_json.get("message", str(e))
            except Exception:
                msg = str(e)
            raise ZapClientError(f"ZAP API error: {msg}")
        except Exception as e:
            raise ZapClientError(f"Failed to communicate with ZAP: {e}")

    def check_connectivity(self) -> bool:
        """Verifies if the ZAP API endpoint is reachable."""
        try:
            res = self._request("core/view/version/")
            return "version" in res
        except Exception:
            return False

    def check_readiness(self) -> bool:
        """Verifies if ZAP is ready (checks version and connectivity)."""
        return self.check_connectivity()

    def start_spider(self, target_url: str) -> str:
        """Triggers a spider scan against the target URL. Returns the scan ID."""
        res = self._request("spider/action/scan/", {"url": target_url}, is_post=True)
        if "scan" not in res:
            raise ZapClientError(f"Unexpected response starting spider scan: {res}")
        return str(res["scan"])

    def get_spider_status(self, scan_id: str) -> int:
        """Retrieves progress percentage of the spider scan (0 to 100)."""
        res = self._request("spider/view/status/", {"scanId": scan_id})
        if "status" not in res:
            raise ZapClientError(f"Unexpected spider status response: {res}")
        try:
            return int(res["status"])
        except ValueError:
            raise ZapClientError(f"Invalid spider status: {res['status']}")

    def get_records_to_scan(self) -> int:
        """Retrieves count of records remaining to scan passively."""
        res = self._request("pscan/view/recordsToScan/")
        if "recordsToScan" not in res:
            raise ZapClientError(
                f"Unexpected response retrieving records to scan: {res}"
            )
        try:
            return int(res["recordsToScan"])
        except ValueError:
            raise ZapClientError(
                f"Invalid records to scan count: {res['recordsToScan']}"
            )

    def wait_for_pscan(self, poll_interval: int = 1, timeout: int = 30) -> None:
        """Polls recordsToScan until it reaches 0 or timeout is hit."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            count = self.get_records_to_scan()
            if count == 0:
                return
            time.sleep(poll_interval)

    def get_alerts(self, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves list of alerts/findings from ZAP."""
        params = {}
        if base_url:
            params["baseurl"] = base_url
        res = self._request("core/view/alerts/", params)
        if "alerts" not in res:
            raise ZapClientError(f"Unexpected response retrieving alerts: {res}")
        return res["alerts"]
