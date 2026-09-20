import json
import urllib.request

from .models import ScanReport


class SeereClient:
    """
    Optional metadata-only pipeline to a SEERE Sentinel control plane.

    Raw secret values are never accepted by this client.
    """

    def __init__(self, endpoint: str, token: str):
        self.endpoint = endpoint
        self.token = token

    def push_report(self, report: ScanReport) -> dict:
        payload = report.to_dict()

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "seere-sdk/0.1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8", "replace")
            return {
                "status": response.status,
                "body": body[:2000],
            }
