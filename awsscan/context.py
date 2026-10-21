"""Scan context: AWS client access, pagination and error helpers.

Checks never import boto3 directly. They ask the context for a client, which
makes them easy to test with fake clients and to run against a demo account.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterator

ClientFactory = Callable[[str, str], Any]


def error_code(exc: BaseException) -> str | None:
    """Return the AWS error code from a botocore ClientError (or a fake one)."""
    response = getattr(exc, "response", None) or {}
    return (response.get("Error") or {}).get("Code")


class ScanContext:
    def __init__(self, client_factory: ClientFactory, regions: list[str], account_id: str,
                 home_region: str | None = None, now: datetime | None = None) -> None:
        self._factory = client_factory
        self._cache: dict[tuple[str, str], Any] = {}
        self.regions = regions
        self.account_id = account_id
        self.home_region = home_region or regions[0]
        self.now = now or datetime.now(timezone.utc)

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region or self.home_region)
        if key not in self._cache:
            self._cache[key] = self._factory(*key)
        return self._cache[key]

    @staticmethod
    def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterator[Any]:
        """Yield every item of ``result_key`` across all pages of an API call."""
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(result_key, [])
