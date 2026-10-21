"""Check registry.

A check is a generator decorated with :func:`check`. It receives the scan
context (and the region for regional checks) and yields ``Result`` tuples.
"""

from __future__ import annotations

from typing import Callable, Iterable, NamedTuple

from .models import CheckMeta


class Result(NamedTuple):
    passed: bool
    resource: str
    details: str = ""


CheckFunc = Callable[..., Iterable[Result]]
REGISTRY: list[tuple[CheckMeta, CheckFunc]] = []


def check(*, id: str, title: str, service: str, severity: str, scope: str = "regional",
          cis: str = "-", description: str = "", remediation: str = "") -> Callable[[CheckFunc], CheckFunc]:
    if scope not in ("global", "regional"):
        raise ValueError(f"{id}: scope must be global or regional")
    meta = CheckMeta(id, title, service, severity, scope, cis, description, remediation)

    def decorator(func: CheckFunc) -> CheckFunc:
        if any(m.id == id for m, _ in REGISTRY):
            raise ValueError(f"duplicate check id {id}")
        REGISTRY.append((meta, func))
        return func

    return decorator


def all_checks() -> list[tuple[CheckMeta, CheckFunc]]:
    from . import checks  # noqa: F401  (importing registers every check)

    return sorted(REGISTRY, key=lambda item: item[0].id)
