"""Сравнение версий в семантике PHP version_compare.

База WPVulnerability описывает диапазоны теми же операторами, что и PHP.
"""

from __future__ import annotations

import re

_SPECIAL = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "pl": 5,
    "p": 5,
}
_NUMBER_RANK = 4


def _parts(version: str) -> list[int | str]:
    text = version.strip().lower()
    text = text.replace("_", ".").replace("-", ".").replace("+", ".")
    text = re.sub(r"([0-9])([a-z])", r"\1.\2", text)
    text = re.sub(r"([a-z])([0-9])", r"\1.\2", text)
    parts: list[int | str] = []
    for piece in text.split("."):
        if piece == "":
            continue
        if piece.isdigit():
            parts.append(int(piece))
        else:
            parts.append(piece)
    return parts


def _rank(piece: int | str) -> tuple:
    if isinstance(piece, int):
        return (_NUMBER_RANK, piece)
    if piece in _SPECIAL:
        return (_SPECIAL[piece], 0)
    return (6, piece)


def _missing_against(other: int | str) -> int:
    """Сравнение конца более короткой версии с оставшейся частью.

    Возвращает -1, если короткая версия меньше, и 1, если больше.
    """
    if isinstance(other, int):
        return -1
    if other in {"pl", "p"}:
        return -1
    if other in {"dev", "alpha", "a", "beta", "b", "rc"}:
        return 1
    return -1


def compare(left: str, right: str) -> int:
    a = _parts(left)
    b = _parts(right)
    length = max(len(a), len(b))
    for index in range(length):
        if index >= len(a):
            return _missing_against(b[index])
        if index >= len(b):
            return -_missing_against(a[index])
        if a[index] == b[index]:
            continue
        ra = _rank(a[index])
        rb = _rank(b[index])
        if ra < rb:
            return -1
        if ra > rb:
            return 1
    return 0


def satisfies(installed: str, operator: str, bound: str) -> bool:
    result = compare(installed, bound)
    if operator == "lt":
        return result < 0
    if operator == "le":
        return result <= 0
    if operator == "eq":
        return result == 0
    if operator == "ne":
        return result != 0
    if operator == "gt":
        return result > 0
    if operator == "ge":
        return result >= 0
    return False


def is_affected(installed: str, operator: dict | None) -> bool:
    if not installed or not operator:
        return False
    checks: list[bool] = []
    min_version = operator.get("min_version")
    min_operator = operator.get("min_operator")
    max_version = operator.get("max_version")
    max_operator = operator.get("max_operator")
    if min_version and min_operator:
        checks.append(satisfies(installed, str(min_operator), str(min_version)))
    if max_version and max_operator:
        checks.append(satisfies(installed, str(max_operator), str(max_version)))
    if not checks:
        return str(operator.get("unfixed")) in {"1", "true", "True"}
    return all(checks)


def severity_from_cvss(score: float | None, fallback: str = "medium") -> str:
    if score is None:
        return fallback
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return fallback


def cvss_score(vulnerability: dict) -> float | None:
    impact = vulnerability.get("impact") or {}
    for key in ("cvss", "cvss3"):
        block = impact.get(key) or {}
        raw = block.get("score")
        if raw in (None, ""):
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None
