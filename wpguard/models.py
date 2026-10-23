from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class Finding:
    severity: str
    category: str
    code: str
    title: str
    location: str
    evidence: str = ""
    advice: str = ""
    absolute_path: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "code": self.code,
            "title": self.title,
            "location": self.location,
            "evidence": self.evidence,
            "advice": self.advice,
            "details": self.details,
        }


@dataclass
class Plugin:
    slug: str
    name: str
    version: str
    path: Path
    main_file: Optional[Path]
    kind: str = "plugin"
    headerless: bool = False
    requires_php: str = ""


@dataclass
class Theme:
    slug: str
    name: str
    version: str
    path: Path


@dataclass
class WpConfig:
    path: Optional[Path]
    db_name: Optional[str] = None
    db_user: Optional[str] = None
    db_password: Optional[str] = None
    db_host: str = "localhost"
    db_port: int = 3306
    db_socket: Optional[str] = None
    db_charset: str = "utf8mb4"
    table_prefix: str = "wp_"
    constants: dict[str, str] = field(default_factory=dict)
    password_is_literal: bool = False

    def __repr__(self) -> str:
        return (
            f"WpConfig(name={self.db_name!r}, user={self.db_user!r}, "
            f"host={self.db_host!r}, prefix={self.table_prefix!r})"
        )


@dataclass
class Site:
    root: Path
    config: WpConfig
    core_version: Optional[str]
    plugins: list[Plugin]
    themes: list[Theme]
    locale: str = "en_US"


@dataclass
class Options:
    workers: int = 4
    offline: bool = False
    refresh: bool = False
    quiet: bool = False
    php_version: Optional[str] = None
    max_bytes: int = 8 * 1024 * 1024
    min_severity: str = "info"
    sections: set[str] = field(default_factory=lambda: {
        "surface", "malware", "integrity", "vuln", "database"
    })
    cache_dir: Optional[Path] = None
    db_host: Optional[str] = None
    db_port: Optional[int] = None
    db_name: Optional[str] = None
    db_user: Optional[str] = None
    db_password: Optional[str] = None
    db_prefix: Optional[str] = None
    apply: bool = False
    quarantine: bool = False


@dataclass
class Action:
    kind: str
    location: str
    absolute_path: str
    reason: str
    done: bool = False
    error: str = ""
    destination: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "location": self.location,
            "reason": self.reason,
            "done": self.done,
            "error": self.error,
            "destination": self.destination,
        }


@dataclass
class SiteReport:
    root: str
    core_version: Optional[str]
    findings: list[Finding]
    stats: dict[str, Any] = field(default_factory=dict)
    actions: list[Action] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_RANK}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts


def keep(finding: Finding, minimum: str) -> bool:
    return SEVERITY_RANK.get(finding.severity, 9) <= SEVERITY_RANK.get(minimum, 4)


def worst_exit_code(findings: list[Finding]) -> int:
    for finding in findings:
        if finding.severity in {"critical", "high"}:
            return 2
    return 0
