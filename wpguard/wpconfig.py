"""Чтение wp-config.php без исполнения PHP."""

from __future__ import annotations

import re
from pathlib import Path

from wpguard.models import WpConfig

_DEFINE = re.compile(
    r"""define\s*\(\s*(['"])(?P<name>[A-Za-z0-9_]+)\1\s*,\s*"""
    r"""(?:'(?P<sq>(?:\\'|[^'])*)'|"(?P<dq>(?:\\"|[^"])*)"|(?P<bare>[A-Za-z0-9_.-]+))\s*\)""",
    re.IGNORECASE,
)
_PREFIX = re.compile(
    r"""\$table_prefix\s*=\s*(['"])(?P<value>[^'"]*)\1"""
)


def _unescape(value: str, quote: str) -> str:
    if quote == "'":
        return value.replace("\\'", "'").replace("\\\\", "\\")
    return value.replace('\\"', '"').replace("\\\\", "\\")


def parse_wp_config(text: str, path: Path | None = None) -> WpConfig:
    constants: dict[str, str] = {}
    for match in _DEFINE.finditer(text):
        name = match.group("name").upper()
        if match.group("sq") is not None:
            constants[name] = _unescape(match.group("sq"), "'")
        elif match.group("dq") is not None:
            constants[name] = _unescape(match.group("dq"), '"')
        else:
            constants[name] = match.group("bare")
    prefix_match = _PREFIX.search(text)
    prefix = prefix_match.group("value") if prefix_match else "wp_"
    host, port, socket = split_db_host(constants.get("DB_HOST") or "localhost")
    password = constants.get("DB_PASSWORD")
    return WpConfig(
        path=path,
        db_name=constants.get("DB_NAME"),
        db_user=constants.get("DB_USER"),
        db_password=password,
        db_host=host,
        db_port=port,
        db_socket=socket,
        db_charset=constants.get("DB_CHARSET") or "utf8mb4",
        table_prefix=prefix or "wp_",
        constants=constants,
        password_is_literal="DB_PASSWORD" in constants,
    )


def load_wp_config(path: Path) -> WpConfig:
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_wp_config(text, path)


def split_db_host(host: str) -> tuple[str, int, str | None]:
    host = host.strip()
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            address = host[1:end]
            rest = host[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return address, int(rest[1:]), None
            return address, 3306, None
    if ":" in host:
        name, rest = host.split(":", 1)
        if rest.startswith("/"):
            return name or "localhost", 3306, rest
        if rest.isdigit():
            return name, int(rest), None
    return host, 3306, None


def php_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    text = value.strip().strip("'\"").lower()
    if text in {"true", "1", "on", "yes"}:
        return True
    if text in {"false", "0", "off", "no", ""}:
        return False
    return None


def locale_of(config: WpConfig) -> str:
    lang = config.constants.get("WPLANG") or ""
    lang = lang.strip()
    if not lang or lang.lower() in {"en_us", "en"}:
        return "en_US"
    return lang
