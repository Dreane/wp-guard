"""Восстановление официальных файлов и вынос опасных файлов из сайта."""

from __future__ import annotations

import hashlib
import io
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from wpguard.http import HttpClient, HttpError
from wpguard.integrity import hashes_match
from wpguard.malware import PHP_EXTENSIONS
from wpguard.models import Action, Finding, Site

QUARANTINE_CODES = {
    "php-eval-decode", "php-assert-input", "php-preg-e", "php-variable-call",
    "php-array-map-assert", "php-call-user-exec", "php-file-put-input", "php-shell-input",
    "php-long-decode-call", "php-chr-chain", "php-strrev-eval", "php-pack-eval",
    "php-shell-filesman", "php-shell-c99", "php-shell-wso", "php-shell-b374k",
    "php-shell-r57", "php-dolly-marker", "php-reversed-marker", "packed-payload",
    "goto-obfuscation", "dolly-file", "hex-filename", "double-extension",
    "suspicious-filename", "config-backup", "env-file", "database-dump",
    "php-in-uploads", "polyglot-image", "php-in-languages", "root-extra-php",
    "core-extra", "plugin-extra",
}
PROTECTED_NAMES = {".htaccess", ".user.ini", "wp-config.php", "php.ini", ".php.ini"}


def _inside(site: Site, path: Path) -> bool:
    try:
        path.resolve().relative_to(site.root.resolve())
        return True
    except ValueError:
        return False


def _storage(cache_dir: Path, site: Site, kind: str) -> Path:
    digest = hashlib.sha256(str(site.root.resolve()).encode("utf-8")).hexdigest()[:16]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return cache_dir / kind / digest / stamp


def plan(findings: list[Finding], site: Site, quarantine: bool) -> list[Action]:
    actions: list[Action] = []
    restored: set[str] = set()
    for finding in findings:
        if finding.code not in {"core-mismatch", "plugin-mismatch"}:
            continue
        path = Path(finding.absolute_path) if finding.absolute_path else None
        if path is None or not path.is_file() or not _inside(site, path):
            continue
        if path.name in PROTECTED_NAMES:
            continue
        actions.append(Action(
            kind="restore",
            location=finding.location,
            absolute_path=str(path),
            reason=finding.title,
        ))
        restored.add(finding.location)
    if not quarantine:
        return actions
    seen = set(restored)
    for finding in findings:
        if finding.location in seen or finding.code not in QUARANTINE_CODES:
            continue
        path = Path(finding.absolute_path) if finding.absolute_path else None
        if path is None or not path.is_file() or not _inside(site, path):
            continue
        if path.name in PROTECTED_NAMES:
            continue
        if path.suffix.lower() not in PHP_EXTENSIONS and finding.code not in {
            "config-backup", "env-file", "database-dump", "polyglot-image", "double-extension", "dolly-file", "hex-filename"
        }:
            continue
        actions.append(Action(
            kind="quarantine",
            location=finding.location,
            absolute_path=str(path),
            reason=finding.title,
        ))
        seen.add(finding.location)
    return actions


def _backup(path: Path, folder: Path, site: Site) -> Path:
    relative = path.resolve().relative_to(site.root.resolve())
    destination = folder / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, destination)
    return destination


def _core_bytes(client: HttpClient, version: str, relative: str) -> bytes:
    url = "https://core.svn.wordpress.org/tags/" + quote(version) + "/" + quote(relative, safe="/")
    return client.get_bytes(url)


def _plugin_bytes(client: HttpClient, slug: str, version: str, relative: str) -> bytes:
    url = (
        "https://downloads.wordpress.org/plugin/"
        + quote(slug) + "." + quote(version, safe=".") + ".zip"
    )
    payload = client.get_bytes(url)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        target = f"{slug}/{relative}".replace("\\", "/")
        chosen = None
        for name in archive.namelist():
            normalized = name.replace("\\", "/")
            if normalized.startswith("/") or ".." in Path(normalized).parts:
                continue
            if normalized == target or normalized.lower() == target.lower():
                chosen = name
                break
        if chosen is None:
            raise HttpError(url, f"В архиве плагина нет {relative}")
        return archive.read(chosen)


def _acceptable(data: bytes, details: dict) -> bool:
    md5 = hashlib.md5(data).hexdigest()
    sha = hashlib.sha256(data).hexdigest()
    expected_md5 = [str(item).lower() for item in details.get("expected_md5") or []]
    expected_sha = [str(item).lower() for item in details.get("expected_sha256") or []]
    if not expected_md5 and not expected_sha:
        return False
    return hashes_match(md5, sha, expected_md5, expected_sha)


def _write(path: Path, data: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".wp-guard-tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def apply_actions(
    actions: list[Action],
    findings: list[Finding],
    site: Site,
    client: HttpClient | None,
    cache_dir: Path,
) -> None:
    by_location = {finding.location: finding for finding in findings if finding.code in {"core-mismatch", "plugin-mismatch"}}
    backup_root = _storage(cache_dir, site, "backups")
    quarantine_root = _storage(cache_dir, site, "quarantine")
    for action in actions:
        path = Path(action.absolute_path)
        try:
            if action.kind == "restore":
                if client is None:
                    raise HttpError("", "Для восстановления нужен доступ к wordpress.org")
                finding = by_location.get(action.location)
                details = finding.details if finding else {}
                if details.get("kind") == "plugin":
                    data = _plugin_bytes(client, str(details.get("slug")), str(details.get("version")), str(details.get("file")))
                else:
                    data = _core_bytes(client, str(details.get("version")), action.location)
                if not _acceptable(data, details):
                    raise HttpError("", "Скачанная копия не совпала с контрольной суммой, файл не изменён")
                saved = _backup(path, backup_root, site)
                _write(path, data)
                action.destination = str(saved)
                action.done = True
            elif action.kind == "quarantine":
                saved = quarantine_root / path.resolve().relative_to(site.root.resolve())
                saved.parent.mkdir(parents=True, exist_ok=True)
                if saved.exists():
                    saved = saved.with_name(saved.name + ".1")
                shutil.move(str(path), str(saved))
                action.destination = str(saved)
                action.done = True
        except Exception as exc:
            action.error = str(exc)[:300]
            action.done = False
