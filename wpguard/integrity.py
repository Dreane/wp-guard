"""Сверка файлов ядра и официальных плагинов с wordpress.org."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

from wpguard.http import HttpClient, HttpError, NotFound
from wpguard.malware import PHP_EXTENSIONS, relative
from wpguard.models import Finding, Plugin, Site

LOW_EXTENSIONS = {".txt", ".md", ".pot", ".po", ".mo", ".html", ".htm"}
SKIP_NAMES = {".ds_store", "thumbs.db"}


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.lower()]
    if isinstance(value, list):
        return [str(item).lower() for item in value]
    return []


def hash_file(path: Path) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def hashes_match(md5: str, sha: str, expected_md5: list[str], expected_sha: list[str]) -> bool:
    if expected_sha and sha in expected_sha:
        return True
    if expected_md5 and md5 in expected_md5:
        return True
    return False


def _mismatch_severity(rel: str) -> str:
    suffix = Path(rel).suffix.lower()
    if suffix in PHP_EXTENSIONS:
        return "critical"
    if suffix in {".js", ".css"}:
        return "high"
    if suffix in LOW_EXTENSIONS:
        return "low"
    return "medium"


def _core_urls(version: str, locale: str) -> list[str]:
    urls = [
        "https://api.wordpress.org/core/checksums/1.0/?version="
        + quote(version) + "&locale=" + quote(locale or "en_US")
    ]
    if (locale or "en_US") != "en_US":
        urls.append(
            "https://api.wordpress.org/core/checksums/1.0/?version="
            + quote(version) + "&locale=en_US"
        )
    return urls


def load_core_checksums(client: HttpClient, version: str, locale: str) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    errors: list[str] = []
    for url in _core_urls(version, locale):
        try:
            payload = client.get_json(url)
        except NotFound:
            errors.append(url)
            continue
        except HttpError:
            errors.append(url)
            continue
        table = payload.get("checksums")
        if not isinstance(table, dict) or not table:
            errors.append(url)
            continue
        for rel, digest in table.items():
            merged.setdefault(str(rel), [])
            merged[str(rel)].extend(_as_list(digest))
    if not merged and errors:
        raise HttpError(errors[0], "Не удалось получить контрольные суммы ядра")
    return merged


def _checksum_finding(severity, code, title, rel, path: Path | None, evidence, advice, **details) -> Finding:
    return Finding(
        severity=severity,
        category="integrity",
        code=code,
        title=title,
        location=rel,
        evidence=evidence[:180],
        advice=advice,
        absolute_path=str(path) if path is not None else "",
        details=details,
    )


def check_core(site: Site, client: HttpClient, workers: int) -> list[Finding]:
    if not site.core_version:
        return [_checksum_finding(
            "high", "core-version-missing", "Версия ядра не прочитана",
            "wp-includes/version.php", site.root / "wp-includes" / "version.php",
            "В version.php нет $wp_version",
            "Файл ядра повреждён или это не каталог WordPress.",
        )]
    try:
        expected = load_core_checksums(client, site.core_version, site.locale)
    except HttpError as exc:
        return [_checksum_finding(
            "medium", "core-unchecked", "Целостность ядра не проверена",
            "", None, str(exc)[:180],
            "Повторите проверку, когда будет доступ к api.wordpress.org.",
            version=site.core_version,
        )]
    findings: list[Finding] = []
    present: list[tuple[str, Path]] = []
    missing_core: list[str] = []
    missing_bundle: list[str] = []
    for rel in expected:
        path = site.root / rel
        if path.is_file():
            present.append((rel, path))
        elif rel.startswith("wp-admin/") or rel.startswith("wp-includes/") or "/" not in rel:
            missing_core.append(rel)
        else:
            missing_bundle.append(rel)
    digests: dict[str, tuple[str, str]] = {}
    if present:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            mapped = pool.map(lambda item: (item[0], hash_file(item[1])), present)
            for rel, digest in mapped:
                digests[rel] = digest
    for rel, path in present:
        md5, sha = digests[rel]
        if hashes_match(md5, sha, expected[rel], []):
            continue
        findings.append(_checksum_finding(
            _mismatch_severity(rel),
            "core-mismatch",
            "Файл ядра не совпадает с wordpress.org",
            rel,
            path,
            f"md5 {md5}",
            "Верните официальный файл командой remediate. Не правьте ядро вручную.",
            kind="core",
            version=site.core_version,
            expected_md5=expected[rel],
            expected_sha256=[],
        ))
    for rel in missing_core[:30]:
        findings.append(_checksum_finding(
            "high", "core-missing", "В ядре не хватает файла", rel,
            site.root / rel, rel,
            "Удалённый файл ядра иногда заменяют заглушкой в другом месте. Верните оригинал.",
            kind="core", version=site.core_version,
        ))
    if len(missing_core) > 30:
        findings.append(_checksum_finding(
            "high", "core-missing-more", "В ядре не хватает ещё файлов", "",
            None, f"ещё {len(missing_core) - 30}",
            "Восстановите ядро этой версии с wordpress.org.",
        ))
    if missing_bundle:
        sample = ", ".join(missing_bundle[:8])
        findings.append(_checksum_finding(
            "low", "bundled-missing",
            "Удалены файлы стандартных тем или плагинов из комплекта",
            "", None, f"{len(missing_bundle)}: {sample}",
            "Удаление неиспользуемой стандартной темы — нормальная практика. Убедитесь, что это сделали вы.",
        ))
    known = set(expected)
    extras: list[tuple[str, Path]] = []
    for folder in ("wp-admin", "wp-includes"):
        base = site.root / folder
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [name for name in dirnames if name not in {".git", ".svn"}]
            for filename in filenames:
                if filename.lower() in SKIP_NAMES:
                    continue
                path = Path(dirpath) / filename
                rel = relative(site.root, path)
                if rel not in known:
                    extras.append((rel, path))
    php_extras = [(rel, path) for rel, path in extras if path.suffix.lower() in PHP_EXTENSIONS]
    other_extras = [(rel, path) for rel, path in extras if path.suffix.lower() not in PHP_EXTENSIONS]
    for rel, path in php_extras[:40]:
        findings.append(_checksum_finding(
            "critical", "core-extra", "В ядре лежит файл, которого нет в выпуске WordPress",
            rel, path, path.name,
            "Штатный выпуск этот файл не содержит. Карантин или удаление после просмотра.",
            kind="core-extra",
        ))
    if len(php_extras) > 40:
        findings.append(_checksum_finding(
            "critical", "core-extra-more", "В ядре ещё посторонние PHP-файлы",
            "", None, f"ещё {len(php_extras) - 40}",
            "Просмотрите wp-admin и wp-includes.",
        ))
    if other_extras:
        findings.append(_checksum_finding(
            "medium", "core-extra-other", "В ядре есть посторонние файлы не на PHP",
            other_extras[0][0], other_extras[0][1], f"всего {len(other_extras)}",
            "Сверьте список с чистой установкой той же версии.",
        ))
    return findings


def _plugin_files(payload: dict) -> dict[str, tuple[list[str], list[str]]]:
    files = payload.get("files") or {}
    parsed: dict[str, tuple[list[str], list[str]]] = {}
    if not isinstance(files, dict):
        return parsed
    for rel, hashes in files.items():
        if isinstance(hashes, dict):
            parsed[str(rel)] = (_as_list(hashes.get("md5")), _as_list(hashes.get("sha256")))
        else:
            parsed[str(rel)] = (_as_list(hashes), [])
    return parsed


def check_plugin(site: Site, plugin: Plugin, client: HttpClient, workers: int) -> tuple[list[Finding], str | None]:
    if plugin.kind != "plugin" or plugin.headerless or not plugin.version or not plugin.path.is_dir():
        return [], None
    slug = plugin.slug.lower()
    version = plugin.version.strip()
    url = (
        "https://downloads.wordpress.org/plugin-checksums/"
        + quote(slug) + "/" + quote(version, safe=".") + ".json"
    )
    try:
        payload = client.get_json(url)
    except NotFound:
        return [], slug
    except HttpError as exc:
        return ([_checksum_finding(
            "medium", "plugin-unchecked", "Контрольные суммы плагина не скачались",
            plugin.slug, plugin.path, str(exc)[:180],
            "Повторите проверку позже. Файлы всё равно просматриваются правилами.",
        )], None)
    expected = _plugin_files(payload)
    if not expected:
        return [], slug
    findings: list[Finding] = []
    base = plugin.path
    present = []
    for rel, hashes in expected.items():
        path = base / rel
        if path.is_file():
            present.append((rel, path, hashes))
    digests = {}
    if present:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for rel, digest in pool.map(lambda item: (item[0], hash_file(item[1])), present):
                digests[rel] = digest
    for rel, path, (md5s, shas) in present:
        md5, sha = digests[rel]
        if hashes_match(md5, sha, md5s, shas):
            continue
        findings.append(_checksum_finding(
            _mismatch_severity(rel),
            "plugin-mismatch",
            "Файл официального плагина изменён",
            relative(site.root, path),
            path,
            f"{plugin.slug} {version}",
            "Верните файл из выпуска этой версии. Правки внутри плагина с wordpress.org затираются и часто оказываются вредоносными.",
            kind="plugin",
            slug=slug,
            version=version,
            file=rel,
            expected_md5=md5s,
            expected_sha256=shas,
        ))
    known = set(expected)
    extras = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [name for name in dirnames if name not in {".git", ".svn", "node_modules"}]
        for filename in filenames:
            if filename.lower() in SKIP_NAMES:
                continue
            path = Path(dirpath) / filename
            rel = path.relative_to(base).as_posix()
            if rel not in known:
                extras.append((rel, path))
    for rel, path in extras:
        if path.suffix.lower() not in PHP_EXTENSIONS:
            continue
        findings.append(_checksum_finding(
            "high",
            "plugin-extra",
            "В официальном плагине есть PHP, которого нет в выпуске",
            relative(site.root, path),
            path,
            f"{plugin.slug}: {rel}",
            "В архиве wordpress.org этого файла нет. Так подкладывают второй вход после взлома.",
            kind="plugin-extra",
            slug=slug,
        ))
    return findings, None


def scan(site: Site, client: HttpClient | None, workers: int = 4) -> list[Finding]:
    if client is None:
        return [_checksum_finding(
            "medium", "integrity-offline", "Сверка с wordpress.org пропущена",
            "", None, "--offline",
            "Запустите без --offline, чтобы сравнить ядро и плагины с официальными суммами.",
        )]
    findings = check_core(site, client, workers)
    unknown: list[str] = []
    for plugin in site.plugins:
        plugin_findings, unknown_slug = check_plugin(site, plugin, client, workers)
        findings.extend(plugin_findings)
        if unknown_slug:
            unknown.append(unknown_slug)
    if unknown:
        findings.append(_checksum_finding(
            "info",
            "plugins-without-checksums",
            "Часть плагинов нельзя сверить с wordpress.org",
            "",
            None,
            ", ".join(unknown[:30]),
            "Их нет в каталоге, либо версия в шапке не совпадает с выпущенной. Файлы проверены правилами. Платные и самописные плагины сюда попадают закономерно.",
        ))
    return findings
