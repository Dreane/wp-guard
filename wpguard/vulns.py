"""Уязвимости ядра, плагинов, тем и PHP по открытой базе WPVulnerability."""

from __future__ import annotations

import re
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from wpguard.http import HttpClient, HttpError, NotFound
from wpguard.models import Finding, Plugin, Site, Theme
from wpguard.versioning import compare, cvss_score, is_affected, severity_from_cvss

API = "https://www.wpvulnerability.net"
ABANDONED_DAYS = 730


def detect_php_version() -> str | None:
    try:
        completed = subprocess.run(
            ["php", "-r", "echo PHP_VERSION;"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or "").strip()
    match = re.match(r"\d+\.\d+(?:\.\d+)?", text)
    return match.group(0) if match else None


def _finding(severity, code, title, location, evidence, advice, **details) -> Finding:
    return Finding(
        severity=severity,
        category="vulnerability",
        code=code,
        title=title,
        location=location,
        evidence=evidence[:180],
        advice=advice,
        details=details,
    )


def _cves(vulnerability: dict) -> list[str]:
    found = []
    for source in vulnerability.get("source") or []:
        identifier = str(source.get("id") or "")
        if identifier.upper().startswith("CVE-"):
            found.append(identifier)
    return found


def _supply_chain_findings(data: dict, location: str, label: str) -> list[Finding]:
    entries = data.get("supplychain") or data.get("supply_chain") or []
    if not isinstance(entries, list):
        return []
    found: list[Finding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        verdict = str(entry.get("verdict") or "").lower()
        if verdict not in {"malicious", "suspicious"}:
            continue
        title = entry.get("name") or entry.get("title") or "Компрометация в каталоге"
        found.append(_finding(
            "critical" if verdict == "malicious" else "high",
            "supply-chain",
            f"{label}: {title}",
            location,
            verdict,
            "Плагин или тема попадали в цепочку поставки. Обновитесь до версии, которую каталог пометил как очищенную, либо удалите компонент.",
        ))
    return found


def _range_text(operator: dict | None) -> str:
    if not operator:
        return "диапазон не указан"
    parts = []
    if operator.get("min_version") and operator.get("min_operator"):
        parts.append(f"{operator['min_operator']} {operator['min_version']}")
    if operator.get("max_version") and operator.get("max_operator"):
        parts.append(f"{operator['max_operator']} {operator['max_version']}")
    return " ".join(parts) or "диапазон не указан"


def vulnerabilities_for(client: HttpClient, kind: str, key: str) -> tuple[dict, list]:
    slug = quote_key(key) if kind != "core" else urllib.parse.quote(key)
    url = f"{API}/{kind}/{slug}/"
    payload = client.get_json(url)
    data = payload.get("data") or {}
    items = data.get("vulnerability") or []
    if not isinstance(items, list):
        items = []
    return data, items


def quote_key(value: str) -> str:
    return urllib.parse.quote(value.strip().lower(), safe="-_.")


def findings_from_vulnerabilities(
    data: dict,
    items: list,
    installed: str,
    location: str,
    label: str,
) -> list[Finding]:
    found: list[Finding] = []
    found.extend(_supply_chain_findings(data, location, label))
    if str(data.get("closed")) in {"1", "true", "True"}:
        reason = data.get("closed_reason") or "каталог закрыл компонент"
        found.append(_finding(
            "high",
            "closed-component",
            f"{label} закрыт в каталоге WordPress",
            location,
            str(reason)[:180],
            "Закрытие часто следует за взломом автора или заброшенностью. Удалите компонент и замените его.",
        ))
    ranked: list[Finding] = []
    for item in items:
        operator = item.get("operator") or {}
        if not is_affected(installed, operator):
            continue
        score = cvss_score(item)
        severity = severity_from_cvss(score)
        cves = ", ".join(_cves(item)[:4])
        evidence = f"установлено {installed}; {_range_text(operator)}"
        if cves:
            evidence += f"; {cves}"
        name = item.get("name") or "Уязвимость"
        ranked.append(_finding(
            severity,
            "known-vulnerability",
            str(name),
            location,
            evidence,
            "Обновите компонент до версии, которой нет в уязвимом диапазоне, либо удалите его, если обновления нет.",
            cvss=score,
            uuid=item.get("uuid"),
        ))
    ranked.sort(key=lambda item: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item.severity, 9),
        item.title,
    ))
    found.extend(ranked)
    return found


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    match = re.search(r"(\d{4}-\d{2}-\d{2})", value)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _plugin_info_url(slug: str) -> str:
    query = urllib.parse.urlencode([
        ("action", "plugin_information"),
        ("request[slug]", slug),
        ("request[fields][sections]", "0"),
        ("request[fields][description]", "0"),
        ("request[fields][banners]", "0"),
        ("request[fields][reviews]", "0"),
        ("request[fields][ratings]", "0"),
        ("request[fields][contributors]", "0"),
        ("request[fields][versions]", "0"),
        ("request[fields][screenshots]", "0"),
        ("request[fields][tags]", "0"),
        ("request[fields][compatibility]", "0"),
    ])
    return "https://api.wordpress.org/plugins/info/1.2/?" + query


def _theme_info_url(slug: str) -> str:
    query = urllib.parse.urlencode([
        ("action", "theme_information"),
        ("request[slug]", slug),
    ])
    return "https://api.wordpress.org/themes/info/1.2/?" + query


def _remote_version(client: HttpClient, url: str) -> tuple[str | None, datetime | None, str | None]:
    try:
        payload = client.get_json(url)
    except (HttpError, NotFound):
        return None, None, None
    if payload.get("error") and "version" not in payload:
        return None, None, None
    version = payload.get("version")
    updated = _parse_date(payload.get("last_updated") or payload.get("last_updated_time"))
    requires = payload.get("requires_php")
    requires_text = str(requires).strip() if requires else None
    return (str(version) if version else None), updated, requires_text


def _outdated(location: str, label: str, installed: str, latest: str | None, updated: datetime | None) -> list[Finding]:
    found: list[Finding] = []
    if latest and compare(installed, latest) < 0:
        found.append(_finding(
            "medium",
            "outdated",
            f"{label} устарел",
            location,
            f"установлено {installed}, в каталоге {latest}",
            "Обновляйте плагины и темы сразу после выхода версии: в 2025 году большинство новых дыр было именно в плагинах, а массовые атаки начинались в течение часов.",
        ))
    if updated is not None:
        age = datetime.now(timezone.utc) - updated
        if age.days >= ABANDONED_DAYS:
            found.append(_finding(
                "medium",
                "abandoned",
                f"{label} не обновлялся больше двух лет",
                location,
                updated.strftime("%Y-%m-%d"),
                "Заброшенный компонент не получит заплатку. Замените его и удалите, если он выключен: код на диске всё равно можно вызвать.",
            ))
    return found


def _php_findings(client: HttpClient, version: str) -> list[Finding]:
    try:
        data, items = vulnerabilities_for(client, "php", version)
    except HttpError as exc:
        return [_finding(
            "medium", "php-unchecked", "Версия PHP не проверена по базе уязвимостей",
            "php", str(exc)[:180], "Повторите запуск с сетью и --php-version.",
        )]
    found = []
    if data.get("status") == "d":
        end = data.get("date_end") or ""
        found.append(_finding(
            "high",
            "php-eol",
            "Ветка PHP снята с поддержки",
            "php",
            f"{version}, поддержка до {end}".strip(),
            "Переведите сайт на поддерживаемую ветку PHP. Старая ветка не получает исправления безопасности.",
        ))
    found.extend(findings_from_vulnerabilities(data, items, version, "php", f"PHP {version}"))
    return found


def _core_job(client: HttpClient, site: Site) -> list[Finding]:
    version = site.core_version or ""
    found: list[Finding] = []
    try:
        data, items = vulnerabilities_for(client, "core", version)
        found.extend(findings_from_vulnerabilities(data, items, version, "wordpress", f"WordPress {version}"))
    except HttpError as exc:
        found.append(_finding(
            "medium", "core-vuln-unchecked", "Уязвимости ядра не проверены",
            "wordpress", str(exc)[:180], "Повторите запуск, когда wpvulnerability.net доступен.",
        ))
    try:
        payload = client.get_json("https://api.wordpress.org/core/version-check/1.7/")
    except HttpError as exc:
        found.append(_finding(
            "low", "core-latest-unknown", "Не удалось узнать последнюю версию ядра",
            "wordpress", str(exc)[:180], "Проверьте доступ к api.wordpress.org.",
        ))
        return found
    offers = [item for item in payload.get("offers") or [] if not item.get("partial_version")]
    latest = None
    if offers:
        latest = offers[0].get("current") or offers[0].get("version")
    if latest and compare(version, str(latest)) < 0:
        severity = "high" if any(item.severity in {"critical", "high"} for item in found) else "medium"
        found.append(_finding(
            severity, "outdated-core", "Ядро WordPress устарело", "wordpress",
            f"установлено {version}, актуальна {latest}",
            "Обновите ядро. Даже когда дыры сидят в плагинах, старое ядро остаётся отдельной целью.",
        ))
    return found


def _plugin_job(client: HttpClient, plugin: Plugin, php_version: str | None) -> list[Finding]:
    location = f"plugin:{plugin.slug}"
    if plugin.headerless or plugin.kind != "plugin":
        if plugin.kind == "mu-plugin":
            return [_finding(
                "info", "mu-plugin-not-in-directory",
                "Must-use плагин не сверяется с каталогом",
                location, plugin.name or plugin.slug,
                "Проверьте файл вручную: mu-plugins подключаются всегда и не видны в обычном списке.",
            )]
        return []
    if not plugin.version:
        return [_finding(
            "medium", "plugin-version-missing", "У плагина не прочитана версия",
            location, plugin.slug, "Без версии нельзя понять, закрыта ли дыра.",
        )]
    found: list[Finding] = []
    try:
        data, items = vulnerabilities_for(client, "plugin", plugin.slug)
        found.extend(findings_from_vulnerabilities(
            data, items, plugin.version, location, plugin.name or plugin.slug
        ))
    except NotFound:
        found.append(_finding(
            "info", "plugin-not-in-vulnerability-db",
            "Плагина нет в базе уязвимостей каталога",
            location, plugin.slug,
            "Самописный или платный плагин. Его файлы всё равно проверяются правилами.",
        ))
    except HttpError as exc:
        found.append(_finding(
            "medium", "plugin-vuln-unchecked", "Уязвимости плагина не проверены",
            location, str(exc)[:180], "Повторите запуск позже.",
        ))
    latest, updated, requires_php = _remote_version(client, _plugin_info_url(plugin.slug.lower()))
    found.extend(_outdated(location, plugin.name or plugin.slug, plugin.version, latest, updated))
    required = requires_php or plugin.requires_php
    if php_version and required and re.match(r"\d", required) and compare(php_version, required) < 0:
        found.append(_finding(
            "medium", "plugin-php-requirement",
            "Плагин требует более новую PHP, чем запущена на сервере",
            location, f"нужна {required}, обнаружена {php_version}",
            "Либо обновите PHP, либо не пользуйтесь этим плагином: на старой версии он может работать небезопасно.",
        ))
    return found


def _theme_job(client: HttpClient, theme: Theme) -> list[Finding]:
    location = f"theme:{theme.slug}"
    if not theme.version:
        return [_finding(
            "low", "theme-version-missing", "У темы не прочитана версия",
            location, theme.slug, "Укажите Version в style.css.",
        )]
    found: list[Finding] = []
    try:
        data, items = vulnerabilities_for(client, "theme", theme.slug)
        found.extend(findings_from_vulnerabilities(
            data, items, theme.version, location, theme.name or theme.slug
        ))
    except NotFound:
        pass
    except HttpError as exc:
        found.append(_finding(
            "medium", "theme-vuln-unchecked", "Уязвимости темы не проверены",
            location, str(exc)[:180], "Повторите запуск позже.",
        ))
    latest, updated, _requires = _remote_version(client, _theme_info_url(theme.slug.lower()))
    found.extend(_outdated(location, theme.name or theme.slug, theme.version, latest, updated))
    return found


def scan(site: Site, client: HttpClient | None, php_version: str | None, workers: int = 4) -> list[Finding]:
    if client is None:
        return [_finding(
            "medium", "vuln-offline", "Проверка уязвимостей пропущена",
            "", "--offline", "Запустите без --offline, чтобы сверить версии с открытой базой.",
        )]
    detected = php_version or detect_php_version()
    jobs = []
    if site.core_version:
        jobs.append(lambda: _core_job(client, site))
    else:
        jobs.append(lambda: [_finding(
            "high", "core-version-missing", "Нельзя проверить уязвимости ядра",
            "wordpress", "версия не прочитана", "Восстановите wp-includes/version.php.",
        )])
    for plugin in site.plugins:
        jobs.append(lambda plugin=plugin: _plugin_job(client, plugin, detected))
    for theme in site.themes:
        jobs.append(lambda theme=theme: _theme_job(client, theme))
    if detected:
        jobs.append(lambda: _php_findings(client, detected))
    else:
        jobs.append(lambda: [_finding(
            "info", "php-version-unknown", "Версия PHP не указана",
            "php", "нет --php-version и нет команды php",
            "Передайте версию PHP сайта: wp-guard scan путь --php-version 8.3.16. Версия в консоли хостинга иногда отличается от версии сайта.",
        )])
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 4))) as pool:
        futures = [pool.submit(job) for job in jobs]
        for future in as_completed(futures):
            findings.extend(future.result())
    if detected:
        findings.append(_finding(
            "info", "php-version-used", "Версия PHP, по которой искались уязвимости",
            "php", detected,
            "Если сайт работает на другой версии FPM, повторите с --php-version.",
        ))
    return findings
