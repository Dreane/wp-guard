"""Настройки сайта, которые сами по себе открывают дверь."""

from __future__ import annotations

import os
from pathlib import Path

from wpguard.models import Finding, Site
from wpguard.wpconfig import php_bool

WEAK_PASSWORDS = {
    "password", "admin", "root", "123456", "12345678", "123456789",
    "wordpress", "qwerty", "pass", "changeme", "iloveyou", "admin123",
}


def _finding(severity, code, title, location, evidence, advice) -> Finding:
    return Finding(
        severity=severity,
        category="hardening",
        code=code,
        title=title,
        location=location,
        evidence=evidence,
        advice=advice,
    )


def _world_writable(path: Path) -> bool:
    if os.name == "nt" or not path.exists():
        return False
    try:
        return bool(path.stat().st_mode & 0o002)
    except OSError:
        return False


def _world_readable(path: Path) -> bool:
    if os.name == "nt" or not path.exists():
        return False
    try:
        return bool(path.stat().st_mode & 0o004)
    except OSError:
        return False


def inspect(site: Site) -> list[Finding]:
    found: list[Finding] = []
    root = site.root
    constants = site.config.constants
    if php_bool(constants.get("DISALLOW_FILE_EDIT")) is not True:
        found.append(_finding(
            "info",
            "file-editor-enabled",
            "В админке включён редактор файлов",
            "wp-config.php",
            "DISALLOW_FILE_EDIT не включён",
            "Добавьте define('DISALLOW_FILE_EDIT', true); чтобы захваченная админка не правила файлы темы и плагинов.",
        ))
    debug = php_bool(constants.get("WP_DEBUG"))
    display = php_bool(constants.get("WP_DEBUG_DISPLAY"))
    if debug is True and display is not False:
        found.append(_finding(
            "medium",
            "debug-display",
            "Ошибки PHP показываются посетителям",
            "wp-config.php",
            "WP_DEBUG включён, WP_DEBUG_DISPLAY не выключен",
            "Выключите показ ошибок на боевом сайте. В тексте ошибки бывают пути и параметры.",
        ))
    elif debug is True:
        found.append(_finding(
            "low",
            "debug-enabled",
            "На боевом сайте включён WP_DEBUG",
            "wp-config.php",
            "WP_DEBUG true",
            "Отладка пишет лишнее в журнал. На публичном сайте её лучше выключить.",
        ))
    prefix = site.config.table_prefix
    if prefix == "wp_":
        found.append(_finding(
            "low",
            "default-prefix",
            "Стандартный префикс таблиц wp_",
            "wp-config.php",
            "table_prefix = wp_",
            "Сам по себе префикс не защищает, но автоматические SQL-атаки чаще целятся в wp_.",
        ))
    password = site.config.db_password
    if site.config.password_is_literal and password is not None:
        if password.lower() in WEAK_PASSWORDS or len(password) < 6:
            found.append(_finding(
                "critical",
                "weak-db-password",
                "Пароль базы слишком простой",
                "wp-config.php",
                f"длина пароля: {len(password)}",
                "Задайте длинный уникальный пароль базы и поменяйте его в панели хостинга. Сам пароль в отчёт не пишется.",
            ))
        elif len(password) < 12:
            found.append(_finding(
                "medium",
                "short-db-password",
                "Пароль базы короче 12 символов",
                "wp-config.php",
                f"длина пароля: {len(password)}",
                "Удлините пароль базы. Сам пароль в отчёт не пишется.",
            ))
    if (root / "xmlrpc.php").is_file():
        found.append(_finding(
            "low",
            "xmlrpc-present",
            "xmlrpc.php включён",
            "xmlrpc.php",
            "файл на месте",
            "Через xmlrpc перебирают пароли пачками. Отключите его, если не пользуетесь мобильным приложением WordPress или Jetpack.",
        ))
    if (root / "readme.html").is_file():
        found.append(_finding(
            "info",
            "readme-present",
            "readme.html показывает версию WordPress",
            "readme.html",
            "файл на месте",
            "Файл не дыра сам по себе, но сообщает точную версию. Его можно удалить.",
        ))
    config_path = site.config.path
    if config_path is not None and _world_readable(config_path):
        found.append(_finding(
            "high",
            "wp-config-readable",
            "wp-config.php доступен на чтение всем пользователям сервера",
            "wp-config.php",
            "в правах есть бит чтения для всех",
            "Поставьте права 640 или 600, чтобы другие аккаунты на хостинге не прочитали пароль базы.",
        ))
    for candidate in (config_path, root / ".htaccess", root / "wp-content"):
        if candidate is not None and _world_writable(candidate):
            found.append(_finding(
                "high",
                "world-writable",
                "Объект доступен на запись всем пользователям сервера",
                str(candidate.name),
                str(candidate),
                "Уберите права на запись для всех. Иначе соседний аккаунт на хостинге может подменить файл.",
            ))
    quarantine = root / "wp-content" / "wp-guard-quarantine"
    if quarantine.is_dir():
        files = [
            item for item in quarantine.rglob("*")
            if item.is_file() and item.name not in {".htaccess", "index.php", "README.txt"}
        ]
        if files:
            found.append(_finding(
                "info",
                "legacy-quarantine",
                "Внутри сайта остался старый каталог карантина",
                "wp-content/wp-guard-quarantine",
                f"файлов: {len(files)}",
                "Перенесите каталог за пределы public_html. Пока он внутри сайта, PHP из него теоретически можно запустить.",
            ))
    return found
