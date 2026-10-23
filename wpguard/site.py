"""Поиск установки WordPress, плагинов и тем."""

from __future__ import annotations

import os
import re
from pathlib import Path

from wpguard.models import Plugin, Site, Theme, WpConfig
from wpguard.wpconfig import load_wp_config, locale_of

SKIP_DIRS = {
    ".git",
    ".svn",
    "node_modules",
    "wp-guard-quarantine",
    "wp-guard-backups",
}
_VERSION = re.compile(r"""\$wp_version\s*=\s*(['"])([^'"]+)\1""")
_HEADER = re.compile(
    r"(?im)^\s*(?:\*\s*)?(?P<key>[A-Za-z][A-Za-z0-9 _-]*):\s*(?P<value>.+?)\s*$"
)


class SiteNotFound(Exception):
    pass


def header_map(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in _HEADER.finditer(text[:8192]):
        key = match.group("key").strip().lower()
        if key not in found:
            found[key] = match.group("value").strip()
    return found


def read_text_head(path: Path, limit: int = 8192) -> str:
    with path.open("rb") as handle:
        return handle.read(limit).decode("utf-8", errors="ignore")


def is_site(path: Path) -> bool:
    if not (path / "wp-includes" / "version.php").is_file():
        return False
    if (path / "wp-config.php").is_file():
        return True
    parent = path.parent / "wp-config.php"
    return parent.is_file()


def find_sites(path: Path, max_depth: int = 5) -> list[Path]:
    path = path.resolve()
    if not path.exists():
        raise SiteNotFound(f"Путь не существует: {path}")
    if path.is_file():
        path = path.parent
    if is_site(path):
        return [path]
    found: list[Path] = []
    for dirpath, dirnames, _filenames in os.walk(path):
        current = Path(dirpath)
        try:
            depth = len(current.relative_to(path).parts)
        except ValueError:
            depth = 0
        if depth > max_depth:
            dirnames.clear()
            continue
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        if is_site(current):
            found.append(current)
            dirnames.clear()
    if not found:
        raise SiteNotFound(
            "Не найдена установка WordPress. Нужны wp-includes/version.php и wp-config.php."
        )
    return found


def config_file(root: Path) -> Path | None:
    local = root / "wp-config.php"
    if local.is_file():
        return local
    parent = root.parent / "wp-config.php"
    if parent.is_file():
        return parent
    return None


def core_version(root: Path) -> str | None:
    version_file = root / "wp-includes" / "version.php"
    if not version_file.is_file():
        return None
    text = read_text_head(version_file, 16384)
    match = _VERSION.search(text)
    if not match:
        return None
    return match.group(2).strip()


def _plugin_from_header(path: Path, slug: str, kind: str) -> Plugin | None:
    headers = header_map(read_text_head(path))
    name = headers.get("plugin name")
    if not name:
        return None
    return Plugin(
        slug=slug,
        name=name,
        version=headers.get("version", "").strip(),
        path=path.parent if path.parent.name != "plugins" else path.parent,
        main_file=path,
        kind=kind,
        requires_php=headers.get("requires php", "").strip(),
    )


def _find_plugin_main(directory: Path) -> Plugin | None:
    preferred = directory / f"{directory.name}.php"
    candidates = []
    if preferred.is_file():
        candidates.append(preferred)
    for child in sorted(directory.glob("*.php")):
        if child not in candidates:
            candidates.append(child)
    for candidate in candidates:
        plugin = _plugin_from_header(candidate, directory.name, "plugin")
        if plugin is not None:
            plugin.path = directory
            return plugin
    return None


def discover_plugins(root: Path) -> list[Plugin]:
    base = root / "wp-content" / "plugins"
    plugins: list[Plugin] = []
    if not base.is_dir():
        return plugins
    for child in sorted(base.iterdir(), key=lambda item: item.name.lower()):
        if child.name.startswith(".") or child.name in SKIP_DIRS:
            continue
        if child.is_dir():
            plugin = _find_plugin_main(child)
            if plugin is None:
                plugins.append(Plugin(
                    slug=child.name,
                    name=child.name,
                    version="",
                    path=child,
                    main_file=None,
                    headerless=True,
                ))
            else:
                plugins.append(plugin)
        elif child.suffix.lower() == ".php":
            plugin = _plugin_from_header(child, child.stem, "plugin")
            if plugin is None:
                plugins.append(Plugin(
                    slug=child.stem,
                    name=child.name,
                    version="",
                    path=child,
                    main_file=child,
                    headerless=True,
                ))
            else:
                plugin.path = child
                plugins.append(plugin)
    return plugins


def discover_mu_plugins(root: Path) -> list[Plugin]:
    base = root / "wp-content" / "mu-plugins"
    found: list[Plugin] = []
    if not base.is_dir():
        return found
    for child in sorted(base.iterdir(), key=lambda item: item.name.lower()):
        if child.name.startswith("."):
            continue
        if child.is_file() and child.suffix.lower() == ".php":
            plugin = _plugin_from_header(child, child.stem, "mu-plugin")
            if plugin is None:
                plugin = Plugin(
                    slug=child.stem,
                    name=child.name,
                    version="",
                    path=child,
                    main_file=child,
                    kind="mu-plugin",
                    headerless=True,
                )
            else:
                plugin.path = child
                plugin.kind = "mu-plugin"
            found.append(plugin)
        elif child.is_dir():
            plugin = _find_plugin_main(child)
            if plugin is not None:
                plugin.kind = "mu-plugin"
                plugin.path = child
                found.append(plugin)
    return found


def discover_themes(root: Path) -> list[Theme]:
    base = root / "wp-content" / "themes"
    themes: list[Theme] = []
    if not base.is_dir():
        return themes
    for child in sorted(base.iterdir(), key=lambda item: item.name.lower()):
        style = child / "style.css"
        if not child.is_dir() or not style.is_file():
            continue
        headers = header_map(read_text_head(style))
        themes.append(Theme(
            slug=child.name,
            name=headers.get("theme name") or child.name,
            version=(headers.get("version") or "").strip(),
            path=child,
        ))
    return themes


def load_site(root: Path) -> Site:
    root = root.resolve()
    config_path = config_file(root)
    if config_path is None:
        config = WpConfig(path=None)
    else:
        config = load_wp_config(config_path)
    return Site(
        root=root,
        config=config,
        core_version=core_version(root),
        plugins=discover_plugins(root) + discover_mu_plugins(root),
        themes=discover_themes(root),
        locale=locale_of(config),
    )
