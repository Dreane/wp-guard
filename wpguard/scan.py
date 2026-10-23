"""Сборка проверки сайта."""

from __future__ import annotations

import os
from pathlib import Path

from wpguard.database import scan as scan_database
from wpguard.http import HttpClient
from wpguard.integrity import scan as scan_integrity
from wpguard.malware import scan as scan_malware
from wpguard.models import Finding, Options, Site, SiteReport, keep
from wpguard.site import find_sites, load_site
from wpguard.surface import inspect as inspect_surface
from wpguard.vulns import scan as scan_vulns


def cache_directory(options: Options) -> Path:
    if options.cache_dir is not None:
        return options.cache_dir
    return Path.home() / ".cache" / "wp-guard"


def apply_db_overrides(site: Site, options: Options) -> None:
    config = site.config
    if options.db_host:
        config.db_host = options.db_host
    if options.db_port:
        config.db_port = options.db_port
    if options.db_name:
        config.db_name = options.db_name
    if options.db_user:
        config.db_user = options.db_user
    if options.db_prefix:
        config.table_prefix = options.db_prefix
    if options.db_password:
        config.db_password = options.db_password
        config.password_is_literal = True
    elif not config.db_password:
        env_password = os.environ.get("WP_GUARD_DB_PASSWORD")
        if env_password:
            config.db_password = env_password
            config.password_is_literal = True


def scan_site(site: Site, options: Options, client: HttpClient | None) -> SiteReport:
    apply_db_overrides(site, options)
    findings: list[Finding] = []
    stats = {
        "plugins": len([plugin for plugin in site.plugins if plugin.kind == "plugin"]),
        "mu_plugins": len([plugin for plugin in site.plugins if plugin.kind == "mu-plugin"]),
        "themes": len(site.themes),
        "files_scanned": 0,
    }
    if "surface" in options.sections:
        findings.extend(inspect_surface(site))
    if "malware" in options.sections:
        malware_findings, malware_stats = scan_malware(
            site,
            workers=options.workers,
            max_bytes=options.max_bytes,
            quiet=options.quiet,
        )
        findings.extend(malware_findings)
        stats["files_scanned"] = malware_stats.get("files_scanned", 0)
    if "integrity" in options.sections:
        findings.extend(scan_integrity(site, client, options.workers))
    if "vuln" in options.sections:
        findings.extend(scan_vulns(site, client, options.php_version, options.workers))
    if "database" in options.sections:
        findings.extend(scan_database(site, client))
    visible = [finding for finding in findings if keep(finding, options.min_severity)]
    return SiteReport(
        root=str(site.root),
        core_version=site.core_version,
        findings=visible,
        stats=stats,
    )


def scan_path(path: Path, options: Options) -> tuple[list[Site], list[SiteReport]]:
    sites = [load_site(root) for root in find_sites(path)]
    client = None
    if not options.offline:
        client = HttpClient(cache_directory(options), refresh=options.refresh)
    reports = [scan_site(site, options, client) for site in sites]
    return sites, reports
