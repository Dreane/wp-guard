"""Командная строка WPGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from wpguard import __version__
from wpguard.background import mark_finished, resolve_report_path, start_background, status_text, stop_background
from wpguard.http import HttpClient
from wpguard.models import Options, worst_exit_code
from wpguard.remediate import apply_actions, plan
from wpguard.report import emit
from wpguard.scan import cache_directory, scan_path, scan_site
from wpguard.site import SiteNotFound, find_sites, load_site


SECTIONS = {
    "scan": {"surface", "malware", "integrity", "vuln", "database"},
    "malware-scan": {"surface", "malware"},
    "integrity-scan": {"integrity"},
    "vuln-scan": {"vuln"},
    "db-scan": {"database"},
}


def _prepare_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", help="Каталог с WordPress или каталог, где его нужно найти")
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--output", help="Записать отчёт в файл")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--offline", action="store_true", help="Не обращаться в интернет")
    parser.add_argument("--refresh", action="store_true", help="Не использовать кэш ответов")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--php-version", help="Версия PHP сайта, например 8.3.16")
    parser.add_argument("--max-file-mb", type=float, default=8)
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"], default="info")
    parser.add_argument("--cache-dir")
    parser.add_argument("--db-host")
    parser.add_argument("--db-port", type=int)
    parser.add_argument("--db-name")
    parser.add_argument("--db-user")
    parser.add_argument("--db-password", help="Лучше задать переменную WP_GUARD_DB_PASSWORD")
    parser.add_argument("--db-prefix")


def _options(args: argparse.Namespace, command: str) -> Options:
    return Options(
        workers=max(1, args.workers),
        offline=args.offline,
        refresh=args.refresh,
        quiet=args.quiet or not sys.stderr.isatty(),
        php_version=args.php_version,
        max_bytes=int(args.max_file_mb * 1024 * 1024),
        min_severity=args.min_severity,
        sections=set(SECTIONS.get(command, SECTIONS["scan"])),
        cache_dir=Path(args.cache_dir) if args.cache_dir else None,
        db_host=args.db_host,
        db_port=args.db_port,
        db_name=args.db_name,
        db_user=args.db_user,
        db_password=args.db_password,
        db_prefix=args.db_prefix,
        apply=getattr(args, "apply", False),
        quarantine=getattr(args, "quarantine", False),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-guard",
        description="Локальный сканер безопасности WordPress. Файлы сайта никуда не отправляются.",
    )
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")
    for name, help_text in (
        ("scan", "Полная проверка: файлы, суммы, уязвимости и база"),
        ("malware-scan", "Правила, эвристика и опасные места на диске"),
        ("integrity-scan", "Сверка ядра и плагинов wordpress.org"),
        ("vuln-scan", "Известные уязвимости версий"),
        ("db-scan", "Администраторы, настройки, записи и cron"),
    ):
        command = sub.add_parser(name, help=help_text)
        _common(command)
        command.add_argument(
            "--background",
            action="store_true",
            help="Продолжить проверку после закрытия SSH. Отчёт пишется в файл",
        )
    remediate = sub.add_parser("remediate", help="Вернуть официальные файлы и вынести опасные из сайта")
    _common(remediate)
    remediate.add_argument("--apply", action="store_true", help="Записать изменения. Без флага только план")
    remediate.add_argument("--quarantine", action="store_true", help="Перенести опасные файлы за пределы сайта")
    sub.add_parser("version", help="Версия программы")
    sub.add_parser("status", help="Показать, идёт ли фоновая проверка, и где лежит отчёт")
    sub.add_parser("stop", help="Остановить фоновую проверку")
    return parser


def run(argv: list[str] | None = None) -> int:
    code = 1
    try:
        code = _execute(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        raise
    finally:
        mark_finished(code)
    return code


def _execute(argv: list[str] | None = None) -> int:
    _prepare_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version or args.command == "version":
        print(f"WPGuard {__version__}")
        return 0
    if args.command == "status":
        print(status_text())
        return 0
    if args.command == "stop":
        return stop_background()
    if not args.command:
        parser.print_help()
        return 0
    if not args.path:
        parser.error("укажите каталог сайта")
    if getattr(args, "background", False):
        source = list(argv) if argv is not None else sys.argv[1:]
        return start_background(source, resolve_report_path(args.output), args.path)
    if args.db_password:
        print(
            "Пароль передан аргументом. На общем сервере его видно в списке процессов. "
            "Надёжнее переменная WP_GUARD_DB_PASSWORD.",
            file=sys.stderr,
        )
    if not args.output:
        args.output = str(resolve_report_path(None))
    options = _options(args, "scan" if args.command == "remediate" else args.command)
    if args.command == "remediate":
        options.sections = {"malware", "integrity"}
    try:
        if args.command == "remediate":
            return _remediate(Path(args.path), options, args)
        _sites, reports = scan_path(Path(args.path), options)
    except SiteNotFound as exc:
        _write_failure(args.output, str(exc))
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        _write_failure(args.output, "Проверка прервана.")
        return 130
    except Exception as exc:
        import traceback
        traceback.print_exc()
        _write_failure(args.output, f"Проверка остановилась с ошибкой.\n{exc}")
        return 1
    emit(reports, args.format, args.output)
    return worst_exit_code([finding for report in reports for finding in report.findings])


def _write_failure(output: str | None, message: str) -> None:
    if not output:
        return
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(f"WPGuard\n{message}\n", encoding="utf-8")


def _remediate(path: Path, options: Options, args: argparse.Namespace) -> int:
    client = None if options.offline else HttpClient(cache_directory(options), refresh=options.refresh)
    reports = []
    for root in find_sites(path):
        site = load_site(root)
        report = scan_site(site, options, client)
        actions = plan(report.findings, site, options.quarantine)
        if options.apply:
            apply_actions(actions, report.findings, site, client, cache_directory(options))
        report.actions = actions
        reports.append(report)
    emit(reports, args.format, args.output)
    failed = any(action.error for report in reports for action in report.actions)
    if failed and options.apply:
        return 1
    return worst_exit_code([finding for report in reports for finding in report.findings])


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))


if __name__ == "__main__":
    main()
