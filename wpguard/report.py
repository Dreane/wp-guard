"""Текстовый, JSON и CSV отчёт."""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import TextIO

from wpguard import __version__
from wpguard.models import SEVERITY_RANK, SiteReport

LABELS = {
    "critical": "КРИТИЧНО",
    "high": "ВЫСОКИЙ",
    "medium": "СРЕДНИЙ",
    "low": "НИЗКИЙ",
    "info": "СВЕДЕНИЕ",
}


def summary_line(report: SiteReport) -> str:
    counts = report.summary()
    parts = [f"{LABELS[name]} {counts[name]}" for name in SEVERITY_RANK if counts[name]]
    return "  ".join(parts) if parts else "замечаний нет"


def render_text(reports: list[SiteReport]) -> str:
    chunks: list[str] = [f"WPGuard {__version__}", ""]
    for report in reports:
        chunks.append(f"Сайт: {report.root}")
        chunks.append(f"Ядро: {report.core_version or 'не прочитано'}")
        stats = report.stats
        if stats:
            chunks.append(
                "Файлов просмотрено: {files}; плагинов: {plugins}; тем: {themes}".format(
                    files=stats.get("files_scanned", "—"),
                    plugins=stats.get("plugins", "—"),
                    themes=stats.get("themes", "—"),
                )
            )
        chunks.append(summary_line(report))
        chunks.append("")
        ordered = sorted(
            report.findings,
            key=lambda item: (SEVERITY_RANK.get(item.severity, 9), item.location, item.code),
        )
        for finding in ordered:
            chunks.append(f"[{LABELS.get(finding.severity, finding.severity)}] {finding.title}")
            chunks.append(f"  Где: {finding.location or '—'}")
            if finding.evidence:
                chunks.append(f"  Факт: {finding.evidence}")
            if finding.advice:
                chunks.append(f"  Что делать: {finding.advice}")
            chunks.append("")
        if report.actions:
            chunks.append("Действия:")
            for action in report.actions:
                state = "выполнено" if action.done else "план"
                if action.error:
                    state = "ошибка"
                line = f"  {state}: {action.kind} {action.location} — {action.reason}"
                chunks.append(line)
                if action.destination:
                    chunks.append(f"    копия: {action.destination}")
                if action.error:
                    chunks.append(f"    {action.error}")
            chunks.append("")
        chunks.append(
            "Темы wordpress.org не сверяются по контрольным суммам: такого API у каталога тем нет. "
            "Их файлы проверены правилами, а версии — открытой базой уязвимостей."
        )
        chunks.append("")
    return "\n".join(chunks).rstrip() + "\n"


def render_json(reports: list[SiteReport]) -> str:
    payload = {
        "tool": "wp-guard",
        "version": __version__,
        "sites": [
            {
                "root": report.root,
                "core": report.core_version,
                "summary": report.summary(),
                "stats": report.stats,
                "findings": [finding.to_dict() for finding in report.findings],
                "actions": [action.to_dict() for action in report.actions],
            }
            for report in reports
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_csv(reports: list[SiteReport]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["site", "severity", "category", "code", "location", "title", "evidence", "advice"])
    for report in reports:
        for finding in report.findings:
            writer.writerow([
                report.root,
                finding.severity,
                finding.category,
                finding.code,
                finding.location,
                finding.title,
                finding.evidence,
                finding.advice,
            ])
    return buffer.getvalue()


def render(reports: list[SiteReport], fmt: str) -> str:
    if fmt == "json":
        return render_json(reports)
    if fmt == "csv":
        return render_csv(reports)
    return render_text(reports)


def emit(reports: list[SiteReport], fmt: str, output: str | None, stream: TextIO | None = None) -> None:
    text = render(reports, fmt)
    if output:
        from pathlib import Path
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        print(f"Отчёт записан: {output}", file=sys.stderr)
    target = stream or sys.stdout
    target.write(text)
    if fmt != "text":
        for report in reports:
            print(f"{report.root}: {summary_line(report)}", file=sys.stderr)
