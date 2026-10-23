"""Фоновая проверка, которая не завершается вместе с сессией SSH."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import warnings
from datetime import datetime
from pathlib import Path

JOB_ENV = "WP_GUARD_JOB"
REPORT_NAME = "wp-guard-report.txt"


def default_report_path() -> Path:
    return Path.home() / REPORT_NAME


def resolve_report_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    return default_report_path()


def job_directory() -> Path:
    override = os.environ.get("WP_GUARD_STATE_DIR")
    path = Path(override) if override else Path.home() / ".cache" / "wp-guard"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _meta_path() -> Path:
    return job_directory() / "scan.json"


def _pid_path() -> Path:
    return job_directory() / "scan.pid"


def _log_path() -> Path:
    return job_directory() / "scan.log"


def child_argv(argv: list[str], output: Path) -> list[str]:
    cleaned = [arg for arg in argv if arg != "--background"]
    has_output = any(arg == "--output" or arg.startswith("--output=") for arg in cleaned)
    if not has_output:
        cleaned.extend(["--output", str(output)])
    if "--quiet" not in cleaned:
        cleaned.append("--quiet")
    return [sys.executable, "-m", "wpguard", *cleaned]


def _windows_process(pid: int):
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return ctypes.get_last_error(), None
    return 0, (kernel32, handle)


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        error, opened = _windows_process(pid)
        if opened is None:
            return error == 5
        kernel32, handle = opened
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _our_process(pid: int) -> bool:
    if not process_alive(pid):
        return False
    if os.name == "nt":
        import ctypes
        error, opened = _windows_process(pid)
        if opened is None:
            return error == 5
        kernel32, handle = opened
        try:
            buffer = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_uint32(1024)
            kernel32.QueryFullProcessImageNameW.argtypes = [
                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32),
            ]
            kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return True
            image = buffer.value.lower()
        finally:
            kernel32.CloseHandle(handle)
        return "python" in image or "wp-guard" in image or "wpguard" in image
    cmdline = Path(f"/proc/{pid}/cmdline")
    try:
        raw = cmdline.read_bytes()
    except OSError:
        return False
    return b"wpguard" in raw or b"wp-guard" in raw


def read_meta() -> dict | None:
    path = _meta_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def write_meta(data: dict) -> None:
    _meta_path().write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def running_pid() -> int | None:
    meta = read_meta()
    if not meta:
        return None
    try:
        pid = int(meta.get("pid") or 0)
    except (TypeError, ValueError):
        return None
    if _our_process(pid):
        return pid
    return None


def write_placeholder(report: Path, target: str) -> None:
    report.parent.mkdir(parents=True, exist_ok=True)
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.write_text(
        "\n".join([
            "WPGuard",
            "",
            "Проверка ещё идёт. Этот текст будет заменён готовым отчётом.",
            f"Начата: {started}",
            f"Сайт: {target}",
            "",
            "Статус: wp-guard status",
            "Остановить: wp-guard stop",
            "",
        ]),
        encoding="utf-8",
    )


def launch_detached(command: list[str], log_path: Path, env: dict[str, str]) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = open(log_path, "ab", buffering=0)
    try:
        kwargs = {
            "stdin": subprocess.DEVNULL,
            "stdout": log_handle,
            "stderr": subprocess.STDOUT,
            "env": env,
            "cwd": str(Path.home()),
            "close_fds": True,
        }
        if os.name == "nt":
            flags = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.CREATE_NO_WINDOW
            )
            process = subprocess.Popen(command, creationflags=flags, **kwargs)
        else:
            process = subprocess.Popen(command, start_new_session=True, **kwargs)
        pid = process.pid
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            del process
    finally:
        log_handle.close()
    return pid


def start_background(argv: list[str], output: Path, target: str) -> int:
    active = running_pid()
    if active is not None:
        meta = read_meta() or {}
        print(f"Проверка уже идёт, процесс {active}.")
        print(f"Отчёт: {meta.get('report') or output}")
        print("Статус: wp-guard status")
        return 0
    output = output.resolve()
    write_placeholder(output, target)
    log_path = _log_path()
    started = datetime.now().isoformat(timespec="seconds")
    log_path.write_text(
        f"WPGuard\nПроверка начата: {started}\nСайт: {target}\nОтчёт: {output}\n\n",
        encoding="utf-8",
    )
    meta = {
        "pid": 0,
        "state": "starting",
        "started": started,
        "report": str(output),
        "log": str(log_path),
        "target": target,
    }
    write_meta(meta)
    env = os.environ.copy()
    env[JOB_ENV] = str(_meta_path())
    package_root = str(Path(__file__).resolve().parent.parent)
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = package_root if not previous else package_root + os.pathsep + previous
    command = child_argv(argv, output)
    try:
        pid = launch_detached(command, log_path, env)
    except OSError as exc:
        meta["state"] = "finished"
        meta["exit_code"] = 1
        write_meta(meta)
        output.write_text(
            f"WPGuard\nПроверку не удалось запустить.\n{exc}\n",
            encoding="utf-8",
        )
        print(f"Не удалось запустить проверку: {exc}", file=sys.stderr)
        return 1
    current = read_meta() or meta
    current["pid"] = pid
    if current.get("state") == "starting":
        current["state"] = "running"
    write_meta(current)
    _pid_path().write_text(str(pid), encoding="utf-8")
    print("Проверка запущена в фоне, это окно можно закрыть.")
    print(f"Отчёт: {output}")
    print(f"Журнал: {log_path}")
    print("Пока проверка идёт, в файле отчёта написано, что она ещё не закончена.")
    print("Статус: wp-guard status")
    print("Остановить: wp-guard stop")
    return 0


def mark_finished(code: int) -> None:
    raw = os.environ.get(JOB_ENV)
    if not raw:
        return
    path = Path(raw)
    meta = {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            meta = loaded
    except (OSError, json.JSONDecodeError):
        pass
    meta["state"] = "finished"
    meta["exit_code"] = code
    meta["finished"] = datetime.now().isoformat(timespec="seconds")
    try:
        path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return


def status_text() -> str:
    meta = read_meta()
    report = default_report_path()
    if meta and meta.get("report"):
        report = Path(str(meta["report"]))
    pid = running_pid()
    lines = []
    if pid is not None:
        lines.append(f"Проверка идёт, процесс {pid}.")
        if meta:
            lines.append(f"Сайт: {meta.get('target', '')}")
            lines.append(f"Начата: {meta.get('started', '')}")
    elif meta and meta.get("state") == "running":
        lines.append("Проверка прервалась до записи готового отчёта.")
        lines.append(f"Журнал: {meta.get('log', _log_path())}")
    elif meta and meta.get("state") == "stopped":
        lines.append("Проверка остановлена.")
    elif meta and meta.get("state") == "finished":
        code = meta.get("exit_code")
        if code == 0:
            lines.append("Последняя проверка завершена: критичных и высоких замечаний нет.")
        elif code == 2:
            lines.append("Последняя проверка завершена: есть критичные или высокие замечания.")
        elif code == 130:
            lines.append("Последняя проверка прервана.")
        else:
            lines.append("Последняя проверка завершена с ошибкой.")
    else:
        lines.append("Проверка сейчас не выполняется.")
    lines.append(f"Отчёт: {report}")
    if report.is_file():
        modified = datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"Файл обновлён: {modified}")
    else:
        lines.append("Файл отчёта ещё не создан.")
    return "\n".join(lines)


def stop_background() -> int:
    meta = read_meta() or {}
    try:
        pid = int(meta.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if not _our_process(pid):
        print("Фоновая проверка не выполняется.")
        return 0
    os.kill(pid, signal.SIGTERM)
    meta["state"] = "stopped"
    meta["finished"] = datetime.now().isoformat(timespec="seconds")
    write_meta(meta)
    print(f"Остановлена проверка, процесс {pid}.")
    if meta.get("report"):
        print(f"Частичный отчёт: {meta['report']}")
    return 0
