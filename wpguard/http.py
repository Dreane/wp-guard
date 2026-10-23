"""HTTP-клиент с дисковым кэшем для wordpress.org и WPVulnerability."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "WPGuard/1.1 (local WordPress security scanner)"
DEFAULT_TTL = 12 * 60 * 60


class HttpError(Exception):
    def __init__(self, url: str, message: str, status: int | None = None):
        super().__init__(message)
        self.url = url
        self.status = status


class NotFound(HttpError):
    pass


class OfflineError(HttpError):
    def __init__(self, url: str = ""):
        super().__init__(url, "Сеть отключена параметром --offline")


class HttpClient:
    def __init__(
        self,
        cache_dir: Path,
        ttl: int = DEFAULT_TTL,
        refresh: bool = False,
        timeout: int = 30,
    ):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.refresh = refresh
        self.timeout = timeout
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_json(self, url: str) -> dict:
        body = self.get_bytes(url)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise HttpError(url, "Ответ не является JSON") from exc
        if not isinstance(payload, dict):
            raise HttpError(url, "Ожидался JSON-объект")
        if payload.get("error") in {1, "1"}:
            raise NotFound(url, str(payload.get("message") or "Объект не найден"), 404)
        return payload

    def get_bytes(self, url: str) -> bytes:
        cached = None if self.refresh else self._read_cache(url)
        if cached is not None:
            status, body = cached
            self._raise_for_status(url, status, body)
            return body
        status, body = self._fetch(url)
        self._write_cache(url, status, body)
        self._raise_for_status(url, status, body)
        return body

    def _fetch(self, url: str) -> tuple[int, bytes]:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read() if exc.fp is not None else b""
            return exc.code, body
        except urllib.error.URLError as exc:
            raise HttpError(url, f"Не удалось подключиться: {exc.reason}") from exc
        except TimeoutError as exc:
            raise HttpError(url, "Превышено время ожидания") from exc

    def _raise_for_status(self, url: str, status: int, body: bytes) -> None:
        if status == 404:
            raise NotFound(url, "Ресурс не найден", 404)
        if status >= 400:
            detail = body[:180].decode("utf-8", errors="replace")
            raise HttpError(url, f"HTTP {status}: {detail}", status)

    def _paths(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{key}.meta", self.cache_dir / f"{key}.body"

    def _read_cache(self, url: str) -> tuple[int, bytes] | None:
        meta_path, body_path = self._paths(url)
        if not meta_path.is_file() or not body_path.is_file():
            return None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if meta.get("url") != url:
            return None
        fetched = float(meta.get("fetched") or 0)
        if time.time() - fetched > self.ttl:
            return None
        try:
            return int(meta.get("status") or 0), body_path.read_bytes()
        except OSError:
            return None

    def _write_cache(self, url: str, status: int, body: bytes) -> None:
        if len(body) > 80 * 1024 * 1024:
            return
        meta_path, body_path = self._paths(url)
        temporary = body_path.with_suffix(".body.tmp")
        temporary.write_bytes(body)
        temporary.replace(body_path)
        meta_path.write_text(
            json.dumps({"url": url, "fetched": time.time(), "status": status}),
            encoding="utf-8",
        )
