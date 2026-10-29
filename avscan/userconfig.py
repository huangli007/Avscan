"""用户配置：引擎可执行文件的路径覆盖。

解决两类现实问题：
  1. 引擎装在非标准目录，自动探测的 probes 匹配不到；
  2. 探测到的路径不对（多版本、绿色版挪过位置），启动即失败。

覆盖优先于自动探测。配置写在 exe 同级的 config/engines.json，
目录不可写时退回 %APPDATA%\\avscan\\config。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .runtime import app_dir

_cache: dict[str, str] | None = None


def config_dir() -> Path:
    """优先用程序目录（便携），不可写时退回用户 AppData。"""
    candidate = app_dir() / "config"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        probe = candidate / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return candidate
    except OSError:
        fallback = Path(os.environ.get("APPDATA") or Path.home()) / "avscan" / "config"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def config_file() -> Path:
    return config_dir() / "engines.json"


def _read() -> dict:
    path = config_file()
    if not path.is_file():
        return {"overrides": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {"overrides": {}}
    if not isinstance(data, dict):
        return {"overrides": {}}
    data.setdefault("overrides", {})
    return data


def _write(data: dict) -> None:
    path = config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    global _cache
    _cache = None


def load_overrides() -> dict[str, str]:
    """返回 {引擎 key: 可执行文件路径}。"""
    global _cache
    if _cache is None:
        overrides = _read().get("overrides", {})
        _cache = {k: v for k, v in overrides.items() if isinstance(v, str) and v.strip()}
    return dict(_cache)


def get_override(key: str) -> str | None:
    return load_overrides().get(key.strip().lower())


def set_override(key: str, path: str | None) -> Path:
    """设置或清除某引擎的启动路径。path 为 None/空 表示清除。"""
    data = _read()
    overrides: dict = data.setdefault("overrides", {})
    key = key.strip().lower()

    if path is None or not str(path).strip():
        overrides.pop(key, None)
    else:
        overrides[key] = str(Path(path).expanduser().resolve())

    _write(data)
    return config_file()


def describe() -> list[dict]:
    """列出当前所有覆盖项及其文件是否存在（供界面展示）。"""
    rows: list[dict] = []
    for key, path in sorted(load_overrides().items()):
        p = Path(path)
        rows.append(
            {
                "engine": key,
                "path": path,
                "exists": p.is_file(),
                "suffix_ok": p.suffix.lower() in (".exe", ".com", ".bat", ".cmd"),
            }
        )
    return rows
