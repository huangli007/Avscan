"""扫描执行器：串行调用各引擎 CLI，落盘原始输出，解析成统一结论。

串行是刻意的：多个杀软同时扫同一批文件会互相抢 IO/CPU，且部分引擎有全局锁，
并发反而更慢、更容易互相干扰授权状态。
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .engines import (
    ERROR,
    MANUAL,
    SKIPPED,
    STATUS_LABEL,
    TIMEOUT,
    UNKNOWN,
    EngineStatus,
)
from .targets import Target


@dataclass
class ScanResult:
    engine: str
    display: str
    vendor: str
    tier: str
    status: str
    target: str
    target_kind: str
    target_files: int
    target_bytes: int
    exit_code: int | None = None
    detections: list[dict] = field(default_factory=list)
    message: str = ""
    duration_sec: float = 0.0
    cmdline: str = ""
    stdout_path: str | None = None
    engine_version: str | None = None
    db_version: str | None = None
    db_date: str | None = None
    started_at: str = ""
    finished_at: str = ""

    @property
    def label(self) -> str:
        return STATUS_LABEL.get(self.status, self.status)

    def to_dict(self) -> dict:
        return asdict(self)


def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp936"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _kill_tree(pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_target(
    status: EngineStatus,
    target: Target,
    raw_dir: Path,
    *,
    timeout: int,
    dry_run: bool = False,
    index: int = 0,
) -> ScanResult:
    engine = status.engine
    base = ScanResult(
        engine=engine.key,
        display=engine.display,
        vendor=engine.vendor,
        tier=engine.tier,
        status=SKIPPED,
        target=str(target.path),
        target_kind=target.kind,
        target_files=target.file_count,
        target_bytes=target.total_bytes,
        engine_version=status.version,
        db_version=status.db_version,
        db_date=status.db_date,
    )

    if engine.tier == "manual":
        base.status = MANUAL
        base.message = engine.gui_hint or "在 GUI 内指定该目录扫描"
        return base

    if not status.ready or status.exe is None or engine.build is None:
        base.status = ERROR
        base.message = f"引擎不可用：{status.reason}"
        return base

    argv = engine.build(status.exe, target.path, raw_dir)

    if engine.key == "malwarebytes":
        # mbam.exe 不支持指定路径，明确提示而不是假装扫过了
        base.status = ERROR
        base.message = "Malwarebytes 免费版不支持命令行定向扫描，请改为人工扫描"
        base.cmdline = subprocess.list2cmdline(argv)
        return base

    base.cmdline = subprocess.list2cmdline(argv)

    if dry_run:
        base.status = SKIPPED
        base.message = "dry-run：仅生成命令，未执行"
        return base

    stdout_file = raw_dir / f"{engine.key}__{index:04d}.stdout.txt"
    stderr_file = raw_dir / f"{engine.key}__{index:04d}.stderr.txt"

    base.started_at = _now()
    started = time.monotonic()

    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(raw_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except (OSError, ValueError) as exc:
        base.status = ERROR
        base.message = f"启动失败：{exc}"
        base.finished_at = _now()
        base.duration_sec = time.monotonic() - started
        return base

    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc.pid)
        try:
            out, err = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            out, err = b"", b""

    base.duration_sec = round(time.monotonic() - started, 1)
    base.finished_at = _now()
    base.exit_code = proc.returncode

    stdout_text = _decode(out)
    stderr_text = _decode(err)

    try:
        stdout_file.write_text(stdout_text, encoding="utf-8")
        stderr_file.write_text(stderr_text, encoding="utf-8")
        base.stdout_path = str(stdout_file)
    except OSError:
        base.stdout_path = None

    if timed_out:
        base.status = TIMEOUT
        base.message = f"超过 {timeout}s 未完成，已终止（不视为无毒）"
        return base

    if engine.parse is None:
        base.status = UNKNOWN
        base.message = "缺少结果解析器"
        return base

    try:
        verdict, detections, message = engine.parse(
            stdout_text, stderr_text, proc.returncode, raw_dir
        )
    except Exception as exc:  # noqa: BLE001 - 解析异常不能污染结论
        base.status = UNKNOWN
        base.message = f"结果解析异常：{exc}"
        return base

    base.status = verdict
    base.detections = detections
    base.message = message
    return base


def run_engine(
    status: EngineStatus,
    targets: list[Target],
    raw_dir: Path,
    *,
    timeout: int,
    dry_run: bool = False,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    for i, target in enumerate(targets):
        results.append(
            run_target(status, target, raw_dir, timeout=timeout, dry_run=dry_run, index=i)
        )
    return results


def dump_result(path: Path, result: ScanResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
