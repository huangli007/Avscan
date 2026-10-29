"""扫描管道：无交互、无打印，供 CLI 与 GUI 共用。

把「探测引擎 → 解析目标 → 逐个执行 → 写报告」串成一个可调用函数，
进度通过回调抛给上层（CLI 打终端，GUI 刷界面），取消通过 should_cancel 轮询。
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import __version__
from .engines import EngineStatus, probe_all, select_engines
from .report import publish_reports
from .runner import run_target
from .runtime import app_dir
from .targets import RISK_EXTS, TargetSet, build_target_set, human_bytes

ProgressFn = Callable[[str, str], None]
CancelFn = Callable[[], bool]
DEFAULT_RUNS_DIR = app_dir() / "runs"


def _slugify(text: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_" else "-" for c in text.strip())
    return "-".join(filter(None, cleaned.split("-")))[:40].strip("-")


@dataclass
class ScanPlan:
    """执行前的计划快照，供界面预检与用户确认。"""

    target_set: TargetSet
    statuses: list[EngineStatus]
    runnable: list[EngineStatus] = field(default_factory=list)
    manual_only: list[EngineStatus] = field(default_factory=list)
    missing: list[EngineStatus] = field(default_factory=list)

    @property
    def has_engine(self) -> bool:
        return bool(self.runnable or self.manual_only)

    @property
    def file_total(self) -> int:
        return self.target_set.file_total

    @property
    def byte_total(self) -> int:
        return self.target_set.byte_total

    @property
    def size_text(self) -> str:
        return human_bytes(self.byte_total)


@dataclass
class ScanOutcome:
    run_id: str
    run_dir: Path
    verdict: str
    results: list[dict]
    meta: dict
    report_md: Path | None = None
    cancelled: bool = False

    @property
    def report_dir(self) -> Path:
        return self.run_dir


def build_plan(
    targets: list[str],
    engines: str = "auto",
    *,
    per_file: bool = False,
    only_risk: bool = False,
) -> ScanPlan:
    """解析目标并探测引擎。抛 ValueError / FileNotFoundError 由上层处理。"""
    engine_list = select_engines(engines)
    use_per_file = per_file or only_risk
    target_set = build_target_set(
        targets,
        per_file=use_per_file,
        extensions=RISK_EXTS if only_risk else None,
    )
    statuses = probe_all(engine_list)
    return ScanPlan(
        target_set=target_set,
        statuses=statuses,
        runnable=[s for s in statuses if s.runnable],
        manual_only=[s for s in statuses if s.installed and s.engine.tier == "manual"],
        missing=[s for s in statuses if not s.installed],
    )


def run_scan(
    plan: ScanPlan,
    *,
    label: str = "",
    timeout: int = 1800,
    dry_run: bool = False,
    out_root: Path | None = None,
    run_id: str = "",
    on_progress: ProgressFn | None = None,
    should_cancel: CancelFn | None = None,
) -> ScanOutcome:
    """执行扫描并产出报告。on_progress(stage, message) 的 stage 取值：

    start / engine_start / engine_done / engine_skip / done / cancel
    """

    def emit(stage: str, message: str = "") -> None:
        if on_progress is not None:
            on_progress(stage, message)

    def cancelled() -> bool:
        return bool(should_cancel and should_cancel())

    rid = run_id or (
        "RUN-" + datetime.now().strftime("%Y%m%d-%H%M%S") + (f"-{_slugify(label)}" if label else "")
    )
    root = Path(out_root).resolve() if out_root else DEFAULT_RUNS_DIR
    run_dir = root / rid
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "run_id": rid,
        "label": label,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": "",
        "mode": plan.target_set.mode,
        "dry_run": bool(dry_run),
        "timeout": timeout,
        "targets": [t.to_dict() for t in plan.target_set.targets],
        "engines": [s.key for s in plan.statuses],
        "hostname": platform.node(),
        "os_version": f"{platform.system()} {platform.release()} {platform.version()}",
        "python": platform.python_version(),
        "tool_version": __version__,
        "run_dir": str(run_dir),
    }

    results: list[dict] = []
    was_cancelled = False
    total = len(plan.statuses)

    emit("start", f"{len(plan.target_set.targets)} 个目标 / {plan.file_total} 个文件 / {plan.size_text}")

    for idx, status in enumerate(plan.statuses, 1):
        if cancelled():
            was_cancelled = True
            break
        if not status.installed:
            continue

        engine = status.engine
        emit("engine_start", f"[{idx}/{total}] {engine.display}")

        if engine.tier == "manual":
            result = run_target(status, plan.target_set.targets[0], raw_dir, timeout=timeout)
            results.append(result.to_dict())
            emit("engine_skip", f"{engine.display}：仅 GUI，已写入核对单")
            continue

        if not status.ready:
            result = run_target(status, plan.target_set.targets[0], raw_dir, timeout=timeout)
            results.append(result.to_dict())
            emit("engine_skip", f"{engine.display}：{status.reason}")
            continue

        for i, target in enumerate(plan.target_set.targets):
            if cancelled():
                was_cancelled = True
                break
            result = run_target(
                status, target, raw_dir, timeout=timeout, dry_run=dry_run, index=i
            )
            results.append(result.to_dict())

        if results:
            last = results[-1]
            emit(
                "engine_done",
                f"{engine.display}：{last.get('status')} · {last.get('duration_sec')}s",
            )

    meta["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    (run_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (run_dir / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    verdict, report_md = publish_reports(run_dir, meta, results)
    emit("cancel" if was_cancelled else "done", verdict)

    return ScanOutcome(
        run_id=rid,
        run_dir=run_dir,
        verdict=verdict,
        results=results,
        meta=meta,
        report_md=report_md,
        cancelled=was_cancelled,
    )


VERDICT_TEXT = {
    "pass": "所有已执行引擎均未发现威胁",
    "fail": "存在检出，详见引擎明细",
    "incomplete": "有引擎未取得结论，无法判定通过",
    "pending": "人工引擎尚未回填，无法判定通过",
    "dryrun": "演练完成，未实际扫描",
    "empty": "无数据",
}
