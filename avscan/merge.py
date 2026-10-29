"""把多次运行的结果合并成一份总报告。

现实约束：9 款消费级杀软不可能长时间共存（驱动冲突、互相报毒、Defender 被降级）。
实际做法是「装一款 → 扫 → 卸 → 换下一款」，于是同一批目标会散落在多个 run 目录里。
这个模块负责把它们收拢成一份可用于发布的单一报告。

合并规则：同一引擎出现多次时取**最严重**的结论（保守优先），并标注来源 run。
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

from .report import SEVERITY


def _load_run(run_dir: Path) -> tuple[dict, list[dict]]:
    meta_path = run_dir / "meta.json"
    results_path = run_dir / "results.json"
    if not meta_path.is_file() or not results_path.is_file():
        raise FileNotFoundError(f"{run_dir} 不是有效运行目录（缺 meta.json / results.json）")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    results = json.loads(results_path.read_text(encoding="utf-8"))
    return meta, results


def merge_runs(run_dirs: list[Path], out_dir: Path, label: str = "") -> tuple[Path, list[str]]:
    """返回 (合并后的运行目录, 警告列表)。"""
    runs: list[tuple[Path, dict, list[dict]]] = []
    for d in run_dirs:
        meta, results = _load_run(d)
        runs.append((d, meta, results))

    warnings: list[str] = []

    # 目标一致性：不同批次的扫描目标不能混在一张报告里
    signature = {tuple(sorted(str(t.get("path", "")) for t in m.get("targets", []))) for _, m, _ in runs}
    if len(signature) > 1:
        warnings.append(
            "各次运行的目标集合不一致，合并后的报告不能作为单一批次的扫毒结论，请确认。"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    merged_raw = out_dir / "raw"
    merged_raw.mkdir(exist_ok=True)

    best: dict[str, dict] = {}
    sources: dict[str, str] = {}

    for run_dir, meta, results in runs:
        tag = str(meta.get("run_id", run_dir.name))
        raw_src = run_dir / "raw"
        raw_dst = merged_raw / tag
        if raw_src.is_dir():
            if raw_dst.exists():
                shutil.rmtree(raw_dst, ignore_errors=True)
            shutil.copytree(raw_src, raw_dst)
        else:
            raw_dst.mkdir(parents=True, exist_ok=True)

        for r in results:
            key = r.get("engine")
            if not key:
                continue
            # 重写日志路径指向合并后的位置
            old_log = r.get("stdout_path")
            if old_log:
                candidate = raw_dst / Path(old_log).name
                r = dict(r)
                r["stdout_path"] = str(candidate) if candidate.exists() else None
                r["source_run"] = tag

            prev = best.get(key)
            if prev is None or SEVERITY.get(r.get("status", ""), 0) > SEVERITY.get(prev.get("status", ""), 0):
                best[key] = r
                sources[key] = tag

    # 人工回填优先合并（后写覆盖先写）
    manual: dict = {}
    for run_dir, _, _ in runs:
        path = run_dir / "manual_results.json"
        if path.is_file():
            try:
                manual.update(json.loads(path.read_text(encoding="utf-8-sig")))
            except (OSError, json.JSONDecodeError):
                warnings.append(f"{run_dir.name}/manual_results.json 解析失败，已忽略。")

    targets_meta = runs[0][1].get("targets", []) if runs else []
    file_total = sum(t.get("file_count", 0) for t in targets_meta)
    byte_total = sum(t.get("total_bytes", 0) for t in targets_meta)

    merged_meta = {
        "run_id": out_dir.name,
        "label": label or runs[0][1].get("label", "") if runs else label,
        "created_at": min((m.get("created_at", "") for _, m, _ in runs), default=""),
        "finished_at": max((m.get("finished_at", "") for _, m, _ in runs), default=""),
        "merged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": runs[0][1].get("mode", "dir") if runs else "dir",
        "dry_run": any(m.get("dry_run") for _, m, _ in runs),
        "timeout": max((m.get("timeout", 0) for _, m, _ in runs), default=0),
        "targets": targets_meta,
        "target_files": file_total,
        "target_bytes": byte_total,
        "engines": list(best.keys()),
        "source_runs": [str(m.get("run_id", d.name)) for d, m, _ in runs],
        "hostname": runs[0][1].get("hostname", "") if runs else "",
        "os_version": runs[0][1].get("os_version", "") if runs else "",
        "python": runs[0][1].get("python", "") if runs else "",
        "tool_version": runs[0][1].get("tool_version", "") if runs else "",
        "run_dir": str(out_dir),
    }

    (out_dir / "meta.json").write_text(
        json.dumps(merged_meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "results.json").write_text(
        json.dumps(list(best.values()), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if manual:
        (out_dir / "manual_results.json").write_text(
            json.dumps(manual, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    return out_dir, warnings
