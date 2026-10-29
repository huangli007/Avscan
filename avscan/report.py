"""报告生成：把逐引擎结果聚合、判级，输出 Markdown / CSV / JSON 三种形态。

Markdown 直接可贴进测试报告；CSV 用 UTF-8 BOM 保证 Excel 打开不乱码。
"""

from __future__ import annotations

import csv
import io
import json
from collections import OrderedDict
from pathlib import Path

from .engines import CLEAN, ERROR, INFECTED, MANUAL, SKIPPED, STATUS_LABEL, TIMEOUT, UNKNOWN
from .targets import human_bytes

# 严重度：数字越大越需要关注
SEVERITY = {
    INFECTED: 6,
    ERROR: 5,
    UNKNOWN: 4,
    TIMEOUT: 3,
    MANUAL: 2,
    CLEAN: 1,
    SKIPPED: 0,
}

STATUS_ICON = {
    CLEAN: "✅ 无毒",
    INFECTED: "❌ 检出",
    ERROR: "⚠️ 失败",
    UNKNOWN: "⚠️ 未知",
    TIMEOUT: "⚠️ 超时",
    MANUAL: "⬜ 待人工",
    SKIPPED: "⏭ 跳过",
}

TIER_LABEL = {"auto": "自动", "manual": "人工"}


def aggregate(results: list[dict]) -> OrderedDict:
    """同一引擎的多条结果（逐文件模式）合并成一条。"""
    grouped: OrderedDict[str, dict] = OrderedDict()
    for r in results:
        key = r["engine"]
        if key not in grouped:
            grouped[key] = {
                "engine": key,
                "display": r["display"],
                "vendor": r["vendor"],
                "tier": r["tier"],
                "status": r["status"],
                "engine_version": r.get("engine_version"),
                "db_version": r.get("db_version"),
                "db_date": r.get("db_date"),
                "detections": list(r.get("detections") or []),
                "duration_sec": r.get("duration_sec") or 0.0,
                "targets": 1,
                "files": r.get("target_files") or 0,
                "bytes": r.get("target_bytes") or 0,
                "messages": [r.get("message")] if r.get("message") else [],
                "exit_codes": [r.get("exit_code")],
                "logs": [r["stdout_path"]] if r.get("stdout_path") else [],
            }
            continue

        agg = grouped[key]
        if SEVERITY.get(r["status"], 0) > SEVERITY.get(agg["status"], 0):
            agg["status"] = r["status"]
        agg["detections"].extend(r.get("detections") or [])
        agg["duration_sec"] = round((agg["duration_sec"] or 0) + (r.get("duration_sec") or 0), 1)
        agg["targets"] += 1
        agg["files"] += r.get("target_files") or 0
        agg["bytes"] += r.get("target_bytes") or 0
        if r.get("message"):
            agg["messages"].append(r["message"])
        agg["exit_codes"].append(r.get("exit_code"))
        if r.get("stdout_path"):
            agg["logs"].append(r["stdout_path"])
        agg["db_version"] = agg["db_version"] or r.get("db_version")
        agg["db_date"] = agg["db_date"] or r.get("db_date")

    return grouped


def verdict_of(agg: OrderedDict) -> tuple[str, str]:
    """返回 (结论枚举, 一句话说明)。"""
    statuses = [v["status"] for v in agg.values()]
    if not statuses:
        return "empty", "没有任何扫描结果"
    if statuses.count(INFECTED):
        return "fail", f"{statuses.count(INFECTED)} 个引擎报告检出"
    blockers = [s for s in statuses if s in (ERROR, UNKNOWN, TIMEOUT)]
    if blockers:
        return "incomplete", f"{len(blockers)} 个引擎未能给出明确结论"
    if MANUAL in statuses:
        return "pending", "全自动引擎均无检出，仍有引擎待人工补扫"
    skipped = statuses.count(SKIPPED)
    if skipped == len(statuses):
        return "dryrun", "仅 dry-run，未实际扫描"
    return "pass", "所有已执行引擎均未发现威胁"


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(meta: dict, agg: OrderedDict) -> str:
    verdict, verdict_text = verdict_of(agg)
    verdict_label = {
        "pass": "通过",
        "fail": "不通过（存在检出）",
        "incomplete": "不通过（未完成全量验证）",
        "pending": "待补（人工引擎未回填）",
        "dryrun": "演练，无实际结论",
        "empty": "无数据",
    }[verdict]

    total_files = sum(t.get("file_count", 0) for t in meta.get("targets", []))
    total_bytes = sum(t.get("total_bytes", 0) for t in meta.get("targets", []))

    lines: list[str] = []
    lines.append("# 多引擎批量扫毒报告")
    lines.append("")
    lines.append(f"- **任务编号**：`{meta.get('run_id', '-')}`")
    if meta.get("label"):
        lines.append(f"- **任务标签**：{meta['label']}")
    lines.append(f"- **执行时间**：{meta.get('created_at', '-')} → {meta.get('finished_at', '-')}")
    lines.append(f"- **扫描模式**：{'逐文件' if meta.get('mode') == 'file' else '整目录'}")
    lines.append(
        f"- **扫描目标**：{len(meta.get('targets', []))} 项，"
        f"{total_files} 个文件 / {human_bytes(total_bytes)}"
    )
    if meta.get("dry_run"):
        lines.append("- **注意**：本次为 dry-run 演练，仅生成命令未实际执行")
    lines.append("")

    lines.append("## 总体结论")
    lines.append("")
    lines.append(f"> **{verdict_label}** — {verdict_text}")
    lines.append("")

    counts = {s: 0 for s in (CLEAN, INFECTED, ERROR, UNKNOWN, TIMEOUT, MANUAL, SKIPPED)}
    for v in agg.values():
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    summary = " ｜ ".join(
        f"{STATUS_LABEL[s]} {counts[s]}" for s in counts if counts[s]
    )
    lines.append(f"引擎合计 {len(agg)} 个：{summary}")
    lines.append("")

    lines.append("## 引擎结果矩阵")
    lines.append("")
    lines.append(
        "| # | 引擎 | 类型 | 版本 | 病毒库 | 病毒库日期 | 状态 | 检出 | 耗时 | 说明 |"
    )
    lines.append(
        "|---|---|---|---|---|---|---|---|---|---|"
    )
    for i, v in enumerate(agg.values(), 1):
        notes = "；".join(dict.fromkeys(m for m in v["messages"] if m))
        if len(v["detections"]) and v["status"] == INFECTED:
            names = ", ".join(d.get("threat", "") for d in v["detections"][:3])
            notes = f"检出：{names}" + (f"（共 {len(v['detections'])} 项）" if len(v["detections"]) > 3 else "")
        lines.append(
            "| {i} | {name} | {tier} | {v} | {db} | {dbd} | {st} | {n} | {t} | {note} |".format(
                i=i,
                name=_md_escape(v["display"]),
                tier=TIER_LABEL.get(v["tier"], v["tier"]),
                v=_md_escape(v["engine_version"] or "-"),
                db=_md_escape(v["db_version"] or "-"),
                dbd=_md_escape(v["db_date"] or "-"),
                st=STATUS_ICON.get(v["status"], v["status"]),
                n=len(v["detections"]),
                t=_fmt_duration(v["duration_sec"]),
                note=_md_escape(notes or "-"),
            )
        )
    lines.append("")

    infected = {k: v for k, v in agg.items() if v["status"] == INFECTED}
    if infected:
        lines.append("## 检出明细")
        lines.append("")
        for key, v in infected.items():
            lines.append(f"### {v['display']}")
            lines.append("")
            lines.append("| 威胁名 / 原始记录 | 文件 |")
            lines.append("|---|---|")
            for d in v["detections"]:
                lines.append(
                    f"| {_md_escape(d.get('threat', '-'))} | {_md_escape(d.get('file') or '-')} |"
                )
            lines.append("")

    manual = {k: v for k, v in agg.items() if v["status"] == MANUAL}
    if manual:
        lines.append("## 待人工补扫")
        lines.append("")
        lines.append("以下引擎无命令行扫描接口，需按 `manual-checklist.md` 手动执行后回填。")
        lines.append("")
        for v in manual.values():
            lines.append(f"- **{v['display']}**：{v['messages'][0] if v['messages'] else '见核对单'}")
        lines.append("")

    problems = {k: v for k, v in agg.items() if v["status"] in (ERROR, UNKNOWN, TIMEOUT)}
    if problems:
        lines.append("## 未取得结论的引擎")
        lines.append("")
        lines.append("这些引擎**不能**按「无毒」计，需排查后重跑。")
        lines.append("")
        for v in problems.values():
            msg = v["messages"][-1] if v["messages"] else "-"
            lines.append(f"- **{v['display']}**（{STATUS_LABEL[v['status']]}）：{msg}")
        lines.append("")

    lines.append("## 证据清单")
    lines.append("")
    lines.append("| 引擎 | 退出码 | 原始输出 |")
    lines.append("|---|---|---|")
    for v in agg.values():
        codes = ",".join("-" if c is None else str(c) for c in v["exit_codes"])
        logs = "<br>".join(f"`{Path(p).name}`" for p in v["logs"]) or "-"
        lines.append(f"| {_md_escape(v['display'])} | {codes} | {logs} |")
    lines.append("")
    lines.append(f"> 原始文件位于运行目录下的 `raw/` 子目录。")
    lines.append("")

    lines.append("## 环境快照")
    lines.append("")
    lines.append(f"- 主机：{meta.get('hostname', '-')}")
    lines.append(f"- 系统：{meta.get('os_version', '-')}")
    lines.append(f"- Python：{meta.get('python', '-')}")
    lines.append(f"- 工具版本：avscan {meta.get('tool_version', '-')}")
    lines.append("")
    return "\n".join(lines)


CSV_COLUMNS = [
    ("编号", lambda i, v: i),
    ("引擎", lambda i, v: v["display"]),
    ("厂商", lambda i, v: v["vendor"]),
    ("类型", lambda i, v: TIER_LABEL.get(v["tier"], v["tier"])),
    ("引擎版本", lambda i, v: v["engine_version"] or ""),
    ("病毒库", lambda i, v: v["db_version"] or ""),
    ("病毒库日期", lambda i, v: v["db_date"] or ""),
    ("状态", lambda i, v: STATUS_LABEL.get(v["status"], v["status"])),
    ("检出数", lambda i, v: len(v["detections"])),
    ("扫描文件数", lambda i, v: v["files"]),
    ("耗时(秒)", lambda i, v: v["duration_sec"]),
    ("退出码", lambda i, v: ",".join("-" if c is None else str(c) for c in v["exit_codes"])),
    ("说明", lambda i, v: "；".join(dict.fromkeys(m for m in v["messages"] if m))),
]


def render_csv(meta: dict, agg: OrderedDict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow([c[0] for c in CSV_COLUMNS])
    for i, v in enumerate(agg.values(), 1):
        writer.writerow([c[1](i, v) for c in CSV_COLUMNS])
    writer.writerow([])
    verdict, text = verdict_of(agg)
    writer.writerow(["任务编号", meta.get("run_id", "")])
    writer.writerow(["任务标签", meta.get("label", "")])
    writer.writerow(["总体结论", f"{verdict} - {text}"])
    writer.writerow(["执行时间", meta.get("created_at", "")])
    return "\ufeff" + buf.getvalue()


def render_json(meta: dict, agg: OrderedDict, results: list[dict]) -> str:
    verdict, text = verdict_of(agg)
    payload = {
        "meta": meta,
        "verdict": {"code": verdict, "text": text},
        "aggregated": list(agg.values()),
        "results": results,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


CHECKLIST_TEMPLATE = """# 人工扫毒核对单

> 生成的引擎没有命令行扫描接口，需要手动操作后把结论填回 `manual_results.json`。
> 填完运行 `python scan.py report <运行目录>` 重新出报告，结论会自动合并。

- 任务编号：`{run_id}`
- 生成时间：{created_at}
- 扫描目标：

{targets}

## 操作要求

1. 打开杀软主界面，进入「自定义查杀 / 指定位置查杀」；
2. 添加上面列出的路径（**不要**勾选「自动清理」，先只检测）；
3. 等扫描结束后，记录威胁数量与病毒库版本；
4. 把结果填进下面的 JSON 回填文件。

## 回填文件格式（manual_results.json）

```json
{{
{example}
}}
```

`status` 取值：`clean` 无毒 / `infected` 检出 / `error` 无法完成。
`db_version`、`db_date` 在杀软界面的「病毒库/更新」页可查。

## 核对表

| 引擎 | 操作入口 | 目标 | 检出数 | 结论 | 病毒库 | 病毒库日期 | 操作人 | 时间 |
|---|---|---|---|---|---|---|---|---|
{rows}
"""


def render_checklist(meta: dict, agg: OrderedDict) -> str:
    targets = meta.get("targets", [])
    target_lines = "\n".join(f"{i}. `{t['path']}`" for i, t in enumerate(targets, 1))

    manual = [v for v in agg.values() if v["status"] == MANUAL]
    example = ",\n".join(
        f'  "{v["engine"]}": {{"status": "clean", "db_version": "", "db_date": "", "note": ""}}'
        for v in manual
    )
    rows = []
    for v in manual:
        rows.append(
            f"| {v['display']} | {v['messages'][0] if v['messages'] else '-'} | 全部 | | | | | | |"
        )
    if not rows:
        rows.append("| （无待人工引擎） | - | - | - | - | - | - | - | - |")

    return CHECKLIST_TEMPLATE.format(
        run_id=meta.get("run_id", "-"),
        created_at=meta.get("created_at", "-"),
        targets=target_lines,
        example=example or '  "huorong": {"status": "clean"}',
        rows="\n".join(rows),
    )


def load_manual_results(run_dir: Path) -> dict:
    path = run_dir / "manual_results.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def apply_manual_results(agg: OrderedDict, manual: dict) -> OrderedDict:
    """把人工回填的结论并入聚合结果。"""
    for key, payload in manual.items():
        if key not in agg or not isinstance(payload, dict):
            continue
        status = str(payload.get("status", "")).lower().strip()
        if status not in (CLEAN, INFECTED, ERROR):
            continue
        agg[key]["status"] = status
        agg[key]["engine_version"] = payload.get("engine_version") or agg[key]["engine_version"]
        agg[key]["db_version"] = payload.get("db_version") or agg[key]["db_version"]
        agg[key]["db_date"] = payload.get("db_date") or agg[key]["db_date"]
        note = payload.get("note") or "人工扫描回填"
        agg[key]["messages"] = [f"[人工] {note}"]
    return agg


def publish_reports(run_dir: Path, meta: dict, results: list[dict]) -> tuple[str, Path]:
    """写出四份报告并返回 (结论, report.md 路径)。CLI 与 GUI 共用。"""
    agg = aggregate(results)
    agg = apply_manual_results(agg, load_manual_results(run_dir))

    (run_dir / "report.md").write_text(render_markdown(meta, agg), encoding="utf-8")
    (run_dir / "report.csv").write_text(render_csv(meta, agg), encoding="utf-8")
    (run_dir / "report.json").write_text(render_json(meta, agg, results), encoding="utf-8")
    (run_dir / "manual-checklist.md").write_text(render_checklist(meta, agg), encoding="utf-8")

    verdict, _ = verdict_of(agg)
    return verdict, run_dir / "report.md"
