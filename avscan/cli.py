"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

from . import __version__
from .engines import ENGINES, STATUS_LABEL, probe_all, select_engines
from .merge import merge_runs
from .packages import (
    KIND_LABEL,
    find,
    install_package,
    load_manifest,
    open_package,
    risk_summary,
    summary,
    verify_packages,
)
from .pkgcheck import inspect_paths
from .report import (
    aggregate,
    apply_manual_results,
    load_manual_results,
    render_checklist,
    render_csv,
    render_json,
    render_markdown,
    verdict_of,
)
from .runner import run_target
from .selftest import run as run_selftest
from .targets import RISK_EXTS, build_target_set, human_bytes

from .runtime import app_dir

DEFAULT_RUNS_DIR = app_dir() / "runs"

VERDICT_TEXT = {
    "pass": "通过：所有已执行引擎均未发现威胁",
    "fail": "不通过：存在检出",
    "incomplete": "不通过：有引擎未取得结论",
    "pending": "待补：人工引擎未回填",
    "dryrun": "演练完成，未实际扫描",
    "empty": "无数据",
}


# ---- 终端排版（中文字符按 2 列宽） ----------------------------------------
def _width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _width(text))


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max([_width(h)] + [_width(str(r[i])) for r in rows]) for i, h in enumerate(headers)]
    sep = "  "
    out = [sep.join(_pad(h, widths[i]) for i, h in enumerate(headers))]
    out.append(sep.join("-" * w for w in widths))
    for row in rows:
        out.append(sep.join(_pad(str(c), widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)


def _setup_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


# ---- detect ---------------------------------------------------------------
def cmd_detect(args: argparse.Namespace) -> int:
    statuses = probe_all(select_engines(args.engines) if args.engines else ENGINES)

    if args.json:
        payload = [
            {
                "key": s.key,
                "display": s.engine.display,
                "vendor": s.engine.vendor,
                "tier": s.engine.tier,
                "installed": s.installed,
                "ready": s.ready,
                "exe": str(s.exe) if s.exe else None,
                "version": s.version,
                "db_version": s.db_version,
                "db_date": s.db_date,
                "reason": s.reason,
                "caveats": list(s.engine.caveats),
            }
            for s in statuses
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    rows = []
    for s in statuses:
        if not s.installed:
            state = "未安装"
        elif s.engine.tier == "manual":
            state = "仅 GUI"
        elif s.ready:
            state = "可自动"
        else:
            state = "不可用"
        rows.append(
            [
                s.engine.display,
                "人工" if s.engine.tier == "manual" else "自动",
                state,
                s.version or "-",
                s.db_version or "-",
                s.db_date or "-",
                str(s.exe) if s.exe else "-",
            ]
        )

    print(_table(["引擎", "类型", "状态", "版本", "病毒库", "病毒库日期", "路径"], rows))

    auto_ready = [s for s in statuses if s.runnable]
    manual_ready = [s for s in statuses if s.installed and s.engine.tier == "manual"]
    missing = [s for s in statuses if not s.installed]

    print()
    print(f"可全自动执行：{len(auto_ready)} 个" + (f"（{', '.join(s.engine.display for s in auto_ready)}）" if auto_ready else ""))
    print(f"仅人工执行　：{len(manual_ready)} 个" + (f"（{', '.join(s.engine.display for s in manual_ready)}）" if manual_ready else ""))
    print(f"未安装　　　：{len(missing)} 个" + (f"（{', '.join(s.engine.display for s in missing)}）" if missing else ""))

    caveats = [(s.engine.display, c) for s in statuses if s.installed for c in s.engine.caveats]
    if caveats:
        print()
        print("注意事项：")
        for name, text in caveats:
            print(f"  · {name}：{text}")
    return 0


# ---- scan -----------------------------------------------------------------
def _slugify(text: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_" else "-" for c in text.strip())
    cleaned = "-".join(filter(None, cleaned.split("-")))
    return cleaned[:40].strip("-")


def _write_reports(run_dir: Path, meta: dict, results: list[dict]) -> tuple[str, str]:
    agg = aggregate(results)
    agg = apply_manual_results(agg, load_manual_results(run_dir))

    (run_dir / "report.md").write_text(render_markdown(meta, agg), encoding="utf-8")
    (run_dir / "report.csv").write_text(render_csv(meta, agg), encoding="utf-8")
    (run_dir / "report.json").write_text(render_json(meta, agg, results), encoding="utf-8")
    (run_dir / "manual-checklist.md").write_text(render_checklist(meta, agg), encoding="utf-8")

    verdict, _ = verdict_of(agg)
    return verdict, str(run_dir / "report.md")


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        engine_list = select_engines(args.engines)
    except ValueError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    per_file = args.per_file or args.only_risk
    try:
        target_set = build_target_set(
            args.targets,
            per_file=per_file,
            extensions=RISK_EXTS if args.only_risk else None,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    statuses = probe_all(engine_list)
    runnable = [s for s in statuses if s.runnable]
    manual_only = [s for s in statuses if s.installed and s.engine.tier == "manual"]

    if not runnable and not manual_only:
        print("错误：所选引擎均不可用，先跑 `python scan.py detect` 看环境。", file=sys.stderr)
        return 3

    print(f"扫描目标　：{len(target_set.targets)} 项，{target_set.file_total} 个文件 / {human_bytes(target_set.byte_total)}")
    if target_set.mode == "file":
        print(f"扫描模式　：逐文件（已过滤 {target_set.excluded} 个非高危文件）" if args.only_risk else "扫描模式　：逐文件")
    else:
        print("扫描模式　：整目录（由引擎自身递归）")
    print(f"参与引擎　：{len(runnable)} 个自动" + (f" + {len(manual_only)} 个人工" if manual_only else ""))
    for s in runnable:
        print(f"  · {s.engine.display}" + (f" {s.version}" if s.version else ""))
    for s in manual_only:
        print(f"  · {s.engine.display}（仅 GUI，将生成核对单）")
    print()

    if args.dry_run:
        print("== DRY RUN：只打印将执行的命令 ==")
        print()

    if not args.yes and not args.dry_run:
        try:
            answer = input("确认开始扫描？[Y/n] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("", "y", "yes"):
            print("已取消。")
            return 0
        print()

    run_id = args.run_id or (
        "RUN-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        + (f"-{_slugify(args.label)}" if args.label else "")
    )
    runs_root = Path(args.out).expanduser().resolve() if args.out else DEFAULT_RUNS_DIR
    run_dir = runs_root / run_id
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "run_id": run_id,
        "label": args.label or "",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": "",
        "mode": target_set.mode,
        "dry_run": bool(args.dry_run),
        "timeout": args.timeout,
        "targets": [t.to_dict() for t in target_set.targets],
        "engines": [s.key for s in statuses],
        "hostname": platform.node(),
        "os_version": f"{platform.system()} {platform.release()} {platform.version()}",
        "python": platform.python_version(),
        "tool_version": __version__,
        "run_dir": str(run_dir),
    }

    results = []
    interrupted = False

    try:
        for idx, status in enumerate(statuses, 1):
            if not status.installed:
                continue
            engine = status.engine
            print(f"[{idx}/{len(statuses)}] {engine.display} ...", end="", flush=True)

            if engine.tier == "manual":
                result = run_target(status, target_set.targets[0], raw_dir, timeout=args.timeout)
                results.append(result.to_dict())
                print(" 待人工（已写入核对单）")
                continue

            if not status.ready:
                result = run_target(status, target_set.targets[0], raw_dir, timeout=args.timeout)
                results.append(result.to_dict())
                print(f" 跳过：{status.reason}")
                continue

            started = datetime.now()
            for i, target in enumerate(target_set.targets):
                result = run_target(
                    status,
                    target,
                    raw_dir,
                    timeout=args.timeout,
                    dry_run=args.dry_run,
                    index=i,
                )
                results.append(result.to_dict())

            last = results[-1] if results else {}
            icon = {"clean": "OK", "infected": "检出", "error": "失败", "unknown": "未知", "timeout": "超时", "skipped": "跳过"}
            print(f" {icon.get(last.get('status', ''), last.get('status', ''))}"
                  f" · {last.get('message', '')}"
                  f" · {last.get('duration_sec', 0)}s")
            if args.dry_run:
                print(f"      {last.get('cmdline', '')}")
            _ = started

    except KeyboardInterrupt:
        interrupted = True
        print("\n已中断，正在保存已完成的结果 ...")

    meta["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    verdict, report_path = _write_reports(run_dir, meta, results)

    print()
    print(f"结论：{VERDICT_TEXT.get(verdict, verdict)}")
    print(f"报告：{report_path}")
    print(f"CSV ：{run_dir / 'report.csv'}")
    print(f"核对单：{run_dir / 'manual-checklist.md'}")

    if interrupted:
        return 130
    return 0 if verdict in ("pass", "dryrun") else 1


# ---- report ---------------------------------------------------------------
def cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).expanduser().resolve()
    if not run_dir.is_dir():
        print(f"错误：目录不存在 {run_dir}", file=sys.stderr)
        return 2

    meta_path = run_dir / "meta.json"
    results_path = run_dir / "results.json"
    if not meta_path.is_file() or not results_path.is_file():
        print(f"错误：{run_dir} 不是有效的运行目录（缺 meta.json / results.json）", file=sys.stderr)
        return 2

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    results = json.loads(results_path.read_text(encoding="utf-8"))

    verdict, report_path = _write_reports(run_dir, meta, results)

    agg = aggregate(results)
    merged = apply_manual_results(agg, load_manual_results(run_dir))
    rows = []
    for v in merged.values():
        rows.append(
            [
                v["display"],
                {"auto": "自动", "manual": "人工"}[v["tier"]],
                STATUS_LABEL.get(v["status"], v["status"]),
                str(len(v["detections"])),
                f"{v['duration_sec']}s",
            ]
        )
    print(_table(["引擎", "类型", "状态", "检出", "耗时"], rows))
    print()
    print(f"结论：{VERDICT_TEXT.get(verdict, verdict)}")
    print(f"报告：{report_path}")
    return 0


# ---- merge ----------------------------------------------------------------
def cmd_merge(args: argparse.Namespace) -> int:
    run_dirs = [Path(d).expanduser().resolve() for d in args.run_dirs]
    for d in run_dirs:
        if not d.is_dir():
            print(f"错误：目录不存在 {d}", file=sys.stderr)
            return 2

    if args.out:
        out_dir = Path(args.out).expanduser().resolve()
    else:
        out_dir = DEFAULT_RUNS_DIR / ("MERGE-" + datetime.now().strftime("%Y%m%d-%H%M%S"))

    try:
        out_dir, warnings = merge_runs(run_dirs, out_dir, args.label)
    except FileNotFoundError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    meta = json.loads((out_dir / "meta.json").read_text(encoding="utf-8"))
    results = json.loads((out_dir / "results.json").read_text(encoding="utf-8"))
    verdict, report_path = _write_reports(out_dir, meta, results)

    print(f"已合并 {len(run_dirs)} 次运行，覆盖 {len(results)} 个引擎结果")
    for w in warnings:
        print(f"警告：{w}")
    print()
    print(f"结论：{VERDICT_TEXT.get(verdict, verdict)}")
    print(f"报告：{report_path}")
    return 0 if verdict == "pass" else 1


# ---- inspect --------------------------------------------------------------
def _mb(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


def cmd_inspect(args: argparse.Namespace) -> int:
    paths = [Path(p).expanduser() for p in args.paths]
    for p in paths:
        if not p.exists():
            print(f"错误：路径不存在 {p}", file=sys.stderr)
            return 2

    reports = inspect_paths(paths)
    if not reports:
        print("未找到可分析的安装包（.exe/.msi/.msix/.appx）", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2))
        return 0

    for i, r in enumerate(reports, 1):
        print(f"[{i}] {r.name}   {_mb(r.size)}")
        pe_line = f"{r.machine} / {r.subsystem}" if r.is_pe else "非 PE 文件"
        if r.dotnet:
            pe_line += " / .NET"
        print(f"    类型    : {pe_line}")
        if r.compiled:
            print(f"    编译时间: {r.compiled}")
        print(f"    安装器  : {r.installer}")
        if r.installer_evidence:
            print(f"    判定依据: {', '.join(r.installer_evidence[:3])}")
        if r.packers:
            print(f"    疑似加壳: {', '.join(r.packers)}")
        print(f"    签名    : {r.sign_status}   {r.signer}")
        if r.product or r.version:
            print(f"    产品    : {r.product}  {r.version}")
        if r.silent_hint:
            print(f"    静默安装: {r.silent_hint}")
        print(f"    SHA256  : {r.sha256}")
        print(f"    VT 查询 : {r.vt_url}")
        for note in r.notes:
            print(f"    ! {note}")
        print()

    print("== 汇总 ==")
    rows = [
        [
            str(i),
            r.name[:44],
            _mb(r.size),
            r.installer.split("（")[0],
            r.sign_status,
            r.signer[:26],
        ]
        for i, r in enumerate(reports, 1)
    ]
    print(_table(["#", "文件", "大小", "安装器", "签名", "签发者"], rows))

    online = [r for r in reports if "在线安装器" in " ".join(r.notes)]
    valid = [r for r in reports if r.sign_status == "Valid"]
    unknown = [r for r in reports if r.sign_status in ("未知", "")]
    invalid = [r for r in reports if r.sign_status not in ("Valid", "未知", "")]

    print()
    print(f"合计 {len(reports)} 个安装包，其中疑似在线安装器 {len(online)} 个")
    print(f"签名：有效 {len(valid)} ｜ 未取到 {len(unknown)} ｜ 异常 {len(invalid)}")
    if unknown:
        print("  未取到签名：" + "、".join(r.name for r in unknown))
    if invalid:
        print("  ⚠️ 签名异常：" + "、".join(f"{r.name}({r.sign_status})" for r in invalid))

    if args.md:
        out = Path(args.md).expanduser()
        out.write_text(_render_inspect_md(reports), encoding="utf-8")
        print(f"Markdown 报告：{out}")
    return 0


def _render_inspect_md(reports) -> str:
    lines = ["# 安装包静态体检报告", ""]
    lines.append("| # | 文件 | 大小 | 安装器 | 签名 | 签发者 | 产品 | 版本 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(reports, 1):
        lines.append(
            f"| {i} | `{r.name}` | {_mb(r.size)} | {r.installer} | {r.sign_status} | "
            f"{r.signer or '-'} | {r.product or '-'} | {r.version or '-'} |"
        )
    lines.append("")
    lines.append("## 哈希与 VirusTotal")
    lines.append("")
    lines.append("> 用哈希查询不会上传文件本体，可安全用于公司内部包。")
    lines.append("")
    lines.append("| 文件 | SHA256 | VT 链接 |")
    lines.append("|---|---|---|")
    for r in reports:
        lines.append(f"| `{r.name}` | `{r.sha256}` | [查询]({r.vt_url}) |")
    lines.append("")
    lines.append("## 逐包详情")
    for r in reports:
        lines.append("")
        lines.append(f"### {r.name}")
        lines.append("")
        lines.append(f"- 大小：{_mb(r.size)}")
        lines.append(f"- PE：{r.machine} / {r.subsystem}" + (" / .NET" if r.dotnet else ""))
        if r.compiled:
            lines.append(f"- 编译时间：{r.compiled}")
        if r.sections:
            lines.append(f"- 节区：{', '.join(r.sections)}")
        lines.append(f"- 安装器：{r.installer}")
        if r.installer_evidence:
            lines.append(f"- 判定依据：{', '.join(r.installer_evidence)}")
        if r.packers:
            lines.append(f"- 疑似加壳：{', '.join(r.packers)}")
        lines.append(f"- 签名：{r.sign_status} {r.signer}")
        if r.silent_hint:
            lines.append(f"- 静默安装：`{r.silent_hint}`")
        for note in r.notes:
            lines.append(f"- 提示：{note}")
    lines.append("")
    return "\n".join(lines)


# ---- packages -------------------------------------------------------------
def cmd_packages(args: argparse.Namespace) -> int:
    action = args.pkg_action
    try:
        pkgs = load_manifest()
    except FileNotFoundError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    if action == "list":
        if args.json:
            print(json.dumps([p.to_dict() for p in pkgs], ensure_ascii=False, indent=2))
            return 0
        rows = []
        for p in pkgs:
            rows.append(
                [
                    p.id,
                    p.display[:26],
                    p.version[:16],
                    KIND_LABEL.get(p.kind, p.kind),
                    f"{p.size_mb:.0f}MB",
                    p.mode_label,
                    "OK" if p.exists else "缺失",
                ]
            )
        print(_table(["ID", "名称", "版本", "类型", "大小", "安装方式", "文件"], rows))
        s = summary(pkgs)
        print()
        print(
            f"共 {s['total']} 个包（文件齐全 {s['present']}）："
            f"离线 {s['offline']} ｜ 在线安装器 {s['online']} ｜ 免安装 {s['portable']}"
        )
        print(
            f"可一键安装 {s['silent_ready']} 个 ｜ 需手动安装 {s['manual_only']} 个 ｜ 合计 {s['total_mb']:.0f} MB"
        )
        if s["silent_ready"]:
            print("注：带 * 的一键安装参数未经本机实测，首次建议先手动装一次确认")
        if s["missing"]:
            print(f"⚠️  缺失 {s['missing']} 个文件")
        return 0

    if action == "verify":
        rows = verify_packages(pkgs)
        table = [
            [r["id"], r["display"][:26], r["status"], r["signer"][:28], f"{r['size_mb']:.0f}MB"]
            for r in rows
        ]
        print(_table(["ID", "名称", "签名", "签发者", "大小"], table))
        bad = [r for r in rows if r["status"] != "Valid"]
        print()
        if bad:
            print("⚠️  签名异常：" + "、".join(f"{r['id']}({r['status']})" for r in bad))
            return 1
        print(f"签名全部有效（{len(rows)} 个）")
        if args.md:
            out = Path(args.md).expanduser()
            lines = ["# 安装包完整性校验", "", "| ID | 名称 | 签名 | 签发者 | SHA256 |", "|---|---|---|---|---|"]
            for r in rows:
                lines.append(f"| {r['id']} | {r['display']} | {r['status']} | {r['signer']} | `{r['sha256']}` |")
            out.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"报告：{out}")
        return 0

    pkg = find(args.id, pkgs)
    if pkg is None:
        print(f"错误：清单里没有 id={args.id}", file=sys.stderr)
        print("可用：" + "、".join(p.id for p in pkgs), file=sys.stderr)
        return 2

    if action == "open":
        ok, msg = open_package(pkg)
        print(msg)
        return 0 if ok else 1

    if action == "install":
        print(f"目标：{pkg.display} {pkg.version}（{KIND_LABEL.get(pkg.kind, pkg.kind)}）")
        print(f"文件：{pkg.file}")
        if pkg.note:
            print(f"说明：{pkg.note}")
        for risk in risk_summary(pkg):
            print(f"  ⚠ {risk}")
        print()

        if pkg.mode != "silent":
            print(f"该包不支持一键静默安装（{pkg.mode_label}）。")
            print("可改用：python scan.py packages open " + pkg.id)
            return 1

        ok, msg = install_package(pkg, confirm=args.yes, wait=not args.no_wait)
        print(msg)
        if not args.yes:
            print()
            print("这是 dry-run。确认要安装请加 --yes：")
            print(f"  python scan.py packages install {pkg.id} --yes")
        return 0 if ok else 1

    return 2


# ---- trigger 触发仅 GUI 的引擎 --------------------------------------------
def cmd_trigger(args: argparse.Namespace) -> int:
    from .huorong import trigger_scan

    ok, msg = trigger_scan(args.paths, args.exe or None)
    print(msg)
    return 0 if ok else 1


# ---- shell 右键菜单 --------------------------------------------------------
def cmd_shell(args: argparse.Namespace) -> int:
    from . import shellmenu

    exe = args.exe or None

    if args.action == "install":
        ok, msg = shellmenu.install(exe)
        print(msg)
        if ok:
            print()
            print("在资源管理器里右键任一文件或文件夹即可看到「用 avscan 扫描」。")
            print("撤销：python scan.py shell uninstall")
        return 0 if ok else 1

    if args.action == "uninstall":
        ok, msg = shellmenu.uninstall()
        print(msg)
        return 0 if ok else 1

    rows = shellmenu.status(exe)
    table = []
    for r in rows:
        if not r["installed"]:
            table.append([r["target"], "未注册", "—"])
        elif r["exe_exists"]:
            table.append([r["target"], "已注册", Path(r["exe"]).name])
        else:
            table.append([r["target"], "已注册", f"目标缺失：{r['exe']}"])
    print(_table(["位置", "状态", "目标程序"], table))
    for r in rows:
        if r["installed"]:
            print(f"  {r['target']}: {r['command']}")
    return 0


# ---- gui ------------------------------------------------------------------
def cmd_gui(args: argparse.Namespace) -> int:
    # 延迟导入：GUI 依赖 Qt，CLI 用户不该为此付出启动成本
    from gui import main as gui_main

    return gui_main([])


# ---- 入口 -----------------------------------------------------------------
def cmd_selftest(args: argparse.Namespace) -> int:
    return run_selftest(verbose=args.verbose)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="多引擎批量扫毒编排：自动跑有 CLI 的引擎，无 CLI 的生成人工核对单。",
    )
    parser.add_argument("-v", "--version", action="version", version=f"avscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_detect = sub.add_parser("detect", help="探测本机装了哪些引擎、能否自动跑")
    p_detect.add_argument("--engines", default="", help="限定引擎，逗号分隔；默认全部")
    p_detect.add_argument("--json", action="store_true", help="输出 JSON")
    p_detect.set_defaults(func=cmd_detect)

    p_scan = sub.add_parser("scan", help="对安装包/安装目录批量扫毒")
    p_scan.add_argument("targets", nargs="+", help="文件或目录，可多个")
    p_scan.add_argument("--engines", default="auto", help="all|auto|manual|逗号分隔的引擎名，默认 auto")
    p_scan.add_argument("--label", default="", help="任务标签，如 'CTONE V0.5.8 发布包'")
    p_scan.add_argument("--timeout", type=int, default=1800, help="单引擎单目标超时秒数，默认 1800")
    p_scan.add_argument("--per-file", action="store_true", help="逐文件扫描（慢，用于精确定位）")
    p_scan.add_argument("--only-risk", action="store_true", help="仅扫高危扩展名（隐含 --per-file）")
    p_scan.add_argument("--dry-run", action="store_true", help="只打印将执行的命令，不实际扫描")
    p_scan.add_argument("--yes", "-y", action="store_true", help="跳过确认")
    p_scan.add_argument("--run-id", default="", help="自定义运行编号")
    p_scan.add_argument("--out", default="", help="运行结果根目录，默认 ./runs")
    p_scan.set_defaults(func=cmd_scan)

    p_report = sub.add_parser("report", help="按运行目录重新生成报告（会合并人工回填）")
    p_report.add_argument("run_dir", help="运行目录，如 runs/RUN-20261029-153000")
    p_report.set_defaults(func=cmd_report)

    p_self = sub.add_parser("selftest", help="解析器自检：验证「检出」能被正确识别")
    p_self.add_argument("--verbose", "-V", action="store_true", help="打印每个样本的判定说明")
    p_self.set_defaults(func=cmd_selftest)

    p_merge = sub.add_parser("merge", help="合并多次运行的结果（分次装/卸杀软的场景）")
    p_merge.add_argument("run_dirs", nargs="+", help="要合并的运行目录")
    p_merge.add_argument("--label", default="", help="合并任务标签")
    p_merge.add_argument("--out", default="", help="输出目录，默认 runs/MERGE-<时间>")
    p_merge.set_defaults(func=cmd_merge)

    p_inspect = sub.add_parser("inspect", help="安装包静态体检：只读不执行，识别安装器/签名/静默参数")
    p_inspect.add_argument("paths", nargs="+", help="安装包文件或目录")
    p_inspect.add_argument("--json", action="store_true", help="输出 JSON")
    p_inspect.add_argument("--md", default="", help="同时导出 Markdown 报告到指定路径")
    p_inspect.set_defaults(func=cmd_inspect)

    p_pkg = sub.add_parser("packages", help="安装包仓库：列出 / 校验 / 一键安装 / 打开文件夹")
    pkg_sub = p_pkg.add_subparsers(dest="pkg_action", required=True)

    pp = pkg_sub.add_parser("list", help="列出归档的安装包及可用安装方式")
    pp.add_argument("--json", action="store_true", help="输出 JSON")
    pp.set_defaults(func=cmd_packages)

    pp = pkg_sub.add_parser("verify", help="校验归档包签名与 SHA256")
    pp.add_argument("--md", default="", help="导出 Markdown 校验报告")
    pp.set_defaults(func=cmd_packages)

    pp = pkg_sub.add_parser("open", help="打开所在文件夹并选中文件（手动安装入口）")
    pp.add_argument("id", help="包 id，如 huorong")
    pp.set_defaults(func=cmd_packages)

    pp = pkg_sub.add_parser("install", help="一键静默安装（默认 dry-run，需 --yes 确认）")
    pp.add_argument("id", help="包 id，如 huorong")
    pp.add_argument("--yes", "-y", action="store_true", help="确认执行安装")
    pp.add_argument("--no-wait", action="store_true", help="拉起进程后立即返回（供 GUI 调用）")
    pp.set_defaults(func=cmd_packages)

    p_gui = sub.add_parser("gui", help="启动图形界面")
    p_gui.set_defaults(func=cmd_gui)

    p_trig = sub.add_parser("trigger", help="触发仅 GUI 引擎扫描（当前支持火绒，复用其右键菜单协议）")
    p_trig.add_argument("paths", nargs="+", help="要扫描的文件或目录")
    p_trig.add_argument("--exe", default="", help="引擎主程序路径，默认使用已知路径")
    p_trig.set_defaults(func=cmd_trigger)

    p_shell = sub.add_parser("shell", help="资源管理器右键菜单：安装 / 卸载 / 查看")
    shell_sub = p_shell.add_subparsers(dest="action", required=True)
    for act, desc in (
        ("install", "安装右键菜单（写入 HKCU，无需管理员）"),
        ("uninstall", "移除右键菜单"),
        ("status", "查看当前注册状态"),
    ):
        pp = shell_sub.add_parser(act, help=desc)
        pp.add_argument("--exe", default="", help="指定要注册的可执行文件，默认自动判断")
        pp.set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> int:
    _setup_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
