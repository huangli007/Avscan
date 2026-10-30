"""引擎注册表：每款杀软一条适配记录（探测规则 / 命令构造 / 结果解析）。

诚实分两级：
  auto   —— 有可用命令行接口，本工具能全自动跑完并解析结果；
  manual —— 只有 GUI，工具负责准备目标、拉起界面、生成人工回填单。

绝不把「没跑起来」当成「无毒」。解析不出明确结论时一律返回 unknown。
"""

from __future__ import annotations

import ctypes
import glob as globmod
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from .paths import program_roots, registry_products
from .runtime import data_dir
from .userconfig import get_override

# ---- 结论常量 -------------------------------------------------------------
CLEAN = "clean"          # 明确无检出
INFECTED = "infected"    # 明确有检出
ERROR = "error"          # 执行失败 / 配置错误
UNKNOWN = "unknown"      # 跑完了但读不出结论（不可当作 clean）
TIMEOUT = "timeout"
SKIPPED = "skipped"
MANUAL = "manual"        # 需人工执行

STATUS_LABEL = {
    CLEAN: "无毒",
    INFECTED: "检出",
    ERROR: "失败",
    UNKNOWN: "未知",
    TIMEOUT: "超时",
    SKIPPED: "跳过",
    MANUAL: "待人工",
}

BuildFn = Callable[[Path, Path, Path], list[str]]
ParseFn = Callable[[str, str, "int | None", Path], tuple[str, list[dict], str]]
PickFn = Callable[[list[Path]], Path]


# ---- Windows 文件版本 -----------------------------------------------------
class _FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [
        ("dwSignature", ctypes.c_ulong),
        ("dwStrucVersion", ctypes.c_ulong),
        ("dwFileVersionMS", ctypes.c_ulong),
        ("dwFileVersionLS", ctypes.c_ulong),
        ("dwProductVersionMS", ctypes.c_ulong),
        ("dwProductVersionLS", ctypes.c_ulong),
        ("dwFileFlagsMask", ctypes.c_ulong),
        ("dwFileFlags", ctypes.c_ulong),
        ("dwFileOS", ctypes.c_ulong),
        ("dwFileType", ctypes.c_ulong),
        ("dwFileSubtype", ctypes.c_ulong),
        ("dwFileDateMS", ctypes.c_ulong),
        ("dwFileDateLS", ctypes.c_ulong),
    ]


def file_version(path: Path) -> str | None:
    """读取 PE 文件版本号，读不到返回 None（不抛异常）。"""
    try:
        ver = ctypes.windll.version
    except AttributeError:
        return None
    try:
        size = ver.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(str(path), 0, size, buf):
            return None
        ptr = ctypes.c_void_p()
        length = ctypes.c_uint()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
            return None
        info = ctypes.cast(ptr, ctypes.POINTER(_FIXEDFILEINFO)).contents
        ms, ls = info.dwFileVersionMS, info.dwFileVersionLS
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:  # noqa: BLE001 - 版本读取失败不影响扫描
        return None


# ---- Defender 病毒库 ------------------------------------------------------
def _service_running(name: str) -> bool:
    """查 Windows 服务是否在运行。查不到就当作在跑，不误伤。"""
    try:
        import subprocess

        out = subprocess.run(
            ["sc", "query", name], capture_output=True, text=True, timeout=5
        )
        return "RUNNING" in out.stdout.upper()
    except Exception:  # noqa: BLE001
        return True


def _defender_availability() -> tuple[bool, str]:
    """Defender 现在还能不能扫。

    装了第三方杀软（火绒等）后 Defender 常被禁用：注册表 DisableAntiSpyware=1，
    WinDefend 服务停止。此时 MpCmdRun 会以 0x80004005 失败，
    必须提前识别出来，否则每次白跑一趟还只报「扫描出错」。
    """
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender",
            0,
            winreg.KEY_READ | 0x0100,  # KEY_WOW64_64KEY
        ) as key:
            disabled, _ = winreg.QueryValueEx(key, "DisableAntiSpyware")
            if int(disabled) == 1:
                return False, "Defender 已被禁用（安装第三方杀软后常见），无法执行扫描"
    except (ImportError, OSError, ValueError):
        pass

    if not _service_running("WinDefend"):
        return False, "WinDefend 服务未运行，Defender 不可用"

    return True, ""


def _defender_db() -> tuple[str | None, str | None]:
    """从注册表读 Defender 的引擎版本 / 病毒库版本 / 病毒库日期。"""
    try:
        import winreg
    except ImportError:
        return None, None

    base = r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
    values: dict[str, object] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ | 0x0100) as key:
            for name in ("AVSignatureVersion", "EngineVersion", "SignaturesLastUpdated"):
                try:
                    values[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except OSError:
        return None, None

    sig = values.get("AVSignatureVersion")
    sig = str(sig) if sig else None

    stamp = values.get("SignaturesLastUpdated")
    date = None
    if isinstance(stamp, (bytes, bytearray)) and len(stamp) >= 8:
        filetime = int.from_bytes(bytes(stamp)[:8], "little")
        if filetime > 0:
            try:
                date = (datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)).strftime(
                    "%Y-%m-%d %H:%M"
                )
            except (OverflowError, ValueError):
                date = None
    return sig, date


# ---- 解析辅助 -------------------------------------------------------------
def _text_of(primary: str, secondary: str) -> str:
    return (primary or "") + "\n" + (secondary or "")


def _read_report(path: Path) -> str:
    """卡片/杀软报告文件编码五花八门，逐个编码试。"""
    if not path.is_file():
        return ""
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16-le", "utf-16", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _parse_defender(stdout: str, stderr: str, rc: int | None, outdir: Path):
    text = _text_of(stdout, stderr)
    detections: list[dict] = []
    for m in re.finditer(r"(?:Threat|威胁)\s*[:：]\s*(.+)", text, re.I):
        detections.append({"threat": m.group(1).strip(), "file": ""})

    count: int | None = None
    m = re.search(r"found\s+(\d+)\s+threats?", text, re.I)
    if m:
        count = int(m.group(1))
    elif re.search(r"found\s+no\s+threats?", text, re.I):
        count = 0

    if count == 0:
        return CLEAN, [], "扫描完成，未发现威胁"
    if count:
        return INFECTED, detections or [{"threat": f"{count} 项", "file": ""}], f"检出 {count} 项"
    if rc == 0:
        return CLEAN, [], "退出码 0（未检出）"
    if rc == 2:
        # 退出码 2 有两种含义：检出未处理，或扫描出错。
        # 只有解析到具体威胁才能判检出，否则按「未完成」处理 ——
        # 把扫描失败报成「发现病毒」是最不能接受的假阳性。
        if detections:
            return INFECTED, detections, f"检出 {len(detections)} 项"
        if re.search(r"Product/Feature\s+disabled", text, re.I):
            return ERROR, [], "Defender 功能已被禁用（通常因安装第三方杀软），无法扫描"
        if re.search(r"\[Failed\]|CmdTool:\s*Failed|0x[0-9A-Fa-f]{8}", text):
            return ERROR, [], "扫描出错（退出码 2），详见原始输出"
        return ERROR, [], "退出码 2 但未解析到威胁，按未完成处理"
    return ERROR, [], f"退出码 {rc}，无法判定"


def _parse_kaspersky(stdout: str, stderr: str, rc: int | None, outdir: Path):
    report = _read_report(outdir / "kaspersky.report.txt")
    text = _text_of(_text_of(stdout, stderr), report)
    detections: list[dict] = []
    for line in text.splitlines():
        low = line.lower()
        if "detected" in low and "not detected" not in low:
            detections.append({"threat": line.strip()[:200], "file": ""})
    if detections:
        return INFECTED, detections, f"检出 {len(detections)} 处（含报告行）"
    if re.search(r"scan\s+(?:completed|finished)", text, re.I) and rc == 0:
        return CLEAN, [], "扫描完成，报告无检出"
    if rc == 0 and report.strip():
        return CLEAN, [], "报告无检出记录"
    return UNKNOWN, [], f"退出码 {rc}，报告为空或不可读"


def _parse_avira(stdout: str, stderr: str, rc: int | None, outdir: Path):
    report = _read_report(outdir / "avira.log") or _read_report(outdir / "avira.report.txt")
    text = _text_of(_text_of(stdout, stderr), report)
    detections: list[dict] = []
    for m in re.finditer(r"ALERT:\s*(.+?)\s+<<<", text):
        detections.append({"threat": m.group(1).strip(), "file": ""})
    for m in re.finditer(r"^\s*(?:Virus|Detection)\s*[:：]\s*(.+)", text, re.I | re.M):
        detections.append({"threat": m.group(1).strip(), "file": ""})
    if detections:
        dedup = {(d["threat"], d["file"]): d for d in detections}
        detections = list(dedup.values())
        return INFECTED, detections, f"检出 {len(detections)} 项"
    if re.search(r"no\s+(?:virus|malware|threat)", text, re.I):
        return CLEAN, [], "日志显示无检出"
    if re.search(r"scan\s+(?:finished|completed|done)", text, re.I) and not detections:
        return CLEAN, [], "扫描完成，日志无 ALERT"
    return UNKNOWN, [], f"退出码 {rc}，日志未给出明确结论"


def _parse_avast(stdout: str, stderr: str, rc: int | None, outdir: Path):
    report = _read_report(outdir / "avast.report.txt")
    text = _text_of(_text_of(stdout, stderr), report)
    detections: list[dict] = []
    for m in re.finditer(r"^\s*\[[LB]\]\s*(?:Threat|Malware)\s*[:：]\s*(.+)", text, re.I | re.M):
        detections.append({"threat": m.group(1).strip(), "file": ""})
    for m in re.finditer(r"Threat\s*[:：]\s*(.+)", text, re.I):
        detections.append({"threat": m.group(1).strip(), "file": ""})
    if detections:
        return INFECTED, detections, f"检出 {len(detections)} 项"
    if re.search(r"(?:no\s+(?:virus|threat)|nothing\s+found)", text, re.I):
        return CLEAN, [], "输出显示无检出"
    if rc == 0 and report.strip():
        return CLEAN, [], "报告存在且无威胁行"
    return UNKNOWN, [], f"退出码 {rc}，输出不足以判定"


def _parse_stinger(stdout: str, stderr: str, rc: int | None, outdir: Path):
    chunks = [_text_of(stdout, stderr)]
    # Stinger 把报告写到 -log 指定的目录，扩展名不固定（.log / .csv / .txt）
    for pattern in ("*.log", "*.csv", "*.txt"):
        for p in sorted(outdir.glob(pattern)):
            if p.name.startswith(("stdout", "stderr")):
                continue
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    text = "\n".join(chunks)

    # 先排除阴性行：'No infected objects found' 里也含 infected，直接匹配会误报检出
    negative = re.compile(r"\b(?:no|0|zero|not)\s+(?:virus|viruses|threat|threats|infected|malware)", re.I)
    detections: list[dict] = []
    for line in text.splitlines():
        if negative.search(line):
            continue
        low = line.lower()
        if "infected" in low or "threat found" in low:
            detections.append({"threat": line.strip()[:200], "file": ""})

    if detections:
        return INFECTED, detections, f"检出 {len(detections)} 行"
    if negative.search(text) or re.search(r"\bclean\b", text, re.I):
        return CLEAN, [], "输出显示无检出"
    if rc == 0 and text.strip():
        return CLEAN, [], "报告存在且无感染记录"
    return UNKNOWN, [], f"退出码 {rc}，未找到可读的扫描报告（Stinger 参数随版本而异，可回退人工扫描）"


def _parse_mbam(stdout: str, stderr: str, rc: int | None, outdir: Path):
    text = _text_of(stdout, stderr) + "\n" + _read_report(outdir / "mbam.report.txt")
    detections: list[dict] = []
    for m in re.finditer(r"^\s*(?:Detected|Detection)\s*[:：]\s*(.+)", text, re.I | re.M):
        detections.append({"threat": m.group(1).strip(), "file": ""})
    if detections:
        return INFECTED, detections, f"检出 {len(detections)} 项"
    if re.search(r"no\s+(?:threats?|detections?)\s+(?:found|detected)", text, re.I):
        return CLEAN, [], "输出显示无检出"
    return UNKNOWN, [], f"退出码 {rc}，免费版通常不输出可解析结果"


# ---- 命令构造 -------------------------------------------------------------
def _build_defender(exe: Path, target: Path, outdir: Path) -> list[str]:
    # -ScanType 3 = 自定义文件/目录扫描；-DisableRemediation = 只检测不处置，
    # 同时会忽略排除项并深入扫描压缩包，适合发布前取证式扫描。
    return [
        str(exe),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(target),
        "-DisableRemediation",
        "-CpuThrottling",
    ]


def _build_kaspersky(exe: Path, target: Path, outdir: Path) -> list[str]:
    report = outdir / "kaspersky.report.txt"
    return [str(exe), "SCAN", str(target), f"/RA:{report}"]


def _build_avira(exe: Path, target: Path, outdir: Path) -> list[str]:
    log = outdir / "avira.log"
    return [str(exe), f"/PATH={target}", "/GUIMODE=2", f"/LOG={log}"]


def _build_avast(exe: Path, target: Path, outdir: Path) -> list[str]:
    return [str(exe), str(target), "/_", "/SHOWRESULTS"]


def _build_stinger(exe: Path, target: Path, outdir: Path) -> list[str]:
    # Stinger 是 GUI 程序：-scan 触发扫描，-sfx 静默不弹窗，-log 指定报告目录。
    # 早先用的 /SCAN= /REPORT= /SILENT /GO 不是 McAfee 的真实参数，Stinger 会直接退出码 6。
    return [str(exe), "-scan", "-sfx", "-log", str(outdir), str(target)]


def _build_mbam(exe: Path, target: Path, outdir: Path) -> list[str]:
    return [str(exe), "/scan", "-silent"]


# ---- 版本选择 -------------------------------------------------------------
def _pick_newest_defender(cands: list[Path]) -> Path:
    def version_key(p: Path):
        m = re.match(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", p.parent.name)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0, 0)

    return max(cands, key=version_key)


# ---- 引擎定义 -------------------------------------------------------------
@dataclass(frozen=True)
class Engine:
    key: str
    display: str
    vendor: str
    order: int
    tier: str                          # auto | manual
    probes: tuple[str, ...] = ()
    reg_keywords: tuple[str, ...] = ()
    build: BuildFn | None = None
    parse: ParseFn | None = None
    pick: PickFn | None = None
    db: Callable[[], tuple[str | None, str | None]] | None = None
    availability: Callable[[], tuple[bool, str]] | None = None
    caveats: tuple[str, ...] = ()
    default_timeout: int = 1800
    gui_hint: str = ""


ENGINES: tuple[Engine, ...] = (
    Engine(
        key="huorong",
        display="火绒安全软件",
        vendor="火绒",
        order=1,
        tier="manual",
        probes=(
            "Huorong/Sysdiag/bin/HipsMain.exe",
            "Huorong/Sysdiag/HipsMain.exe",
        ),
        reg_keywords=("火绒", "huorong"),
        caveats=("无官方命令行扫描接口。首选右键目标「使用火绒安全进行杀毒」；"
                 "也可在主界面「病毒查杀 → 自定义查杀」中指定目录。",),
        gui_hint="右键目标 → 火绒安全软件 → 使用火绒安全进行杀毒",
    ),
    Engine(
        key="360",
        display="360 安全卫士 / 360 杀毒",
        vendor="360",
        order=2,
        tier="manual",
        probes=(
            "360/360sd/360sd.exe",
            "360/360Safe/360Safe.exe",
            "360/360Safe/safemon/360Tray.exe",
            "360/360sd/360rp.exe",
        ),
        reg_keywords=("360",),
        caveats=("无稳定命令行扫描接口；扫描结果需在 GUI 内查看后回填。",),
        gui_hint="木马查杀 → 自定义扫描 → 添加目录 → 开始扫描",
    ),
    Engine(
        key="qqpcmgr",
        display="腾讯电脑管家",
        vendor="腾讯",
        order=3,
        tier="manual",
        probes=(
            "Tencent/QQPCMgr/QQPCMgr.exe",
            "Tencent/QQPCMgr/*/QQPCMgr.exe",
            "Tencent/QQPCMgr/*/QQPCMgr*.exe",
        ),
        reg_keywords=("电脑管家", "QQPCMgr"),
        caveats=("无命令行扫描接口。",),
        gui_hint="病毒查杀 → 指定位置查杀 → 选择目录 → 开始扫描",
    ),
    Engine(
        key="avira",
        display="Avira",
        vendor="Avira",
        order=4,
        tier="auto",
        probes=(
            "Avira/Antivirus/avscan.exe",
            "Avira/*/avscan.exe",
            "Avira/*/*/avscan.exe",
        ),
        reg_keywords=("Avira",),
        build=_build_avira,
        parse=_parse_avira,
        caveats=("avscan.exe 的 GUIMODE 与 LOG 参数在不同版本间有差异，建议先 --dry-run 核对。",),
        default_timeout=2400,
    ),
    Engine(
        key="malwarebytes",
        display="Malwarebytes",
        vendor="Malwarebytes",
        order=5,
        tier="auto",
        probes=(
            "Malwarebytes/Anti-Malware/MBAMCmd.exe",
            "Malwarebytes/Anti-Malware/mbam.exe",
            "Malwarebytes/MBAM/MBAMCmd.exe",
        ),
        reg_keywords=("Malwarebytes",),
        build=_build_mbam,
        parse=_parse_mbam,
        caveats=(
            "免费版 mbam.exe 不接受指定路径，仅商业版支持命令行定向扫描；",
            "免费版请回退为人工：Scan → Custom Scan 勾选目标目录。",
        ),
        gui_hint="Scanner → Custom Scan → Configure Scan → 勾选目标目录",
        default_timeout=3600,
    ),
    Engine(
        key="stinger",
        display="McAfee Stinger",
        vendor="McAfee",
        order=6,
        tier="auto",
        probes=(
            "stinger/stinger64.exe",
            "stinger/stinger.exe",
            "McAfee/Stinger/stinger.exe",
            "Stinger/stinger.exe",
            "McAfee/*/stinger.exe",
        ),
        reg_keywords=("Stinger",),
        build=_build_stinger,
        parse=_parse_stinger,
        caveats=(
            "Stinger 为按需绿色扫描器，无需常驻，适合与其它杀软并存。",
            "必须以管理员身份运行，否则启动报 WinError 740（需要提升）。",
        ),
        default_timeout=2400,
    ),
    Engine(
        key="kaspersky",
        display="卡巴斯基",
        vendor="Kaspersky",
        order=7,
        tier="auto",
        probes=(
            "Kaspersky Lab/*/avp.com",
            "Kaspersky Lab/*/avp.exe",
            "Kaspersky Lab/*/*/avp.com",
        ),
        reg_keywords=("Kaspersky", "卡巴斯基"),
        build=_build_kaspersky,
        parse=_parse_kaspersky,
        caveats=("若产品设置了管理密码，CLI 需要追加 /password:<pwd>。",),
        default_timeout=3600,
    ),
    Engine(
        key="avast",
        display="Avast",
        vendor="Avast",
        order=8,
        tier="auto",
        probes=(
            "Avast Software/Avast/ashCmd.exe",
            "Avast Software/Avast/*/ashCmd.exe",
        ),
        reg_keywords=("Avast",),
        build=_build_avast,
        parse=_parse_avast,
        caveats=("新版 Avast 可能已移除 ashCmd，探测不到时请走人工扫描。",),
        default_timeout=2400,
    ),
    Engine(
        key="defender",
        display="Windows Defender",
        vendor="Microsoft",
        order=9,
        tier="auto",
        probes=(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        ),
        build=_build_defender,
        parse=_parse_defender,
        pick=_pick_newest_defender,
        db=_defender_db,
        availability=_defender_availability,
        caveats=(
            "安装第三方杀软后 Defender 会进入被动模式，实时防护关闭，但按需扫描仍可用。",
        ),
        default_timeout=1800,
    ),
)

ENGINE_MAP: dict[str, Engine] = {e.key: e for e in ENGINES}


# ---- 探测 -----------------------------------------------------------------
@dataclass
class EngineStatus:
    engine: Engine
    installed: bool
    exe: Path | None = None
    version: str | None = None
    db_version: str | None = None
    db_date: str | None = None
    ready: bool = False
    reason: str = ""
    path_source: str = ""  # "" 自动探测 / "manual" 用户手动指定

    @property
    def key(self) -> str:
        return self.engine.key

    @property
    def runnable(self) -> bool:
        # ready=False 的（如 Defender 被禁用、缺命令模板）不该被勾选去跑
        return (
            self.engine.tier == "auto"
            and self.installed
            and self.exe is not None
            and self.ready
        )


def _candidates(engine: Engine, roots: list[Path], reg_dirs: list[Path]) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    for pattern in engine.probes:
        if re.match(r"^[A-Za-z]:[\\/]", pattern):
            matches = globmod.glob(pattern)
        else:
            matches = []
            for root in roots:
                matches.extend(globmod.glob(str(root / pattern)))
            for base in reg_dirs:
                matches.extend(globmod.glob(str(base / pattern)))
        for m in matches:
            p = Path(m)
            if p.is_file():
                key = str(p).lower()
                if key not in seen:
                    seen.add(key)
                    found.append(p)

    return found


def probe_engine(engine: Engine, roots: list[Path], reg_dirs: list[Path]) -> EngineStatus:
    # 用户手动指定的路径优先。指定了就不再自动探测——否则"改了没生效"最难排查。
    override = get_override(engine.key)
    if override:
        p = Path(override).expanduser()
        if not p.is_file():
            return EngineStatus(
                engine=engine,
                installed=False,
                reason=f"手动指定的路径不存在：{p}",
                path_source="manual",
            )
        db_version = db_date = None
        if engine.db is not None:
            db_version, db_date = engine.db()
        manual_reason = "路径为手动指定"
        return EngineStatus(
            engine=engine,
            installed=True,
            exe=p,
            version=file_version(p),
            db_version=db_version,
            db_date=db_date,
            ready=engine.tier == "auto",
            reason=manual_reason if engine.tier == "auto" else f"仅 GUI（{manual_reason}）",
            path_source="manual",
        )

    products = registry_products(engine.reg_keywords) if engine.reg_keywords else []
    extra_dirs = [
        Path(p["location"])
        for p in products
        if p.get("location") and Path(p["location"]).is_dir()
    ]
    candidates = _candidates(engine, roots, reg_dirs + extra_dirs)

    if not candidates:
        return EngineStatus(engine=engine, installed=False, reason="未检测到安装")

    exe = engine.pick(candidates) if engine.pick else candidates[0]
    # 产品版本优先取注册表 DisplayVersion（用户看到的版本号），退回 PE 文件版本
    version = next((p["version"] for p in products if p.get("version")), None) or file_version(exe)

    db_version = db_date = None
    if engine.db is not None:
        db_version, db_date = engine.db()

    if engine.tier == "manual":
        return EngineStatus(
            engine=engine,
            installed=True,
            exe=exe,
            version=version,
            db_version=db_version,
            db_date=db_date,
            ready=False,
            reason="仅 GUI，需人工扫描",
        )

    if engine.build is None or engine.parse is None:
        return EngineStatus(
            engine=engine,
            installed=True,
            exe=exe,
            version=version,
            ready=False,
            reason="缺少命令模板",
        )

    # 环境性不可用：装了第三方杀软、策略禁用、服务停掉等。
    # 这类情况要提前说清楚，别白跑一趟再报"扫描出错"。
    if engine.availability is not None:
        ok, why = engine.availability()
        if not ok:
            return EngineStatus(
                engine=engine,
                installed=True,
                exe=exe,
                version=version,
                db_version=db_version,
                db_date=db_date,
                ready=False,
                reason=why,
            )

    return EngineStatus(
        engine=engine,
        installed=True,
        exe=exe,
        version=version,
        db_version=db_version,
        db_date=db_date,
        ready=True,
        reason="可自动执行",
    )


def _local_tool_roots() -> list[Path]:
    """项目内 tools/ 目录：存放免安装的便携扫描器（EEK / KVRT / Stinger 等）。"""
    base = data_dir("tools")
    return [base] if base.is_dir() else []


def probe_all(engines: tuple[Engine, ...] | list[Engine] | None = None) -> list[EngineStatus]:
    roots = program_roots() + _local_tool_roots()
    selected = tuple(engines) if engines else ENGINES
    return [probe_engine(e, roots, []) for e in selected]


def select_engines(spec: str) -> list[Engine]:
    """--engines all|auto|manual|defender,kaspersky"""
    if not spec or spec.strip().lower() == "all":
        return list(ENGINES)
    if spec.strip().lower() == "auto":
        return [e for e in ENGINES if e.tier == "auto"]
    if spec.strip().lower() == "manual":
        return [e for e in ENGINES if e.tier == "manual"]

    wanted = [s.strip().lower() for s in spec.split(",") if s.strip()]
    unknown = [w for w in wanted if w not in ENGINE_MAP]
    if unknown:
        raise ValueError(
            f"未知引擎: {', '.join(unknown)}\n可用: {', '.join(ENGINE_MAP)}"
        )
    return [ENGINE_MAP[w] for w in wanted]
