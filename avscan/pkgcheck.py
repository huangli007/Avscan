"""安装包静态体检：全程只读文件，不执行任何代码。

回答四个问题：
  1. 这是什么文件（PE 结构、位数、子系统、编译时间）
  2. 用什么打包/安装框架（NSIS / Inno / InstallShield / MSI / SFX）
  3. 有没有壳或可疑特征（UPX 等）
  4. 静默安装该传什么参数

刻意不做：不运行、不解压到磁盘、不调用安装程序。
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---- PE ------------------------------------------------------------------
_MACHINES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0xAA64: "ARM64",
    0x01C4: "ARM",
    0x0200: "IA64",
}
_SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    9: "Windows CE GUI",
    10: "EFI Application",
}

# 安装器 / 打包器特征字符串（ASCII + UTF-16LE 两种编码都会找）
_MARKERS: dict[str, tuple[bytes, ...]] = {
    "NSIS": (b"Nullsoft.NSIS", b"Nullsoft Install System", b"NSIS Error"),
    "Inno Setup": (b"Inno Setup", b"InnoSetupVersion", b"Inno Setup Setup:"),
    "InstallShield": (b"InstallShield", b"ISSetupStream", b"InstallShield Wizard"),
    "WiX Burn": (b"WixBundle", b"BurnStub", b"wixburn"),
    "7-Zip SFX": (b"7-Zip SFX", b"7zS.sfx", b"7zCon.sfx"),
    "WinRAR SFX": (b"WinRAR SFX", b"WinRAR self-extracting"),
    "MSI": (b"Windows Installer", b"MsiExec"),
    "InstallAware": (b"InstallAware",),
    "Wise Installer": (b"Wise Installation", b"WiseMain"),
}

_PACKERS: dict[str, tuple[bytes, ...]] = {
    "UPX": (b"UPX0", b"UPX1", b"UPX!"),
    "ASPack": (b"ASPack",),
    "Themida": (b"Themida",),
    "VMProtect": (b"VMProtect",),
    "Enigma": (b"Enigma Protector",),
}

# 常见静默安装参数（按安装框架推断，实际以厂商文档为准）
_SILENT_HINT = {
    "NSIS": '/S   （可选 /D=<安装目录>，注意 /D 必须放最后且不加引号）',
    "Inno Setup": '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART   （可选 /DIR="<目录>"）',
    "InstallShield": '/s /v"/qn"   （MSI 参数需转义）',
    "WiX Burn": '/quiet /norestart   （可选 /log <file>）',
    "MSI": 'msiexec /i "<msi>" /qn /norestart /l*v "<log>"',
    "7-Zip SFX": '/S   （部分 SFX 支持 -o<目录> -y）',
    "WinRAR SFX": '/S   （静默解压，参数由 SFX 模块决定）',
}


# PE 节名特征。分两类：加壳 / 保护器（影响可信度），以及编译产物线索（中性信息）。
_SECTION_PACKERS = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    ".VMP0": "VMProtect",
    ".VMP1": "VMProtect",
    ".THEMIDA": "Themida",
    ".ENIGMA1": "Enigma Protector",
    ".ENIGMA2": "Enigma Protector",
    ".ASPACK": "ASPack",
    ".PACKED": "通用加壳段",
    ".MPRESS1": "MPRESS",
    ".MPRESS2": "MPRESS",
}
_SECTION_HINTS = {
    ".DETOURC": "Microsoft Detours（API Hook 库）",
    ".DETOURD": "Microsoft Detours（API Hook 库）",
    ".NDATA": "NSIS 安装器数据段",
    ".DIDAT": "Delphi 编译产物",
    ".RLOC": "Delphi 编译产物",
    ".TLS": "含线程局部存储段",
}


@dataclass
class PEInfo:
    is_pe: bool = False
    machine: str = ""
    subsystem: str = ""
    magic: str = ""
    timestamp: str = ""
    sections: list[str] = field(default_factory=list)
    is_dotnet: bool = False
    entry_point: int = 0
    note: str = ""


def _fmt_ts(value: int) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


def parse_pe(path: Path) -> PEInfo:
    try:
        with open(path, "rb") as f:
            head = f.read(0x600)
    except OSError as exc:
        return PEInfo(note=f"读取失败：{exc}")

    if len(head) < 0x40 or head[:2] != b"MZ":
        return PEInfo(note="不是 PE 文件（缺少 MZ 头）")

    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew + 0x108 > len(head) or head[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return PEInfo(note="PE 头损坏或非标准")

    machine, n_sections, tstamp = struct.unpack_from("<HHI", head, e_lfanew + 4)
    opt_off = e_lfanew + 24
    # SizeOfOptionalHeader 在 COFF 头偏移 16，即 e_lfanew+4+16
    size_of_opt = struct.unpack_from("<H", head, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", head, opt_off)[0]
    subsystem = struct.unpack_from("<H", head, opt_off + 68)[0]
    entry = struct.unpack_from("<I", head, opt_off + 16)[0]

    # .NET 检测：CLR Runtime Header 是数据目录第 15 项（索引 14）
    is_dotnet = False
    dd_off = opt_off + (96 if magic == 0x10B else 112)
    clr_off = dd_off + 14 * 8
    if opt_off + size_of_opt > clr_off + 8 and clr_off + 8 <= len(head):
        clr_rva, clr_size = struct.unpack_from("<II", head, clr_off)
        is_dotnet = clr_rva != 0 and clr_size != 0

    sections: list[str] = []
    sect_off = opt_off + size_of_opt
    for i in range(min(n_sections, 16)):
        base = sect_off + i * 40
        if base + 8 > len(head):
            break
        raw = head[base : base + 8].rstrip(b"\0")
        sections.append(raw.decode("latin-1", errors="replace"))

    return PEInfo(
        is_pe=True,
        machine=_MACHINES.get(machine, f"未知(0x{machine:04X})"),
        subsystem=_SUBSYSTEMS.get(subsystem, f"未知({subsystem})"),
        magic={0x10B: "PE32", 0x20B: "PE32+"}.get(magic, f"0x{magic:X}"),
        timestamp=_fmt_ts(tstamp),
        sections=sections,
        is_dotnet=is_dotnet,
        entry_point=entry,
    )


# ---- 特征扫描 --------------------------------------------------------------
def _find_all(buf: mmap.mmap, needles: tuple[bytes, ...]) -> list[str]:
    """同时在 ASCII 与 UTF-16LE 两种编码下找特征串。"""
    hits: list[str] = []
    for needle in needles:
        if buf.find(needle) >= 0:
            hits.append(needle.decode("latin-1"))
            continue
        wide = needle.decode("latin-1").encode("utf-16-le")
        if buf.find(wide) >= 0:
            hits.append(needle.decode("latin-1") + "(UTF-16)")
    return hits


def scan_signatures(path: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """返回 (安装器特征, 壳特征)。"""
    installer_hits: dict[str, list[str]] = {}
    packer_hits: dict[str, list[str]] = {}

    try:
        with open(path, "rb") as f:
            size = path.stat().st_size
            if size == 0:
                return {}, {}
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                for name, needles in _MARKERS.items():
                    hits = _find_all(buf, needles)
                    if hits:
                        installer_hits[name] = hits
                for name, needles in _PACKERS.items():
                    hits = _find_all(buf, needles)
                    if hits:
                        packer_hits[name] = hits
    except (OSError, ValueError):
        pass

    return installer_hits, packer_hits


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest().upper()


# ---- Windows 签名与版本（借 PowerShell 批量取） ---------------------------
_PS_SIGN = r"""
$ErrorActionPreference='SilentlyContinue'
$list = Get-Content -LiteralPath '__LIST__' -Encoding utf8
$rows = $list | Where-Object { $_ } | ForEach-Object {
  $p = $_.Trim()
  $f = Get-Item -LiteralPath $p
  $sig = Get-AuthenticodeSignature -LiteralPath $p
  $v = $f.VersionInfo
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
  [PSCustomObject]@{
    path = $p
    status = [string]$sig.Status
    subject = $subject
    company = $v.CompanyName
    product = $v.ProductName
    file_version = $v.FileVersion
    description = $v.FileDescription
  }
}
$rows | ConvertTo-Json -Compress -Depth 3 | Out-File -LiteralPath '__OUT__' -Encoding utf8
"""


def fetch_signatures(paths: list[Path]) -> dict[str, dict]:
    """用 PowerShell 批量取签名与版本信息。

    两个坑都要绕：中文字段经管道回传会被系统代码页破坏；中文路径经 stdin 传入会失真。
    所以路径走 UTF-8 临时文件进，结果走 UTF-8 临时文件出。
    """
    if not paths:
        return {}

    tmp_dir = Path(tempfile.gettempdir())
    list_file = tmp_dir / f"avscan_paths_{os.getpid()}.txt"
    out_file = tmp_dir / f"avscan_sig_{os.getpid()}.json"

    def _q(p: Path) -> str:
        return str(p).replace("'", "''")

    script = _PS_SIGN.replace("__LIST__", _q(list_file)).replace("__OUT__", _q(out_file))

    try:
        list_file.write_text("\n".join(str(p) for p in paths), encoding="utf-8")
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=240,
        )
        if not out_file.is_file():
            return {}
        raw = out_file.read_text(encoding="utf-8-sig", errors="replace").strip()
    except (OSError, subprocess.SubprocessError):
        return {}
    finally:
        for tmp in (list_file, out_file):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(data, dict):
        data = [data]
    return {str(item.get("path", "")).lower(): item for item in data if isinstance(item, dict)}


def _short_signer(subject: str) -> str:
    if not subject:
        return ""
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip('"')
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:].strip('"')
    return subject[:60]


# ---- 汇总 ------------------------------------------------------------------
@dataclass
class PkgReport:
    path: str
    name: str
    size: int
    sha256: str
    is_pe: bool
    machine: str
    subsystem: str
    compiled: str
    dotnet: bool
    sections: list[str]
    installer: str
    installer_evidence: list[str]
    packers: list[str]
    signer: str
    sign_status: str
    product: str
    version: str
    silent_hint: str
    notes: list[str]
    vt_url: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _pick_installer(hits: dict[str, list[str]]) -> tuple[str, list[str]]:
    if not hits:
        return "未识别", []
    # 命中多个时按特异性排序
    priority = ["WiX Burn", "InstallShield", "Inno Setup", "NSIS", "InstallAware", "Wise Installer", "MSI", "7-Zip SFX", "WinRAR SFX"]
    for name in priority:
        if name in hits:
            return name, hits[name]
    name = next(iter(hits))
    return name, hits[name]


def inspect_one(path: Path, sig_map: dict[str, dict]) -> PkgReport:
    pe = parse_pe(path)
    installer_hits, packer_hits = scan_signatures(path)
    installer, evidence = _pick_installer(installer_hits)
    digest = sha256_of(path)
    sig = sig_map.get(str(path).lower(), {})

    notes: list[str] = []
    size_mb = path.stat().st_size / (1024 * 1024)

    # 加壳只认结构证据（PE 节名），字符串命中仅作弱提示——
    # 大文件里出现 "UPX!" 往往只是内嵌组件或资源引用。
    section_packers = [
        _SECTION_PACKERS[s.upper()] for s in pe.sections if s.upper() in _SECTION_PACKERS
    ]
    packers: list[str] = []
    if section_packers:
        packers.append("、".join(dict.fromkeys(section_packers)) + f"（节名 {', '.join(pe.sections)}）")

    section_notes = [
        _SECTION_HINTS[s.upper()] for s in pe.sections if s.upper() in _SECTION_HINTS
    ]
    for hint in dict.fromkeys(section_notes):
        notes.append(f"节区特征：{hint}")

    weak_hits = [
        f"{k}: {', '.join(v)}"
        for k, v in packer_hits.items()
        if not (k == "UPX" and section_packers)
    ]

    # 在线安装器判定：体积极小且无内嵌载荷迹象
    if size_mb < 15:
        notes.append("体积极小，疑似在线安装器/下载器：本身不含杀毒引擎，运行后联网下载主体")
    if pe.is_pe and "Windows GUI" in pe.subsystem and size_mb > 40:
        notes.append("GUI 子系统 + 大体积，典型离线完整包")
    if pe.is_dotnet and size_mb > 100:
        notes.append(".NET 程序集，体积大可能含内嵌资源")

    # PE 时间戳可信度
    if pe.timestamp:
        try:
            year = int(pe.timestamp[:4])
            if year < 2005 or year > datetime.now().year + 1:
                notes.append(f"PE 时间戳异常（{pe.timestamp}），多为链接器默认值或被刻意设置，不能当作真实编译时间")
        except ValueError:
            pass

    if weak_hits:
        notes.append(
            "字符串中发现打包器标记（"
            + "; ".join(weak_hits)
            + "），多为内嵌组件的正常引用，未构成加壳结论"
        )

    if not pe.is_pe:
        notes.append("不是标准 PE 文件，可能已损坏或为其它封装格式")

    return PkgReport(
        path=str(path),
        name=path.name,
        size=path.stat().st_size,
        sha256=digest,
        is_pe=pe.is_pe,
        machine=pe.machine,
        subsystem=pe.subsystem,
        compiled=pe.timestamp,
        dotnet=pe.is_dotnet,
        sections=pe.sections,
        installer=installer,
        installer_evidence=evidence,
        packers=packers,
        signer=_short_signer(sig.get("subject", "")),
        sign_status=sig.get("status", "未知"),
        product=sig.get("product", "") or "",
        version=sig.get("file_version", "") or "",
        silent_hint=_SILENT_HINT.get(installer, ""),
        notes=notes,
        vt_url=f"https://www.virustotal.com/gui/file/{digest}",
    )


def inspect_paths(paths: list[Path]) -> list[PkgReport]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".exe", ".msi", ".msix", ".appx")))
        elif p.is_file():
            files.append(p)

    sig_map = fetch_signatures(files)
    return [inspect_one(f, sig_map) for f in files]
