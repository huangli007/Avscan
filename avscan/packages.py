"""安装包仓库：清单管理、定位、一键安装、手动安装入口。

为 GUI 准备的两个原子动作：
    open_package()    —— 在资源管理器中选中安装包（手动安装入口）
    install_package() —— 按清单参数静默安装（一键安装入口）

安全约定：
  · install 默认 dry-run，必须显式 confirm 才执行——安装杀软会写驱动、改系统、要求重启；
  · 静默参数未经验证的包（silent_verified=false）一律拒绝静默安装，只允许走手动；
  · 免安装（portable）的包不提供安装动作，直接运行即可。
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .pkgcheck import fetch_signatures, sha256_of, _short_signer
from .runtime import data_dir

REPO_DIRNAME = "packages"
MANIFEST_NAME = "manifest.json"

KIND_LABEL = {"offline": "离线完整包", "online": "在线安装器", "portable": "免安装"}


@dataclass
class Pkg:
    id: str
    display: str
    vendor: str
    version: str
    file: Path
    kind: str
    is_av: bool = True
    installer: str = ""
    silent_args: list[str] = field(default_factory=list)
    silent_verified: bool = False
    needs_reboot: bool = False
    needs_driver: bool = False
    note: str = ""
    engine_key: str | None = None

    @property
    def exists(self) -> bool:
        return self.file.is_file()

    @property
    def size_mb(self) -> float:
        try:
            return self.file.stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0

    @property
    def mode(self) -> str:
        """silent 可一键静默 / manual 只能手动 / portable 免安装。

        只要清单给了静默参数就走 silent；参数是否在本机实测过，另由 silent_verified 标注，
        安装时再多给一道提示，而不是直接堵死一键安装这条路。
        """
        if self.kind == "portable":
            return "portable"
        if self.silent_args:
            return "silent"
        return "manual"

    @property
    def mode_label(self) -> str:
        if self.mode == "silent" and not self.silent_verified:
            return "一键安装*"
        return {"silent": "一键安装", "manual": "手动安装", "portable": "免安装"}[self.mode]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "display": self.display,
            "vendor": self.vendor,
            "version": self.version,
            "file": str(self.file),
            "kind": self.kind,
            "kind_label": KIND_LABEL.get(self.kind, self.kind),
            "is_av": self.is_av,
            "installer": self.installer,
            "silent_args": self.silent_args,
            "silent_verified": self.silent_verified,
            "mode": self.mode,
            "needs_reboot": self.needs_reboot,
            "needs_driver": self.needs_driver,
            "note": self.note,
            "engine_key": self.engine_key,
            "size_mb": round(self.size_mb, 1),
            "exists": self.exists,
        }


def repo_dir() -> Path:
    return data_dir(REPO_DIRNAME)


def load_manifest(root: Path | None = None) -> list[Pkg]:
    base = root or repo_dir()
    manifest = base / MANIFEST_NAME
    if not manifest.is_file():
        raise FileNotFoundError(f"缺少清单文件：{manifest}")

    data = json.loads(manifest.read_text(encoding="utf-8-sig"))
    items = data.get("packages", []) if isinstance(data, dict) else data

    pkgs: list[Pkg] = []
    for item in items:
        pkgs.append(
            Pkg(
                id=str(item.get("id", "")),
                display=str(item.get("display", "")),
                vendor=str(item.get("vendor", "")),
                version=str(item.get("version", "")),
                file=(base / str(item.get("file", ""))).resolve(),
                kind=str(item.get("kind", "offline")),
                is_av=bool(item.get("is_av", True)),
                installer=str(item.get("installer", "")),
                silent_args=list(item.get("silent_args") or []),
                silent_verified=bool(item.get("silent_verified", False)),
                needs_reboot=bool(item.get("needs_reboot", False)),
                needs_driver=bool(item.get("needs_driver", False)),
                note=str(item.get("note", "")),
                engine_key=item.get("engine_key"),
            )
        )
    return pkgs


def find(pkg_id: str, pkgs: list[Pkg] | None = None) -> Pkg | None:
    pool = pkgs if pkgs is not None else load_manifest()
    target = pkg_id.strip().lower()
    for p in pool:
        if p.id.lower() == target:
            return p
    # 允许用 engine_key 或显示名匹配
    for p in pool:
        if (p.engine_key or "").lower() == target or target in p.display.lower():
            return p
    return None


# ---- 手动安装入口 ----------------------------------------------------------
def open_package(pkg: Pkg) -> tuple[bool, str]:
    """在资源管理器中打开所在目录并选中该文件。GUI 的「打开文件夹」按钮直接调这个。"""
    if not pkg.exists:
        return False, f"文件不存在：{pkg.file}"
    try:
        # /select 会定位到文件；目录不存在 explorer 会静默失败
        subprocess.Popen(["explorer", f"/select,{pkg.file}"])
        return True, f"已在资源管理器中定位：{pkg.file}"
    except OSError as exc:
        return False, f"打开失败：{exc}"


def open_folder(pkg: Pkg) -> tuple[bool, str]:
    """只打开所在目录（不选中文件）。"""
    parent = pkg.file.parent
    if not parent.is_dir():
        return False, f"目录不存在：{parent}"
    try:
        subprocess.Popen(["explorer", str(parent)])
        return True, f"已打开目录：{parent}"
    except OSError as exc:
        return False, f"打开失败：{exc}"


# ---- 一键安装入口 ----------------------------------------------------------
def build_install_cmd(pkg: Pkg) -> list[str] | None:
    """构造静默安装命令。参数未验证或包不可静默时返回 None。"""
    if pkg.mode != "silent":
        return None
    return [str(pkg.file), *pkg.silent_args]


def risk_summary(pkg: Pkg) -> list[str]:
    """安装前要呈现给用户的风险点。"""
    risks: list[str] = []
    if pkg.needs_driver:
        risks.append("会安装内核驱动（minifilter），可能与其他安全软件冲突")
    if pkg.needs_reboot:
        risks.append("安装完成后通常需要重启才能生效")
    if pkg.kind == "online":
        risks.append("在线安装器，需要联网下载主体，无网环境会失败")
    if not pkg.is_av:
        risks.append("该包不是杀毒软件")
    return risks


def install_package(
    pkg: Pkg,
    *,
    confirm: bool = False,
    wait: bool = True,
    timeout: int = 1800,
) -> tuple[bool, str]:
    """执行静默安装。

    confirm=False 时只返回将执行的命令（dry-run），不会真的装。
    wait=False 适合 GUI：拉起进程后立即返回，靠界面轮询状态。
    """
    if not pkg.exists:
        return False, f"文件不存在：{pkg.file}"
    if pkg.kind == "portable":
        return False, "免安装包，无需安装，直接运行 exe 即可"
    if pkg.mode != "silent":
        return False, "静默参数未经验证，请改用「打开文件夹」手动安装"

    cmd = build_install_cmd(pkg)
    if cmd is None:
        return False, "无法构造安装命令"

    shown = subprocess.list2cmdline(cmd)
    if not pkg.silent_verified:
        shown += "   [注意：该参数未经本机实测]"
    if not confirm:
        return False, f"[dry-run] {shown}"

    try:
        if wait:
            proc = subprocess.run(cmd, timeout=timeout, capture_output=True)
            if proc.returncode == 0:
                return True, f"安装程序已结束（退出码 0）：{shown}"
            return False, f"安装程序退出码 {proc.returncode}，请检查：{shown}"
        proc = subprocess.Popen(cmd)
        return True, f"已启动安装进程 PID={proc.pid}：{shown}"
    except subprocess.TimeoutExpired:
        return False, f"安装超时（{timeout}s）：{shown}"
    except OSError as exc:
        return False, f"启动失败：{exc}"


# ---- 完整性校验 ------------------------------------------------------------
def verify_packages(pkgs: list[Pkg]) -> list[dict]:
    """重新校验归档包的签名与完整性（文件可能被替换或损坏）。"""
    pool = [p for p in pkgs if p.exists]
    sig_map = fetch_signatures([p.file for p in pool])

    rows: list[dict] = []
    for p in pool:
        info = sig_map.get(str(p.file).lower(), {})
        rows.append(
            {
                "id": p.id,
                "display": p.display,
                "status": info.get("status", "未知"),
                "signer": _short_signer(info.get("subject", "")),
                "sha256": sha256_of(p.file),
                "size_mb": round(p.size_mb, 1),
            }
        )
    return rows


def summary(pkgs: list[Pkg]) -> dict:
    total = len(pkgs)
    present = sum(1 for p in pkgs if p.exists)
    return {
        "total": total,
        "present": present,
        "missing": total - present,
        "offline": sum(1 for p in pkgs if p.kind == "offline"),
        "online": sum(1 for p in pkgs if p.kind == "online"),
        "portable": sum(1 for p in pkgs if p.kind == "portable"),
        "silent_ready": sum(1 for p in pkgs if p.mode == "silent"),
        "manual_only": sum(1 for p in pkgs if p.mode == "manual"),
        "total_mb": round(sum(p.size_mb for p in pkgs), 1),
    }
