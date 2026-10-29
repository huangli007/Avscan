"""程序目录发现。

国产安全软件（火绒/360/腾讯管家）经常把安装目录挪到非系统盘，所以不能只查
%ProgramFiles%。这里做两件事：

1. 枚举所有盘符下的常见程序目录；
2. 从「控制面板卸载列表」的 InstallLocation 反查真实安装路径。
"""

from __future__ import annotations

import os
import string
from pathlib import Path

try:  # winreg 仅在 Windows 存在
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]

_PROGRAM_ROOT_NAMES = (
    "Program Files",
    "Program Files (x86)",
    "Programs",
    "Program Files (Arm)",
)

_UNINSTALL_SUBKEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)


def program_roots() -> list[Path]:
    """返回所有可能承载软件安装目录的根路径（去重、保持稳定顺序）。"""
    roots: list[Path] = []
    seen: set[str] = set()

    def _add(p: str | os.PathLike[str]) -> None:
        try:
            rp = Path(p).resolve()
        except OSError:
            return
        key = str(rp).lower()
        if key in seen or not rp.is_dir():
            return
        seen.add(key)
        roots.append(rp)

    # 1) 环境变量声明的标准位置（覆盖 32/64 位与 Arm）
    for var in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "ProgramFiles(Arm)"):
        value = os.environ.get(var)
        if value:
            _add(value)

    # 2) 其余盘符上的同名目录 —— 这是火绒/360 类产品最常见的落点
    if os.name == "nt":
        for letter in string.ascii_uppercase:
            base = Path(f"{letter}:\\")
            try:
                if not base.exists():
                    continue
            except OSError:
                continue
            for name in _PROGRAM_ROOT_NAMES:
                _add(base / name)
            # 少数产品直接在盘符根目录下建自己的文件夹
            _add(base)

    return roots


def registry_products(keywords: tuple[str, ...]) -> list[dict]:
    """从卸载注册表按 DisplayName 关键字取产品信息（名称/版本/安装路径）。"""
    if winreg is None or os.name != "nt":
        return []

    found: list[dict] = []
    seen: set[str] = set()

    access_flags = (
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
    )

    for subkey in _UNINSTALL_SUBKEYS:
        for access in access_flags:
            try:
                root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, access)
            except OSError:
                continue
            with root:
                try:
                    index = 0
                    while True:
                        try:
                            child_name = winreg.EnumKey(root, index)
                        except OSError:
                            break
                        index += 1
                        try:
                            child = winreg.OpenKey(root, child_name)
                        except OSError:
                            continue
                        # 必须在 with 块内读完所有值：句柄关闭后再 QueryValueEx 会抛 OSError
                        with child:
                            try:
                                display, _ = winreg.QueryValueEx(child, "DisplayName")
                            except OSError:
                                continue
                            if not display:
                                continue
                            if not any(kw.lower() in str(display).lower() for kw in keywords):
                                continue
                            key = str(display).lower()
                            if key in seen:
                                continue
                            info: dict = {"display": str(display), "version": "", "location": ""}
                            for value_name, target in (
                                ("DisplayVersion", "version"),
                                ("InstallLocation", "location"),
                            ):
                                try:
                                    value, _ = winreg.QueryValueEx(child, value_name)
                                    info[target] = str(value).strip().strip('"')
                                except OSError:
                                    pass
                            seen.add(key)
                            found.append(info)
                except OSError:
                    continue

    return found
