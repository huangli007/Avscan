"""资源管理器右键菜单注册。

用注册表静态动词实现，不写 Shell 扩展 DLL —— 后者要编译 C++、崩溃会拖垮整个资源管理器。
写入位置全部在 HKEY_CURRENT_USER，不需要管理员权限，可随时撤销。

注册三个入口：
  · 任意文件  → 用 avscan 扫描
  · 任意文件夹 → 用 avscan 扫描
  · 文件夹空白处 → 扫描当前目录
"""

from __future__ import annotations

import re
import sys
import winreg
from pathlib import Path

MENU_KEY = "avscan"
MENU_TITLE = "用 avscan 扫描"
# 允许一次选中多个文件时只启动一个实例
MULTI_SELECT = "Player"

_TARGETS = (
    ("*", "%1"),                       # 任意文件
    ("Directory", "%1"),               # 文件夹
    ("Directory\\Background", "%V"),   # 文件夹空白处（当前目录）
)


def _exe_path(exe: str | Path | None = None) -> Path:
    if exe is not None:
        return Path(exe).resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    # 源码运行时无法用右键菜单（需要 python 解释器），返回项目根便于提示
    return Path(sys.argv[0]).resolve()


def _command(exe: Path, placeholder: str) -> str:
    if getattr(sys, "frozen", False) or exe.suffix.lower() == ".exe":
        return f'"{exe}" --scan "{placeholder}"'
    # 源码运行：带上解释器与 app.py
    app_py = exe.parent / "app.py"
    return f'"{sys.executable}" "{app_py}" --scan "{placeholder}"'


def _key_path(subkey: str) -> str:
    return rf"Software\Classes\{subkey}\shell\{MENU_KEY}"


def install(exe: str | Path | None = None) -> tuple[bool, str]:
    target = _exe_path(exe)
    if not target.is_file():
        return False, f"可执行文件不存在：{target}"

    done: list[str] = []
    for subkey, placeholder in _TARGETS:
        verb = _key_path(subkey)
        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, verb, 0, winreg.KEY_WRITE
            ) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, MENU_TITLE)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f"{target},0")
                winreg.SetValueEx(key, "MultiSelectModel", 0, winreg.REG_SZ, MULTI_SELECT)

            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, verb + r"\command", 0, winreg.KEY_WRITE
            ) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, _command(target, placeholder))
            done.append(subkey)
        except OSError as exc:
            return False, f"写入 {subkey} 失败：{exc}"

    return True, "已注册右键菜单（{} 处）：{}".format(len(done), "、".join(done))


def uninstall() -> tuple[bool, str]:
    removed = 0
    for subkey, _ in _TARGETS:
        verb = _key_path(subkey)
        for path in (verb + r"\command", verb):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
                removed += 1
            except FileNotFoundError:
                continue
            except OSError as exc:
                return False, f"删除 {path} 失败：{exc}"
    if removed == 0:
        return True, "右键菜单本来就没装"
    return True, "已移除右键菜单"


def status(exe: str | Path | None = None) -> list[dict]:
    """检查注册状态。不比对"当前程序"，因为注册的可能是另一个位置的 exe。"""
    rows: list[dict] = []

    for subkey, _ in _TARGETS:
        verb = _key_path(subkey)
        entry = {
            "target": subkey,
            "installed": False,
            "command": "",
            "exe": "",
            "exe_exists": False,
        }
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, verb + r"\command", 0, winreg.KEY_READ
            ) as key:
                cmd, _ = winreg.QueryValueEx(key, "")
                entry["installed"] = True
                entry["command"] = cmd
                # 取出第一个引号内路径，判断目标程序是否还在
                match = re.search(r'"([^"]+)"', cmd)
                if match:
                    entry["exe"] = match.group(1)
                    entry["exe_exists"] = Path(match.group(1)).is_file()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        rows.append(entry)
    return rows
