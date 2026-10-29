"""火绒扫描触发：复用其右键菜单的真实调用协议。

协议来自实测捕获（非文档、非逆向）：

    HipsMain.exe -S <tmpfile>

`<tmpfile>` 内容为待扫描路径，UTF-8 无 BOM，多路径以 `|` 结尾分隔，例如：

    D:\\文档\\项目\\A6B Copilot按键\\Aura|

已知限制：HipsMain 受驱动级自我保护，**非特权进程直接启动会被拒**（WinError 5）。
以管理员身份运行 avscan 时才可能成功；否则只能由用户在资源管理器里点右键菜单。
"""

from __future__ import annotations

import ctypes
import subprocess
import tempfile
from pathlib import Path

DEFAULT_EXE = Path(r"D:\Program Files\Huorong\Sysdiag\bin\HipsMain.exe")
LIST_NAME = "HRS_avscan.tmp"


def is_admin() -> bool:
    """当前进程是否具备管理员权限。火绒只接受管理员进程拉起它。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


PERMISSION_HINT = (
    "火绒有驱动级自我保护，只有管理员进程才能拉起它。\n\n"
    "任选一种：\n"
    "1. 关闭 avscan → 右键 avscan.exe → 「以管理员身份运行」→ 回来点「触发」\n"
    "2. 永久生效：右键 avscan.exe → 属性 → 兼容性 → 勾选「以管理员身份运行此程序」\n\n"
    "不想改权限也行：资源管理器右键目标 → 火绒安全软件 → 使用火绒安全进行杀毒。"
)


def build_list_file(paths: list[str], name: str = LIST_NAME) -> Path:
    """按火绒的格式写待扫描清单。"""
    tmp = Path(tempfile.gettempdir()) / name
    normalized = [str(Path(p).expanduser().resolve()) for p in paths]
    tmp.write_text("|".join(normalized) + "|", encoding="utf-8")
    return tmp


def trigger_scan(
    paths: list[str],
    exe: str | Path | None = None,
) -> tuple[bool, str]:
    """发起火绒扫描。成功只代表「扫描窗口已拉起」，不代表扫描结论。"""
    if not paths:
        return False, "没有待扫描路径"

    target_exe = Path(exe) if exe else DEFAULT_EXE
    if not target_exe.is_file():
        return False, f"火绒主程序不存在：{target_exe}"

    try:
        list_file = build_list_file(paths)
    except OSError as exc:
        return False, f"写入待扫描清单失败：{exc}"

    try:
        proc = subprocess.Popen([str(target_exe), "-S", str(list_file)])
    except PermissionError:
        return False, (
            "火绒拒绝启动（WinError 5）：其自我保护不允许普通进程拉起主程序。\n"
            "请以管理员身份运行 avscan 后重试，或在资源管理器里右键手动扫描。"
        )
    except OSError as exc:
        return False, f"启动火绒失败：{exc}"

    return True, f"已发起火绒扫描（PID {proc.pid}），请在火绒窗口查看进度，扫完后回填结论。"
