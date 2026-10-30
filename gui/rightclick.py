"""模拟人工右键菜单扫描。

不做任何私有协议逆向，只做和人工完全一样的动作：

    打开资源管理器并选中目标 → 激活窗口 → Shift+F10 打开上下文菜单
    → 在菜单里找到该引擎的扫描项 → 触发它

触发用的是 UIA 的 InvokePattern，**不移动鼠标、不抢光标**，
只在几秒内借用一次前台焦点（资源管理器会被带到前台）。

已实测可用：Malwarebytes「用 Malwarebytes 扫描」、联想电脑管家「使用联想电脑管家进行扫描」。
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

try:
    import uiautomation as auto
except ImportError:  # pragma: no cover
    auto = None  # type: ignore[assignment]

from ctypes import windll

VK_SHIFT = 0x10
VK_F10 = 0x79
VK_ESC = 0x1B

DEPENDENCY_HINT = (
    "模拟右键需要 uiautomation 库（MIT 协议）：\n"
    "    pip install uiautomation\n"
    "打包版已内置，源码运行时才需要。"
)

# 各引擎在右键菜单里的匹配关键词（按顺序取第一个命中的）
MENU_KEYWORDS: dict[str, tuple[str, ...]] = {
    "huorong": ("火绒",),
    "malwarebytes": ("malwarebytes",),
    "qqpcmgr": ("腾讯电脑管家", "电脑管家"),
    "360": ("360",),
    "avira": ("avira",),
    "avast": ("avast",),
    "kaspersky": ("卡巴斯基", "kaspersky"),
}

user32 = windll.user32


def _key(vk: int, up: bool = False) -> None:
    user32.keybd_event(vk, 0, 2 if up else 0, 0)


def _combo(*vks: int) -> None:
    for vk in vks:
        _key(vk)
        time.sleep(0.05)
    for vk in reversed(vks):
        _key(vk, up=True)
        time.sleep(0.05)


def _safe_class(ctrl) -> str:
    try:
        return ctrl.ClassName or ""
    except Exception:  # noqa: BLE001
        return ""


def _safe_name(ctrl) -> str:
    try:
        return ctrl.Name or ""
    except Exception:  # noqa: BLE001
        return ""


def _top_windows() -> list:
    try:
        return list(auto.GetRootControl().GetChildren())
    except Exception:  # noqa: BLE001
        return []


def _find_context_menu(timeout: float = 2.5):
    """上下文菜单是老式 #32768 窗口。"""
    end = time.time() + timeout
    while time.time() < end:
        for w in _top_windows():
            if _safe_class(w) == "#32768":
                return w
        time.sleep(0.2)
    return None


def _menu_items(menu) -> list[tuple[str, object]]:
    rows: list[tuple[str, object]] = []
    try:
        walker = auto.WalkControl(menu, includeTop=False, maxDepth=3)
    except Exception:  # noqa: BLE001
        return rows
    for ctrl, _ in walker:
        name = _safe_name(ctrl).strip()
        if name:
            rows.append((name, ctrl))
    return rows


def _focus(hwnd: int) -> bool:
    """把资源管理器带到前台。失败时用 AttachThreadInput 提升权限再试。"""
    if user32.SetForegroundWindow(hwnd):
        return True
    try:
        fg = user32.GetForegroundWindow()
        cur = user32.GetWindowThreadProcessId(fg, None)
        tgt = user32.GetWindowThreadProcessId(hwnd, None)
        user32.AttachThreadInput(cur, tgt, True)
        user32.SetForegroundWindow(hwnd)
        user32.AttachThreadInput(cur, tgt, False)
        return bool(user32.GetForegroundWindow() == hwnd)
    except Exception:  # noqa: BLE001
        return False


def _select_in_explorer(targets: list[str]) -> object | None:
    """打开资源管理器并选中目标，返回该窗口控件。"""
    paths = ",".join(str(Path(t)) for t in targets)
    try:
        subprocess.Popen(["explorer", f"/select,{paths}"])
    except Exception:  # noqa: BLE001
        return None

    deadline = time.time() + 8
    while time.time() < deadline:
        time.sleep(0.4)
        candidates = [w for w in _top_windows() if _safe_class(w) == "CabinetWClass"]
        if candidates:
            # 选标题里含目标目录名的那个
            folder = Path(targets[0]).parent.name
            for w in candidates:
                if folder and folder in _safe_name(w):
                    return w
            return candidates[-1]
    return None


def list_scan_menu_items(target: str) -> list[str]:
    """列出目标文件右键菜单里所有扫描类项——用于诊断"这个引擎有没有右键入口"。"""
    if auto is None:
        return []
    win = _select_in_explorer([target])
    if win is None:
        return []
    _focus(win.NativeWindowHandle)
    time.sleep(0.6)
    _combo(VK_SHIFT, VK_F10)
    time.sleep(0.8)
    menu = _find_context_menu()
    if menu is None:
        return []
    try:
        items = [name for name, _ in _menu_items(menu)]
    finally:
        _combo(VK_ESC)
    return [n for n in items if "扫描" in n or "杀毒" in n]


def scan_by_rightclick(
    targets: list[str],
    engine_key: str,
    timeout: float = 25.0,
) -> tuple[bool, str]:
    """模拟人工右键扫描。

    返回 (是否成功发起, 说明)。成功只代表「引擎的扫描已被触发」，
    结论仍需人工看结果后回填。
    """
    if not targets:
        return False, "没有待扫描的目标"

    if auto is None:
        return False, DEPENDENCY_HINT

    keywords = MENU_KEYWORDS.get(engine_key, ())
    if not keywords:
        return False, f"未定义「{engine_key}」的右键菜单关键词"

    win = _select_in_explorer(targets)
    if win is None:
        return False, "无法打开资源管理器"

    if not _focus(win.NativeWindowHandle):
        return False, "无法把资源管理器切到前台（可能有窗口抢占焦点），请稍后重试"

    time.sleep(0.6)
    _combo(VK_SHIFT, VK_F10)
    time.sleep(0.9)

    menu = _find_context_menu()
    if menu is None:
        return False, "上下文菜单未弹出"

    try:
        items = _menu_items(menu)
        if not items:
            return False, "读不到右键菜单内容"

        matched: tuple[str, object] | None = None
        for kw in keywords:
            for name, ctrl in items:
                if kw.lower() in name.lower() and "avscan" not in name.lower():
                    matched = (name, ctrl)
                    break
            if matched:
                break

        if matched is None:
            available = [n for n, _ in items if "扫描" in n or "杀毒" in n]
            hint = "、".join(available) if available else "（菜单里没有任何扫描项）"
            return False, f"右键菜单里没有该引擎的扫描项。当前可用的有：{hint}"

        name, ctrl = matched
        try:
            pattern = ctrl.GetInvokePattern()
        except Exception:  # noqa: BLE001
            pattern = None

        if pattern:
            pattern.Invoke()
        else:
            # 退路：物理点击（会短暂移动鼠标）
            ctrl.Click(simulateMove=False)

        time.sleep(1.5)
        return True, f"已通过右键菜单触发「{name}」，请在引擎窗口查看进度，扫完后回填结论"
    finally:
        _combo(VK_ESC)
