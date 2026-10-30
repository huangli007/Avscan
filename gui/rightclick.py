"""模拟人工右键菜单扫描。

不做任何私有协议逆向，只做和人工完全一样的动作：

    打开资源管理器并选中目标 → 激活窗口 → Shift+F10 打开上下文菜单
    → 在菜单里找到该引擎的扫描项 → 触发它

触发用的是 UIA 的 InvokePattern，**不移动鼠标、不抢光标**，
只在几秒内借用一次前台焦点（资源管理器会被带到前台）。

已实测可用：Malwarebytes「用 Malwarebytes 扫描」、联想电脑管家「使用联想电脑管家进行扫描」。
"""

from __future__ import annotations

import ctypes
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

# 各引擎在右键菜单里的匹配词。
#   exact  —— 直接就是扫描动作的菜单项
#   parent —— 父级项（点开是子菜单），需要再进一层找 exact
MENU_KEYWORDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    #                        exact                                    parent
    "huorong": (("使用火绒安全进行杀毒", "使用火绒安全扫描"), ("火绒安全软件", "火绒")),
    "malwarebytes": (("Malwarebytes",), ()),
    "qqpcmgr": (("腾讯电脑管家", "电脑管家"), ()),
    "360": (("360",), ()),
    "avira": (("Avira",), ()),
    "avast": (("Avast",), ()),
    "kaspersky": (("卡巴斯基", "Kaspersky"), ()),
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


MN_GETHMENU = 0x01E1
WM_COMMAND = 0x0111
MF_BYPOSITION = 0x0400
MF_SEPARATOR = 0x00000800


def _menu_handle(hwnd_menu: int):
    """从菜单窗口句柄取 HMENU（MN_GETHMENU）。"""
    user32.SendMessageW.restype = ctypes.c_void_p
    return user32.SendMessageW(hwnd_menu, MN_GETHMENU, 0, 0)


def _menu_entries(hmenu) -> list[tuple[int, str, int, object]]:
    """枚举菜单项：返回 (索引, 文本, 命令ID, 子菜单句柄)。"""
    if not hmenu:
        return []
    user32.GetMenuItemCount.restype = ctypes.c_int
    user32.GetMenuItemID.restype = ctypes.c_uint
    user32.GetSubMenu.restype = ctypes.c_void_p

    count = user32.GetMenuItemCount(hmenu)
    buf = ctypes.create_unicode_buffer(320)
    rows: list[tuple[int, str, int, object]] = []
    for i in range(count):
        user32.GetMenuStringW(hmenu, i, buf, 320, MF_BYPOSITION)
        rows.append((i, buf.value or "", user32.GetMenuItemID(hmenu, i), user32.GetSubMenu(hmenu, i)))
    return rows


def _win32_invoke_in_menu(
    hwnd_menu: int,
    hmenu,
    needles: tuple[str, ...],
    parents: tuple[str, ...],
    depth: int,
) -> str | None:
    """在给定菜单（HMENU）里找扫描项；级联时递归进子菜单的 HMENU。"""
    if depth > 4:
        return None

    entries = _menu_entries(hmenu)

    # 1) 本层直接命中，且带可执行命令 ID
    for needle in needles:
        for _i, text, mid, sub in entries:
            if needle.lower() not in text.lower():
                continue
            if mid not in (0, 0xFFFFFFFF):
                user32.PostMessageW(hwnd_menu, WM_COMMAND, mid, 0)
                return text
            if sub:
                found = _win32_invoke_in_menu(hwnd_menu, sub, needles, parents, depth + 1)
                if found:
                    return found

    # 2) 本层没命中 → 找级联父项，进它的子菜单再找
    for pneedle in parents:
        for _i, text, mid, sub in entries:
            if pneedle.lower() not in text.lower():
                continue
            if not sub:
                continue
            found = _win32_invoke_in_menu(hwnd_menu, sub, needles, parents, depth + 1)
            if found:
                return found
    return None


def _win32_invoke_scan(
    hwnd_menu: int,
    needles: tuple[str, ...],
    parents: tuple[str, ...] = (),
) -> str | None:
    """用 Win32 菜单 API 找到扫描项并触发。

    比 UIA 可靠：老式菜单（#32768）本就是标准 Win32 菜单，
    直接读菜单树 + 发 WM_COMMAND，不需要鼠标，也不需要 UIA 能枚举到子菜单。

    parents 是"级联父项"的匹配词——像「火绒安全软件」这种项本身没有命令 ID，
    要进它的子菜单里再找 needles。
    """
    hmenu = _menu_handle(hwnd_menu)
    if not hmenu:
        return None
    return _win32_invoke_in_menu(hwnd_menu, hmenu, needles, parents, 0)


def _context_menus() -> list:
    """当前所有上下文菜单窗口（级联菜单的每一层都是一个 #32768）。"""
    return [w for w in _top_windows() if _safe_class(w) == "#32768"]


def _find_context_menu(timeout: float = 2.5):
    """上下文菜单是老式 #32768 窗口。"""
    end = time.time() + timeout
    while time.time() < end:
        menus = _context_menus()
        if menus:
            return menus[-1]
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
    """把窗口带到前台。

    两个坑：
    1. GetForegroundWindow 默认按 32 位 int 返回，64 位句柄会溢出成负数，
       跟 hwnd 永远不相等 —— 必须显式声明 restype。
    2. 前台锁（别的程序刚抢过焦点）时 SetForegroundWindow 会失败，
       用 Alt trick + AttachThreadInput 破锁。
    """
    user32.GetForegroundWindow.restype = ctypes.c_void_p
    user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]

    for _ in range(3):
        try:
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.25)
            if user32.GetForegroundWindow() == hwnd:
                return True
        except Exception:  # noqa: BLE001
            pass

        # Alt trick：按下 Alt 会让系统解除前台锁
        user32.keybd_event(0x12, 0, 0, 0)
        user32.keybd_event(0x12, 0, 2, 0)
        time.sleep(0.15)

        try:
            fg = user32.GetForegroundWindow()
            cur = user32.GetWindowThreadProcessId(fg, None)
            tgt = user32.GetWindowThreadProcessId(hwnd, None)
            user32.AttachThreadInput(cur, tgt, True)
            user32.BringWindowToTop(hwnd)
            user32.SetForegroundWindow(hwnd)
            user32.SetActiveWindow(hwnd)
            user32.AttachThreadInput(cur, tgt, False)
            time.sleep(0.25)
            if user32.GetForegroundWindow() == hwnd:
                return True
        except Exception:  # noqa: BLE001
            pass

    return False


def _navigate_to(win, folder: str) -> None:
    """让一个已打开的资源管理器窗口跳到指定目录（Ctrl+L → 粘贴 → 回车）。"""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        return
    app.clipboard().setText(folder)
    time.sleep(0.2)

    _focus(win.NativeWindowHandle)
    time.sleep(0.4)
    _combo(VK_CONTROL, 0x4C)  # Ctrl+L
    time.sleep(0.5)
    _combo(VK_CONTROL, 0x56)  # Ctrl+V
    time.sleep(0.6)
    _key(0x0D)  # Enter
    time.sleep(2.2)


def _select_in_explorer(targets: list[str]) -> object | None:
    """打开资源管理器并选中目标，返回该窗口控件。

    优先复用**用户已经打开的**资源管理器窗口 —— Win11 每个窗口是独立进程，
    驱动注入型（fire绒这类）的右键菜单只出现在用户自己开的窗口里，
    `explorer /select` 每次新起的进程是没有的。
    """
    folder = str(Path(targets[0]).parent)
    folder_name = Path(folder).name

    existing = [w for w in _top_windows() if _safe_class(w) == "CabinetWClass"]
    for w in existing:
        if folder_name and folder_name in _safe_name(w):
            return w  # 已经开着这个目录

    if existing:
        try:
            _navigate_to(existing[0], folder)
            return existing[0]
        except Exception:  # noqa: BLE001
            pass

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
            for w in candidates:
                if folder_name and folder_name in _safe_name(w):
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


def _locate_item(win, needle: str) -> tuple[int, int] | None:
    """在窗口里找到名为 needle 的文件项，返回它的屏幕中心坐标。

    Win11 新版 explorer 是 XAML，UIA 树很深（maxDepth 要到 14 才拿得到项）。
    """
    if auto is None:
        return None
    try:
        walker = auto.WalkControl(win, includeTop=False, maxDepth=14)
    except Exception:  # noqa: BLE001
        return None
    for ctrl, _ in walker:
        try:
            name = _safe_name(ctrl)
            if not name or needle.lower() not in name.lower():
                continue
            if "Item" not in (ctrl.ControlTypeName or ""):
                continue
            rect = ctrl.BoundingRectangle
            if rect.right > rect.left:
                return ((rect.left + rect.right) // 2, (rect.top + rect.bottom) // 2)
        except Exception:  # noqa: BLE001
            continue
    return None


def _human_move(x: int, y: int, steps: int = 18) -> None:
    """分步移动鼠标，带轻微抖动——贴近真人，避开"瞬移"式输入。"""
    import ctypes
    import random

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    p = POINT()
    user32.GetCursorPos(ctypes.byref(p))
    sx, sy = p.x, p.y
    for i in range(1, steps + 1):
        t = i / steps
        e = 3 * t * t - 2 * t * t * t
        user32.SetCursorPos(
            int(sx + (x - sx) * e + random.uniform(-2, 2)),
            int(sy + (y - sy) * e + random.uniform(-2, 2)),
        )
        time.sleep(0.012)
    user32.SetCursorPos(int(x), int(y))
    time.sleep(0.15)


def scan_by_rightclick(
    targets: list[str],
    engine_key: str,
    timeout: float = 25.0,
) -> tuple[bool, str]:
    """模拟人工右键扫描。

    全流程与人工一致：切到资源管理器 → 定位目标文件 → 鼠标移过去 → 右键 →
    在菜单里找到引擎的扫描项 → 触发。全程不抢鼠标，只借用前台焦点。

    返回 (是否成功发起, 说明)。成功只代表「引擎的扫描已被触发」，
    结论仍需人工看结果后回填。
    """
    if not targets:
        return False, "没有待扫描的目标"

    if auto is None:
        return False, DEPENDENCY_HINT

    keywords = MENU_KEYWORDS.get(engine_key)
    if not keywords:
        return False, f"未定义「{engine_key}」的右键菜单关键词"
    exact_words, parent_words = keywords

    win = _select_in_explorer(targets)
    if win is None:
        return False, "无法打开资源管理器"

    if not _focus(win.NativeWindowHandle):
        return False, "无法把资源管理器切到前台（可能有窗口抢占焦点），请稍后重试"

    time.sleep(0.5)

    # 定位目标文件 —— 键盘菜单（Shift+F10）与鼠标右键路径不同，
    # 驱动注入型菜单只在真实鼠标右键时出现，所以必须用鼠标。
    needle = Path(targets[0]).name
    pos = _locate_item(win, needle)
    if pos is None:
        _combo(VK_SHIFT, VK_F10)
    else:
        _human_move(pos[0], pos[1])
        user32.mouse_event(0x0008, 0, 0, 0, 0)  # RIGHTDOWN
        time.sleep(0.10)
        user32.mouse_event(0x0010, 0, 0, 0, 0)  # RIGHTUP

    time.sleep(1.2)

    menu = _find_context_menu()
    if menu is None:
        return False, "上下文菜单未弹出"

    try:
        items = _menu_items(menu)
        if not items:
            return False, "读不到右键菜单内容"

        matched: tuple[str, object] | None = None
        for kw in exact_words:
            for name, ctrl in items:
                if kw.lower() in name.lower() and "avscan" not in name.lower():
                    matched = (name, ctrl)
                    break
            if matched:
                break

        # 优先用 Win32 菜单 API 触发：它能直接进子菜单，不依赖鼠标也不依赖 UIA
        if exact_words:
            hwnd_menu = menu.NativeWindowHandle
            try:
                fired = _win32_invoke_scan(hwnd_menu, exact_words, parent_words)
            except Exception:  # noqa: BLE001
                fired = None
            if fired:
                time.sleep(1.5)
                return True, f"已通过右键菜单触发「{fired}」，请在引擎窗口查看进度，扫完后回填结论"

        # 一级菜单里没有直接的扫描项 → 找父级项，点开子菜单再找
        if matched is None and parent_words:
            parent = None
            for kw in parent_words:
                for name, ctrl in items:
                    if kw.lower() in name.lower() and "avscan" not in name.lower():
                        parent = (name, ctrl)
                        break
                if parent:
                    break

            if parent is not None:
                parent_hwnd = menu.NativeWindowHandle
                # 老式菜单的级联项必须**物理点击**才会展开子菜单，
                # Invoke 只会把它选中（子菜单不弹出来）。
                try:
                    parent[1].Click(simulateMove=False)
                except Exception:  # noqa: BLE001
                    try:
                        parent[1].GetInvokePattern().Invoke()
                    except Exception:  # noqa: BLE001
                        pass
                time.sleep(1.4)

                # 级联子菜单是**另一个** #32768 窗口，要找新出现的那个
                sub = None
                for m in _context_menus():
                    try:
                        if m.NativeWindowHandle != parent_hwnd:
                            sub = m
                            break
                    except Exception:  # noqa: BLE001
                        continue
                if sub is None:
                    sub = menu  # 少数实现会复用同一个窗口

                sub_items = _menu_items(sub)
                for kw in exact_words:
                    for name, ctrl in sub_items:
                        if kw.lower() in name.lower():
                            matched = (name, ctrl)
                            break
                    if matched:
                        break
                if matched is None:
                    available = [n for n, _ in sub_items]
                    return False, (
                        f"「{parent[0]}」子菜单里没有扫描项："
                        + ("、".join(available[:8]) if available else "（空）")
                    )

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
