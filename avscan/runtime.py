"""运行时路径解析：区分「源码运行」与「PyInstaller 打包后」。

打包后 __file__ 位于临时解压目录（onefile）或 _internal（onedir），
而数据目录（tools/ packages/ runs/）必须以 exe 所在目录为根，
否则会出现「程序能启动但一个引擎都探测不到」这种莫名其妙的故障。
"""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    """数据根目录：源码运行时是项目根，打包后是 exe 所在目录。"""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def bundled_dir() -> Path | None:
    """PyInstaller 解压出的内置只读资源目录（未打包时为 None）。"""
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) if base else None


def data_dir(name: str) -> Path:
    """优先使用 exe 同级的可写目录，找不到再退回包内只读资源。"""
    external = app_dir() / name
    if external.is_dir():
        return external

    packed = bundled_dir()
    if packed is not None and (packed / name).is_dir():
        return packed / name

    return external
