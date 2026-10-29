"""桌面版打包入口（PyInstaller）。

源码运行时等价于 `python scan.py gui`；打包后 sys.frozen 为 True，
数据目录由 avscan.runtime 解析到 exe 所在目录。
"""

from __future__ import annotations

import sys
from pathlib import Path

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from gui import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
