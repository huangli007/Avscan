#!/usr/bin/env python3
"""多引擎批量扫毒工具 —— 入口。

用法：
    python scan.py detect
    python scan.py scan "D:\\pkg\\CTONE_Setup.exe" "D:\\pkg\\CTONE"
    python scan.py scan <target> --dry-run
    python scan.py report runs/RUN-20261029-153000
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from avscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
