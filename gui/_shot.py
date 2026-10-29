"""离屏截图脚本：用于开发阶段自查界面效果，不进入事件循环。"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtGui import QFont  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from gui import theme  # noqa: E402
from gui.main_window import MainWindow  # noqa: E402

OUT = PROJECT / ".workbuddy" / "tmp" / "shots"


def shoot() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(theme.stylesheet())
    app.setFont(QFont(theme.FONT, 10))

    win = MainWindow()
    win.resize(1180, 830)
    win.show()

    pages = [("scan", 0), ("packages", 1), ("history", 2)]

    def capture(index: int = 0) -> None:
        if index >= len(pages):
            app.quit()
            return
        name, row = pages[index]
        win.nav.setCurrentRow(row)
        app.processEvents()
        # 给后台探测线程与表格布局留时间
        QTimer.singleShot(
            900,
            lambda: (
                win.grab().save(str(OUT / f"{name}.png")),
                print(f"saved {name}.png"),
                capture(index + 1),
            ),
        )

    QTimer.singleShot(1200, capture)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(shoot())
