"""avscan 桌面界面（PySide6，Notion 极简风格）。"""

from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    # 允许从项目根目录直接运行
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import QApplication

    from avscan.runtime import data_dir

    from . import theme
    from .main_window import MainWindow

    raw = list(argv if argv is not None else sys.argv)

    # --scan <path...>：右键菜单「一键扫描」传进来的目标
    scan_targets: list[str] = []
    if "--scan" in raw:
        idx = raw.index("--scan")
        for item in raw[idx + 1 :]:
            if item.startswith("--"):
                break
            scan_targets.append(item)

    # 只把程序名交给 Qt，避免它去解析我们自己的参数
    qt_argv = [raw[0]] if raw else ["avscan"]

    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontCreateNativeWidgetSiblings, True)
    app = QApplication(qt_argv)
    app.setApplicationName("avscan")
    app.setApplicationDisplayName("avscan — 多引擎批量扫毒")
    app.setStyle("Fusion")
    app.setStyleSheet(theme.stylesheet())
    app.setFont(QFont(theme.FONT, 10))

    # 标题栏与任务栏图标：不设的话显示的是 Qt 默认图标，跟 exe 图标对不上
    for name in ("avscan.ico", "logo_1024.png"):
        icon_path = data_dir("assets") / name
        if icon_path.is_file():
            app.setWindowIcon(QIcon(str(icon_path)))
            break

    # 右键菜单的安装/卸载：打包后没有命令行，必须给 exe 一个自己能撤销的出口
    if "--install-shell" in raw or "--remove-shell" in raw:
        from PySide6.QtWidgets import QMessageBox

        from avscan import shellmenu

        if "--install-shell" in raw:
            ok, msg = shellmenu.install()
        else:
            ok, msg = shellmenu.uninstall()
        QMessageBox.information(None, "右键菜单", msg)
        return 0 if ok else 1

    window = MainWindow()
    window.show()

    if scan_targets:
        window.scan_page.queue_scan(scan_targets)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
