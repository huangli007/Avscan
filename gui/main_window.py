"""主窗口：左侧极简导航 + 右侧内容区。"""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from avscan import __version__
from avscan.runtime import data_dir

from . import theme
from .history_page import HistoryPage
from .packages_page import PackagesPage
from .scan_page import ScanPage

NAV_ITEMS = [
    ("扫描", "◎"),
    ("安装包", "▤"),
    ("历史", "◷"),
]


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("avscan — 多引擎批量扫毒")

        # 小屏（如 1366×768）上固定 830 高会超出屏幕，按可用区域收敛
        width, height = 1180, 830
        screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            width = max(900, min(width, int(avail.width() * 0.92)))
            height = max(600, min(height, int(avail.height() * 0.92)))
        self.resize(width, height)
        self.setMinimumSize(900, 600)

        root = QWidget()
        root.setObjectName("Root")
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.scan_page = ScanPage()
        self.packages_page = PackagesPage()
        self.history_page = HistoryPage()
        for page in (self.scan_page, self.packages_page, self.history_page):
            self.stack.addWidget(page)
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(root)
        self.nav.setCurrentRow(0)

    def _build_sidebar(self) -> QWidget:
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(212)

        v = QVBoxLayout(side)
        v.setContentsMargins(0, 20, 0, 16)
        v.setSpacing(0)

        brand_box = QWidget()
        bh = QHBoxLayout(brand_box)
        bh.setContentsMargins(20, 0, 16, 0)
        bh.setSpacing(9)

        logo_path = data_dir("assets") / "logo_24.png"
        if logo_path.is_file():
            pic = QLabel()
            pic.setPixmap(QPixmap(str(logo_path)))
            pic.setFixedSize(24, 24)
            pic.setScaledContents(True)
            bh.addWidget(pic, 0, Qt.AlignmentFlag.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(1)
        brand = QLabel("avscan")
        brand.setObjectName("Brand")
        text_col.addWidget(brand)
        sub = QLabel("多引擎批量扫毒")
        sub.setObjectName("BrandSub")
        text_col.addWidget(sub)
        bh.addLayout(text_col)
        bh.addStretch(1)
        v.addWidget(brand_box)
        v.addSpacing(18)

        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        for name, icon in NAV_ITEMS:
            item = QListWidgetItem(f"  {icon}   {name}")
            # 固定行高，不能用 sizeHint().expandedTo(nav.sizeHint())，
            # 那会把每个 item 撑成整个列表的高度
            item.setSizeHint(QSize(0, 33))
            self.nav.addItem(item)
        self.nav.setFixedHeight(len(NAV_ITEMS) * 33 + 6)
        self.nav.currentRowChanged.connect(self._on_nav)
        v.addWidget(self.nav)

        v.addStretch(1)

        foot = QWidget()
        fv = QVBoxLayout(foot)
        fv.setContentsMargins(22, 0, 18, 0)
        fv.setSpacing(3)
        ver = QLabel(f"v{__version__}")
        ver.setObjectName("Tiny")
        fv.addWidget(ver)
        tip = QLabel("只检测，不删除")
        tip.setObjectName("Tiny")
        tip.setStyleSheet(f"color:{theme.TEXT_TERTIARY}; font-size:11px;")
        fv.addWidget(tip)
        v.addWidget(foot)

        return side

    def _on_nav(self, index: int) -> None:
        if index < 0:
            return
        self.stack.setCurrentIndex(index)
        if index == 1:
            self.packages_page.reload()
        elif index == 2:
            self.history_page.reload()
