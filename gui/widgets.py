"""通用组件：区块、分隔线、状态徽章、拖拽区。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme


class HLine(QFrame):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("HLine")
        self.setFixedHeight(1)


class Badge(QLabel):
    """状态小标签。kind: gray / green / red / yellow / blue"""

    _COLORS = {
        "gray": (theme.GRAY_SOFT, theme.TEXT_SECONDARY),
        "green": (theme.GREEN_SOFT, theme.GREEN),
        "red": (theme.RED_SOFT, theme.RED),
        "yellow": (theme.YELLOW_SOFT, theme.YELLOW),
        "blue": (theme.ACCENT_SOFT, theme.ACCENT),
    }

    def __init__(self, text: str, kind: str = "gray", parent: QWidget | None = None):
        super().__init__(text, parent)
        self.set_kind(kind)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

    def set_kind(self, kind: str) -> None:
        bg, fg = self._COLORS.get(kind, self._COLORS["gray"])
        self.setStyleSheet(
            f"background:{bg}; color:{fg}; border-radius:3px;"
            f"padding:1px 6px; font-size:11px; font-weight:500;"
        )

    def set_state(self, text: str, kind: str) -> None:
        self.setText(text)
        self.set_kind(kind)


class Section(QWidget):
    """一个内容区块：标题 + 可选副标题 + 右上角操作 + 内容体。"""

    def __init__(
        self,
        title: str,
        subtitle: str = "",
        action: QWidget | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(8)
        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        head.addWidget(title_label)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("SectionSub")
            head.addWidget(sub)
            head.addStretch(1)
        else:
            head.addStretch(1)

        self.head_actions = QHBoxLayout()
        self.head_actions.setSpacing(6)
        head.addLayout(self.head_actions)
        if action is not None:
            self.head_actions.addWidget(action)

        outer.addLayout(head)

        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        outer.addLayout(self.body)


class DropZone(QFrame):
    """虚线拖拽区：拖入文件或文件夹。"""

    dropped = Signal(list)
    clicked = Signal()

    def __init__(self, hint: str = "拖入安装包或安装目录", parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(96)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.icon = QLabel("＋")
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setStyleSheet(f"font-size:20px; color:{theme.TEXT_TERTIARY};")
        layout.addWidget(self.icon)

        self.hint = QLabel(hint)
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint.setStyleSheet(f"color:{theme.TEXT_SECONDARY}; font-size:12px;")
        layout.addWidget(self.hint)

        self.sub = QLabel("点击选择文件或文件夹")
        self.sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sub.setStyleSheet(f"color:{theme.TEXT_TERTIARY}; font-size:11px;")
        layout.addWidget(self.sub)

    # -- 拖拽 --
    def dragEnterEvent(self, event):  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("dragging", "true")
            self.style().unpolish(self)
            self.style().polish(self)

    def dragLeaveEvent(self, event):  # noqa: N802
        self.setProperty("dragging", "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event):  # noqa: N802
        self.setProperty("dragging", "false")
        self.style().unpolish(self)
        self.style().polish(self)
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)
        event.acceptProposedAction()

    def mousePressEvent(self, event):  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


def muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Muted")
    return label


def tiny(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Tiny")
    return label
