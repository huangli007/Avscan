"""人工结果回填对话框：把「手改 JSON」变成点两下。

仅 GUI 的引擎（火绒 / 360 / 腾讯管家）没有命令行，扫描只能人来做，
但"扫完之后把结论录进去"这件事可以大幅简化。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from . import theme


class ManualResultDialog(QDialog):
    def __init__(self, engine_display: str, target_hint: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("回填扫描结果")
        self.setModal(True)
        self.setMinimumWidth(420)

        v = QVBoxLayout(self)
        v.setContentsMargins(22, 20, 22, 18)
        v.setSpacing(12)

        title = QLabel(engine_display)
        title.setStyleSheet(f"font-size:15px; font-weight:600; color:{theme.TEXT};")
        v.addWidget(title)

        hint = QLabel(
            "在杀毒软件里完成扫描后，把结论填到这里。\n"
            "保存后会重新计算总评并更新报告。"
        )
        hint.setStyleSheet(f"color:{theme.TEXT_SECONDARY}; font-size:12px;")
        hint.setWordWrap(True)
        v.addWidget(hint)

        if target_hint:
            path_label = QLabel(target_hint)
            path_label.setWordWrap(True)
            path_label.setStyleSheet(
                f"background:{theme.BG_CODE}; color:{theme.TEXT_SECONDARY};"
                f"border:1px solid {theme.BORDER}; border-radius:4px;"
                "padding:6px 8px; font-size:11px;"
            )
            v.addWidget(path_label)

        v.addSpacing(2)

        self.group = QButtonGroup(self)
        self.rb_clean = QRadioButton("未发现威胁")
        self.rb_infected = QRadioButton("发现威胁")
        self.rb_skip = QRadioButton("跳过（未扫描）")
        self.rb_clean.setChecked(True)
        for i, rb in enumerate((self.rb_clean, self.rb_infected, self.rb_skip)):
            self.group.addButton(rb, i)
            v.addWidget(rb)

        v.addSpacing(2)
        note_label = QLabel("备注（可选）")
        note_label.setStyleSheet(f"color:{theme.TEXT_SECONDARY}; font-size:12px;")
        v.addWidget(note_label)
        self.note = QLineEdit()
        self.note.setPlaceholderText("例如：检出 2 项，已人工确认")
        v.addWidget(self.note)

        v.addSpacing(6)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        ok = QPushButton("保存")
        ok.setObjectName("Primary")
        ok.clicked.connect(self.accept)
        buttons.addWidget(ok)
        v.addLayout(buttons)

    def payload(self) -> dict:
        if self.rb_infected.isChecked():
            status = "infected"
        elif self.rb_skip.isChecked():
            status = "error"  # 跳过按"未取得结论"处理，不会被当成无毒
        else:
            status = "clean"
        return {"status": status, "note": self.note.text().strip()}
