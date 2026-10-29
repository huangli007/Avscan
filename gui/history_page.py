"""历史页：列出本地运行记录，点开查看报告。"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from avscan.report import aggregate, verdict_of
from avscan.pipeline import DEFAULT_RUNS_DIR

from .widgets import HLine, Section, tiny

VERDICT_LABEL = {
    "pass": "通过",
    "fail": "检出",
    "incomplete": "未完成",
    "pending": "待补",
    "dryrun": "演练",
    "empty": "空",
}


class HistoryPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._rows: list[dict] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(40, 34, 40, 34)
        root.setSpacing(22)

        header = QWidget()
        hv = QVBoxLayout(header)
        hv.setContentsMargins(0, 0, 0, 0)
        hv.setSpacing(4)
        title = QLabel("历史")
        title.setObjectName("PageTitle")
        hv.addWidget(title)
        desc = QLabel("本机所有的扫描记录，每次运行都留有原始输出与报告")
        desc.setObjectName("PageDesc")
        hv.addWidget(desc)
        root.addWidget(header)
        root.addWidget(HLine())

        refresh = QPushButton("刷新")
        refresh.setObjectName("Ghost")
        refresh.clicked.connect(self.reload)
        section = Section("运行记录", action=refresh)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["时间", "任务标签", "结论", "引擎", "检出"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setMinimumHeight(300)
        self.table.itemSelectionChanged.connect(self._on_select)
        header_view = self.table.horizontalHeader()
        for i in (0, 2, 3, 4):
            header_view.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        section.body.addWidget(self.table)

        self.summary = tiny("")
        section.body.addWidget(self.summary)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.btn_report = QPushButton("打开报告")
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self._open_report)
        actions.addWidget(self.btn_report)

        self.btn_folder = QPushButton("打开目录")
        self.btn_folder.setEnabled(False)
        self.btn_folder.clicked.connect(self._open_folder)
        actions.addWidget(self.btn_folder)
        actions.addStretch(1)
        section.body.addLayout(actions)

        root.addWidget(section)
        root.addStretch(1)
        scroll.setWidget(content)

        self.reload()

    # ---- 数据 ----
    def reload(self) -> None:
        self._rows.clear()
        base = DEFAULT_RUNS_DIR
        if base.is_dir():
            for run_dir in sorted(base.iterdir(), reverse=True):
                if not run_dir.is_dir():
                    continue
                meta_path = run_dir / "meta.json"
                results_path = run_dir / "results.json"
                if not meta_path.is_file():
                    continue
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    results = (
                        json.loads(results_path.read_text(encoding="utf-8"))
                        if results_path.is_file()
                        else []
                    )
                except (OSError, json.JSONDecodeError):
                    continue

                verdict, _ = verdict_of(aggregate(results)) if results else ("empty", "")
                detections = sum(
                    len(r.get("detections") or []) for r in results
                )
                self._rows.append(
                    {
                        "dir": run_dir,
                        "time": meta.get("finished_at") or meta.get("created_at", ""),
                        "label": meta.get("label") or "—",
                        "verdict": verdict,
                        "engines": len({r.get("engine") for r in results}),
                        "detections": detections,
                    }
                )

        self.table.setRowCount(len(self._rows))
        for i, row in enumerate(self._rows):
            self.table.setItem(i, 0, QTableWidgetItem(row["time"]))
            self.table.setItem(i, 1, QTableWidgetItem(row["label"]))
            self.table.setItem(i, 2, QTableWidgetItem(VERDICT_LABEL.get(row["verdict"], row["verdict"])))
            self.table.setItem(i, 3, QTableWidgetItem(str(row["engines"])))
            self.table.setItem(i, 4, QTableWidgetItem(str(row["detections"])))

        # 高度自适应：记录少时不留大片空白
        row_h = self.table.verticalHeader().defaultSectionSize()
        self.table.setFixedHeight(min(row_h * max(len(self._rows), 1) + 42, 460))

        if self._rows:
            self.summary.setText(f"共 {len(self._rows)} 次运行 · 点选后可在下方打开报告")
        else:
            self.summary.setText("还没有扫描记录")

    def _current(self) -> dict | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def _on_select(self) -> None:
        row = self._current()
        ok = row is not None
        self.btn_report.setEnabled(ok)
        self.btn_folder.setEnabled(ok)

    def _open_report(self) -> None:
        row = self._current()
        if row is None:
            return
        report = row["dir"] / "report.md"
        if report.is_file():
            os.startfile(str(report))  # noqa: S606

    def _open_folder(self) -> None:
        row = self._current()
        if row is not None:
            subprocess.Popen(["explorer", str(row["dir"])])
