"""扫描页：选目标 → 选引擎 → 扫描 → 看结果，一条线走完。"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from avscan.engines import STATUS_LABEL
from avscan.pipeline import VERDICT_TEXT, build_plan
from avscan.report import (
    aggregate,
    apply_manual_results,
    load_manual_results,
    mark_missing_evidence,
    publish_reports,
    verdict_of,
)
from avscan.runtime import data_dir
from avscan.targets import count_risk_files, human_bytes, walk_stats
from avscan.userconfig import set_override

from . import theme
from .evidence import render_output_png
from .manual_dialog import ManualResultDialog
from .widgets import Badge, DropZone, HLine, Section, muted, tiny
from .worker import ProbeWorker, ScanWorker

VERDICT_KIND = {
    "pass": ("green", "通过"),
    "fail": ("red", "不通过"),
    "incomplete": ("yellow", "未完成验证"),
    "pending": ("yellow", "待人工补扫"),
    "dryrun": ("blue", "演练"),
    "empty": ("gray", "无数据"),
}


class EngineRow(QWidget):
    """引擎行：勾选框 + 名称 + 版本 + 路径设置 + 状态徽章。"""

    changed = Signal()

    def __init__(self, status, parent: QWidget | None = None):
        super().__init__(parent)
        self.status = status

        row = QHBoxLayout(self)
        row.setContentsMargins(2, 4, 2, 4)
        row.setSpacing(8)

        self.check = QCheckBox()
        self.check.setChecked(status.runnable)
        self.check.setEnabled(status.runnable)
        row.addWidget(self.check)
        name = QLabel(status.engine.display)
        name.setStyleSheet(f"color:{theme.TEXT}; font-size:13px;")
        row.addWidget(name)

        if status.version:
            row.addWidget(tiny(status.version))

        if status.path_source == "manual":
            row.addWidget(Badge("手动指定", "blue"))

        row.addStretch(1)

        # 路径入口：探测不到或启动失败时，用户能自己指到正确的 exe
        self.btn_path = QPushButton("路径")
        self.btn_path.setObjectName("Ghost")
        self.btn_path.setFixedHeight(20)
        self.btn_path.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_path.setToolTip("指定该引擎的可执行文件，用于解决探测不到或启动失败")
        self.btn_path.clicked.connect(self._edit_path)
        row.addWidget(self.btn_path)

        if not status.installed:
            kind, text = "gray", "未安装"
        elif status.engine.tier == "manual":
            kind, text = "yellow", "仅 GUI"
        elif status.ready:
            kind, text = "green", "可自动"
        else:
            kind, text = "gray", "不可用"
        row.addWidget(Badge(text, kind))

        if not status.installed:
            self.check.setEnabled(False)
            self.check.setChecked(False)
            name.setStyleSheet(f"color:{theme.TEXT_TERTIARY}; font-size:13px;")

    @property
    def checked(self) -> bool:
        return self.check.isChecked()

    def set_checked(self, value: bool) -> None:
        if self.check.isEnabled():
            self.check.setChecked(value)

    def _edit_path(self) -> None:
        engine = self.status.engine

        if self.status.path_source == "manual":
            menu = QMenu(self)
            act_pick = menu.addAction("重新指定路径…")
            act_reset = menu.addAction("恢复自动探测")
            chosen = menu.exec(self.btn_path.mapToGlobal(self.btn_path.rect().bottomLeft()))
            if chosen == act_reset:
                set_override(engine.key, None)
                self.changed.emit()
                return
            if chosen != act_pick:
                return

        start_dir = str(self.status.exe.parent) if self.status.exe else ""
        path, _ = QFileDialog.getOpenFileName(
            self,
            f"指定「{engine.display}」的可执行文件",
            start_dir,
            "可执行文件 (*.exe *.com *.bat *.cmd);;所有文件 (*)",
        )
        if path:
            set_override(engine.key, path)
            self.changed.emit()


class ScanPage(QWidget):
    request_scan = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._targets: list[str] = []
        self._stats: dict[str, tuple[int, int]] = {}
        self._rows: list[EngineRow] = []
        self._keep: set[str] = set()
        self._auto_scan = False
        self._worker: ScanWorker | None = None
        self._probe: ProbeWorker | None = None
        self._outcome = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(self._scroll)

        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(40, 34, 40, 34)
        root.setSpacing(24)

        root.addWidget(self._build_header())
        root.addWidget(HLine())
        root.addWidget(self._build_target_section())
        root.addWidget(HLine())
        root.addWidget(self._build_engine_section())
        root.addWidget(HLine())
        root.addWidget(self._build_action_section())
        root.addWidget(self._build_progress_section())
        root.addWidget(self._build_result_section())
        root.addStretch(1)

        self._scroll.setWidget(content)
        self._start_probe()
    # ---- 构建 ----
    def _build_header(self) -> QWidget:
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)
        title = QLabel("扫描")
        title.setObjectName("PageTitle")
        v.addWidget(title)
        desc = QLabel("选一个安装包或整个安装目录，用多个引擎交叉验证，产出可归档的扫毒报告")
        desc.setObjectName("PageDesc")
        v.addWidget(desc)
        return box

    def _build_target_section(self) -> QWidget:
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("Ghost")
        clear_btn.clicked.connect(self._clear_targets)

        section = Section("目标", action=clear_btn)

        self.drop = DropZone()
        self.drop.dropped.connect(self.add_targets)
        self.drop.clicked.connect(self._on_drop_clicked)
        section.body.addWidget(self.drop)

        self.target_list = QListWidget()
        self.target_list.setVisible(False)
        self.target_list.setMaximumHeight(132)
        self.target_list.setStyleSheet(
            f"QListWidget::item {{ padding:7px 8px; border-bottom:1px solid {theme.BORDER}; }}"
        )
        self.target_list.itemDoubleClicked.connect(self._remove_item)
        section.body.addWidget(self.target_list)

        self.target_summary = tiny("尚未选择目标")
        section.body.addWidget(self.target_summary)
        return section

    def _build_engine_section(self) -> QWidget:
        all_btn = QPushButton("全选可用")
        all_btn.setObjectName("Ghost")
        all_btn.clicked.connect(lambda: self._set_all(True))
        none_btn = QPushButton("全不选")
        none_btn.setObjectName("Ghost")
        none_btn.clicked.connect(lambda: self._set_all(False))

        section = Section("引擎", "默认勾选可自动执行的引擎", action=all_btn)
        section.head_actions.addWidget(none_btn)

        self.engine_list = QListWidget()
        self.engine_list.setStyleSheet(
            "QListWidget::item { border-bottom: none; padding: 0; }"
            "QListWidget { padding-right: 4px; }"
        )
        self.engine_list.setMinimumHeight(120)
        self.engine_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        section.body.addWidget(self.engine_list)

        self.engine_hint = tiny("正在探测本机引擎 ...")
        self.engine_hint.setWordWrap(True)
        section.body.addWidget(self.engine_hint)
        return section

    def _build_action_section(self) -> QWidget:
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(18)

        self.dry_run = QCheckBox("仅演练（只打印命令，不实际扫描）")
        row.addWidget(self.dry_run)

        self.only_risk = QCheckBox("仅扫高危文件（exe / dll / 脚本 / 压缩包）")
        self.only_risk.setToolTip(
            "默认全量扫描：整个目录交给引擎递归，速度快。\n"
            "勾选后改为逐个文件送检，能精确定位到具体文件，但会显著变慢。"
        )
        self.only_risk.toggled.connect(self._on_only_risk_toggled)
        row.addWidget(self.only_risk)

        row.addStretch(1)

        self.btn_scan = QPushButton("开始扫描")
        self.btn_scan.setObjectName("Primary")
        self.btn_scan.setMinimumWidth(110)
        self.btn_scan.clicked.connect(self._on_scan)
        row.addWidget(self.btn_scan)
        v.addLayout(row)

        self.scope_hint = tiny("")
        self.scope_hint.setWordWrap(True)
        v.addWidget(self.scope_hint)
        return box

    def _build_progress_section(self) -> QWidget:
        self.progress_box = QWidget()
        v = QVBoxLayout(self.progress_box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        head = QHBoxLayout()
        self.progress_label = QLabel("准备中")
        self.progress_label.setObjectName("SectionTitle")
        head.addWidget(self.progress_label)
        head.addStretch(1)
        self.btn_cancel = QPushButton("取消")
        self.btn_cancel.setObjectName("Ghost")
        self.btn_cancel.clicked.connect(self._on_cancel)
        head.addWidget(self.btn_cancel)
        v.addLayout(head)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 0)
        v.addWidget(self.progress_bar)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(96)
        self.log.setStyleSheet(
            f"background:{theme.BG_CODE}; border:1px solid {theme.BORDER};"
            f"border-radius:4px; font-family:{theme.MONO}; font-size:11px; padding:6px;"
        )
        v.addWidget(self.log)

        self.progress_box.setVisible(False)
        return self.progress_box

    def _build_result_section(self) -> QWidget:
        self.result_box = QWidget()
        v = QVBoxLayout(self.result_box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)

        head = QHBoxLayout()
        head.setSpacing(10)
        self.verdict_badge = Badge("—", "gray")
        self.verdict_badge.setStyleSheet(
            f"background:{theme.GRAY_SOFT}; color:{theme.TEXT_SECONDARY};"
            "border-radius:4px; padding:4px 10px; font-size:13px; font-weight:600;"
        )
        head.addWidget(self.verdict_badge)

        self.verdict_text = QLabel("")
        self.verdict_text.setObjectName("Muted")
        head.addWidget(self.verdict_text)
        head.addStretch(1)

        self.btn_report = QPushButton("打开报告")
        self.btn_report.clicked.connect(self._open_report)
        head.addWidget(self.btn_report)

        self.btn_folder = QPushButton("打开目录")
        self.btn_folder.clicked.connect(self._open_folder)
        head.addWidget(self.btn_folder)
        v.addLayout(head)

        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(["引擎", "状态", "检出", "耗时", "说明", ""])
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.setShowGrid(False)
        self.result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.result_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.result_table.setMinimumHeight(150)
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        # 说明列文字很长，Stretch 模式下它不收缩，会把操作列整个挤出可视区，
        # 所以改成固定宽度，给操作列留出位置
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.result_table.setColumnWidth(4, 430)
        # 操作列放的是 widget，ResizeToContents 不会计算 widget 宽度，必须显式给宽
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.result_table.setColumnWidth(5, 172)
        v.addWidget(self.result_table)

        self.result_box.setVisible(False)
        return self.result_box

    # ---- 目标 ----
    def add_targets(self, paths: list[str]) -> None:
        added: list[str] = []
        for raw in paths:
            path = str(Path(raw).resolve())
            if path in self._targets or not os.path.exists(path):
                continue
            self._targets.append(path)
            added.append(path)

        if not added:
            return

        # 目录要先统计文件数与体积，大目录可能耗时，给等待光标
        dirs = [p for p in added if Path(p).is_dir()]
        if dirs:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            try:
                for p in dirs:
                    count, size, _ = walk_stats(Path(p))
                    self._stats[p] = (count, size)
            finally:
                QApplication.restoreOverrideCursor()

        self._refresh_targets()

    def _on_drop_clicked(self) -> None:
        """点一下拖拽区就给出明确的两条路，不用先取消文件对话框再选目录。"""
        menu = QMenu(self)
        act_files = menu.addAction("选择文件…")
        act_dir = menu.addAction("选择文件夹…")
        chosen = menu.exec(self.drop.mapToGlobal(self.drop.rect().bottomLeft()))
        if chosen == act_files:
            self._pick_files()
        elif chosen == act_dir:
            self._pick_folder()

    def _pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self, "选择安装包", "", "可执行文件 (*.exe *.msi *.msix);;所有文件 (*)"
        )
        if files:
            self.add_targets(files)

    def _pick_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "选择要扫描的文件夹")
        if folder:
            self.add_targets([folder])

    def _remove_item(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.ItemDataRole.UserRole)
        if path in self._targets:
            self._targets.remove(path)
            self._stats.pop(path, None)
            self._refresh_targets()

    def _clear_targets(self) -> None:
        self._targets.clear()
        self._stats.clear()
        self._refresh_targets()

    # ---- 右键菜单入口 ----
    def queue_scan(self, paths: list[str]) -> None:
        """资源管理器右键「一键扫描」：加入目标后自动开扫，不用再点按钮。"""
        self.add_targets(paths)
        self._auto_scan = True
        if self._rows:
            QTimer.singleShot(400, self._try_auto_scan)

    def _try_auto_scan(self) -> None:
        if not getattr(self, "_auto_scan", False):
            return
        self._auto_scan = False
        if self._targets and any(row.checked for row in self._rows):
            self._on_scan()

    def _refresh_targets(self) -> None:
        self.target_list.clear()
        for path in self._targets:
            p = Path(path)
            if p.is_dir():
                count, size = self._stats.get(path, (0, 0))
                detail = f"{count} 个文件 · {human_bytes(size)}" if count else "目录"
                text = f"{path}    {detail}"
            else:
                try:
                    text = f"{path}    {human_bytes(p.stat().st_size)}"
                except OSError:
                    text = path
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip("双击移除")
            self.target_list.addItem(item)

        has = bool(self._targets)
        self.target_list.setVisible(has)
        self.drop.setVisible(not has)

        if has:
            # 高度贴合行数，避免固定高度在条目少时留出大片空白
            total = sum(self.target_list.sizeHintForRow(i) for i in range(self.target_list.count()))
            self.target_list.setFixedHeight(min(total + 4, 132))

        self._update_summary()
        if hasattr(self, "only_risk") and self.only_risk.isChecked():
            self._on_only_risk_toggled(True)

    def _update_summary(self) -> None:
        """只刷新汇总文案，不重新遍历目录。"""
        if not self._targets:
            self.target_summary.setText("尚未选择目标")
            if hasattr(self, "scope_hint"):
                self.scope_hint.setText("")
            return

        total_files = sum(self._stats.get(p, (0, 0))[0] for p in self._targets if Path(p).is_dir())
        total_files += sum(1 for p in self._targets if Path(p).is_file())
        total_bytes = sum(self._stats.get(p, (0, 0))[1] for p in self._targets if Path(p).is_dir())
        for p in self._targets:
            fp = Path(p)
            if fp.is_file():
                try:
                    total_bytes += fp.stat().st_size
                except OSError:
                    pass

        only_risk = hasattr(self, "only_risk") and self.only_risk.isChecked()
        mode_hint = "逐个文件送检" if only_risk else "目录由引擎递归扫描"
        self.target_summary.setText(
            f"已选 {len(self._targets)} 项 · 共 {total_files} 个文件 · {human_bytes(total_bytes)}"
            f"　（双击列表项可移除；{mode_hint}）"
        )

    # ---- 引擎 ----
    def _start_probe(self) -> None:
        # 记住当前勾选，重探测后恢复，避免用户改了路径就丢掉选择
        self._keep = {row.status.key for row in self._rows if row.checked}
        self.engine_hint.setText("正在探测本机引擎 ...")
        self._probe = ProbeWorker()
        self._probe.done.connect(self._on_probed)
        self._probe.failed.connect(lambda msg: self.engine_hint.setText(f"探测失败：{msg}"))
        self._probe.start()

    def _on_probed(self, statuses) -> None:
        self.engine_list.clear()
        self._rows.clear()
        for status in statuses:
            item = QListWidgetItem()
            row = EngineRow(status)
            if status.key in self._keep and status.runnable:
                row.set_checked(True)
            row.changed.connect(self._start_probe)
            item.setSizeHint(row.sizeHint())
            self.engine_list.addItem(item)
            self.engine_list.setItemWidget(item, row)
            self._rows.append(row)

        ready = sum(1 for s in statuses if s.runnable)
        manual = sum(1 for s in statuses if s.installed and s.engine.tier == "manual")
        missing = sum(1 for s in statuses if not s.installed)
        hint = f"可自动 {ready} 个 ｜ 仅人工 {manual} 个 ｜ 未安装 {missing} 个"

        # 打包分发时 tools/ 若不在 exe 旁边，便携扫描器会全部落空，
        # 用户只会看到一堆「未安装」而不知道为什么
        tools_dir = data_dir("tools")
        if not tools_dir.is_dir():
            hint += "\n未找到 tools/ 目录，便携扫描器不可用"
            self.engine_hint.setToolTip(f"把项目的 tools/ 复制到：{tools_dir}")
        else:
            self.engine_hint.setToolTip("")

        self.engine_hint.setText(hint)

        # 高度贴合实际行高，避免出现滚动条压住徽章，也避免底部留白
        total = sum(self.engine_list.sizeHintForRow(i) for i in range(self.engine_list.count()))
        self.engine_list.setFixedHeight(min(total + 4, 340))

        if self._auto_scan:
            QTimer.singleShot(400, self._try_auto_scan)

    def _set_all(self, value: bool) -> None:
        for row in self._rows:
            row.set_checked(value)

    # ---- 扫描范围 ----
    def _on_only_risk_toggled(self, checked: bool) -> None:
        """勾选高危过滤时，把「逐文件送检」的真实代价算给用户看。"""
        self._update_summary()
        if not checked:
            self.scope_hint.setText("")
            return

        if not self._targets:
            self.scope_hint.setText("尚未选择目标")
            return

        files_only = sum(1 for p in self._targets if Path(p).is_file())
        dirs = [p for p in self._targets if Path(p).is_dir()]
        if not dirs:
            self.scope_hint.setText("当前目标是单个文件，不受此选项影响")
            return

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            total = files_only + sum(count_risk_files(Path(d)) for d in dirs)
        finally:
            QApplication.restoreOverrideCursor()

        if total == 0:
            self.scope_hint.setText("所选目录内没有符合条件的高危文件，建议取消勾选改用全量扫描")
        elif total > 300:
            self.scope_hint.setText(
                f"⚠ 将有 {total} 个文件逐个送检，每个文件都要单独启动一次引擎，耗时可能很长；"
                "建议取消勾选改用全量扫描"
            )
        else:
            self.scope_hint.setText(f"将有 {total} 个文件逐个送检（每个文件单独启动一次引擎）")

    # ---- 扫描 ----
    def _selected_engines(self) -> list[str]:
        keys = [row.status.key for row in self._rows if row.checked and row.status.installed]
        return keys

    def _on_scan(self) -> None:
        if not self._targets:
            QMessageBox.information(self, "缺少目标", "请先拖入或选择要扫描的安装包 / 目录。")
            return
        keys = self._selected_engines()
        if not keys:
            QMessageBox.information(self, "未选择引擎", "至少勾选一个引擎。")
            return

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            plan = build_plan(
                self._targets,
                ",".join(keys),
                only_risk=self.only_risk.isChecked(),
            )
        except (ValueError, FileNotFoundError) as exc:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "无法开始", str(exc))
            return
        finally:
            QApplication.restoreOverrideCursor()

        if not plan.has_engine:
            QMessageBox.warning(self, "无可用引擎", "所选引擎均不可执行，请检查安装状态。")
            return

        self._set_running(True)
        self.result_box.setVisible(False)
        self.log.clear()

        self._worker = ScanWorker(plan, "", 1800, self.dry_run.isChecked())
        self._worker.progress.connect(self._on_progress)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _set_running(self, running: bool) -> None:
        self.progress_box.setVisible(running)
        self.btn_scan.setEnabled(not running)
        self.btn_scan.setText("扫描中 ..." if running else "开始扫描")
        self.drop.setEnabled(not running)
        self.engine_list.setEnabled(not running)
        if running:
            self.progress_label.setText("正在扫描")
            self.progress_bar.setRange(0, 0)

    def _on_progress(self, stage: str, message: str) -> None:
        if message:
            self.log.append(message)
            bar = self.log.verticalScrollBar()
            bar.setValue(bar.maximum())
        if stage == "engine_start":
            self.progress_label.setText(message)

    def _on_cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.progress_label.setText("正在取消 ...")

    def _on_failed(self, message: str) -> None:
        self._set_running(False)
        QMessageBox.critical(self, "扫描失败", message)

    def _on_done(self, outcome) -> None:
        self._outcome = outcome
        self._set_running(False)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self._fill_results(outcome)
        self.result_box.setVisible(True)
        # 结果在页面下方，扫完自动滚过去，避免用户以为没反应
        QTimer.singleShot(80, self._scroll_to_result)
        # 证据截图：引擎原始输出渲染成图 + 结果总览，报告里直接引用
        QTimer.singleShot(300, self._capture_evidence)

    def _capture_evidence(self) -> None:
        """为每个引擎生成证据截图，并让报告引用它们。

        「无毒」结论必须有截图，缺证据的引擎会被降级为未取得结论。
        """
        if self._outcome is None:
            return

        run_dir = self._outcome.run_dir
        shots = run_dir / "screenshots"
        try:
            shots.mkdir(parents=True, exist_ok=True)
        except OSError:
            return

        grouped: dict[str, dict] = {}
        for r in self._outcome.results:
            grouped.setdefault(r["engine"], r)

        for key, r in grouped.items():
            target = shots / f"{key}.png"
            if target.is_file():
                continue  # 用户已手动放入界面截图，不覆盖

            body = ""
            # 原始 results 没有 logs 键（那是聚合后的），要用 stdout_path
            paths = list(r.get("logs") or [])
            if not paths and r.get("stdout_path"):
                paths = [r["stdout_path"]]
            for path in paths:
                p = Path(path)
                if p.is_file():
                    body += p.read_text(encoding="utf-8", errors="replace") + "\n"
            if not body.strip():
                body = str(r.get("message", ""))

            code = r.get("exit_code")
            render_output_png(
                str(r.get("display", key)),
                body,
                target,
                subtitle=f"退出码 {code}" if code is not None else "",
            )

        # 结果总览
        try:
            self.result_box.grab().save(str(shots / "overview.png"), "PNG")
        except Exception:  # noqa: BLE001
            pass

        # 报告重生成：引用截图 + 执行证据完整性检查
        try:
            publish_reports(run_dir, self._outcome.meta, self._outcome.results)
        except Exception:  # noqa: BLE001
            pass
        self._refresh_after_manual()

    def _scroll_to_result(self) -> None:
        if hasattr(self, "_scroll") and self.result_box.isVisible():
            self._scroll.ensureWidgetVisible(self.result_box, 0, 40)

    def _fill_results(self, outcome) -> None:
        kind, label = VERDICT_KIND.get(outcome.verdict, ("gray", outcome.verdict))
        bg, fg = Badge._COLORS.get(kind, Badge._COLORS["gray"])
        self.verdict_badge.setText(label)
        self.verdict_badge.setStyleSheet(
            f"background:{bg}; color:{fg}; border-radius:4px;"
            "padding:4px 10px; font-size:13px; font-weight:600;"
        )
        self.verdict_text.setText(VERDICT_TEXT.get(outcome.verdict, ""))

        grouped: dict[str, dict] = {}
        for r in outcome.results:
            key = r["engine"]
            if key not in grouped:
                grouped[key] = r
            elif r.get("detections"):
                grouped[key] = r

        self.result_table.setRowCount(len(grouped))
        for i, r in enumerate(grouped.values()):
            status = STATUS_LABEL.get(r.get("status", ""), r.get("status", ""))
            message = r.get("message", "")
            # 把常见的启动失败翻译成可操作的建议，而不是把原始错误码丢给用户
            if "740" in message:
                message += "　→ 需以管理员身份运行"
            elif "FileNotFound" in message or "系统找不到" in message:
                message += "　→ 可点「路径」重新指定 exe"

            name_item = QTableWidgetItem(r.get("display", r["engine"]))
            name_item.setData(Qt.ItemDataRole.UserRole, r["engine"])
            self.result_table.setItem(i, 0, name_item)
            self.result_table.setItem(i, 1, QTableWidgetItem(status))
            self.result_table.setItem(i, 2, QTableWidgetItem(str(len(r.get("detections") or []))))
            self.result_table.setItem(i, 3, QTableWidgetItem(f"{float(r.get('duration_sec') or 0):.1f}s"))
            self.result_table.setItem(i, 4, QTableWidgetItem(message))

            # 仅 GUI 的引擎：首选「模拟人工右键扫描」——走引擎自己的完整扫描引擎，
            # 不需要私有协议、不需要管理员（除非引擎自己要求）。
            if r.get("status") == "manual":
                box = QWidget()
                bh = QHBoxLayout(box)
                bh.setContentsMargins(0, 0, 0, 0)
                bh.setSpacing(4)

                btn_rc = QPushButton("模拟右键")
                btn_rc.setObjectName("Ghost")
                btn_rc.setFixedHeight(20)
                btn_rc.setCursor(Qt.CursorShape.PointingHandCursor)
                btn_rc.setToolTip("模拟人工在资源管理器里右键扫描（首选）")
                btn_rc.clicked.connect(lambda _=False, k=r["engine"]: self._simulate_rightclick(k))
                bh.addWidget(btn_rc)

                if r["engine"] == "huorong":
                    btn_trig = QPushButton("触发")
                    btn_trig.setObjectName("Ghost")
                    btn_trig.setFixedHeight(20)
                    btn_trig.setCursor(Qt.CursorShape.PointingHandCursor)
                    btn_trig.setToolTip("备选：按火绒私有协议发起扫描（需管理员）")
                    btn_trig.clicked.connect(lambda _=False: self._trigger_manual())
                    bh.addWidget(btn_trig)

                btn_fill = QPushButton("回填")
                btn_fill.setObjectName("Ghost")
                btn_fill.setFixedHeight(20)
                btn_fill.setCursor(Qt.CursorShape.PointingHandCursor)
                btn_fill.setToolTip("在杀软里扫完后，把结论填进来")
                btn_fill.clicked.connect(lambda _=False, k=r["engine"]: self._fill_manual(k))
                bh.addWidget(btn_fill)

                bh.addStretch(1)
                self.result_table.setCellWidget(i, 5, box)

    # ---- 人工回填 ----
    def _simulate_rightclick(self, engine_key: str) -> None:
        """模拟人工在资源管理器里右键扫描——首选方式。

        不碰鼠标，只短暂把资源管理器切到前台。
        """
        if self._outcome is None:
            return
        targets = [
            str(t.get("path", ""))
            for t in self._outcome.meta.get("targets", [])
            if t.get("path")
        ]
        if not targets:
            QMessageBox.information(self, "无目标", "当前运行没有可扫描的目标路径。")
            return

        from .rightclick import scan_by_rightclick

        QMessageBox.information(
            self,
            "即将模拟右键",
            "程序会打开资源管理器并选中目标，然后自动触发引擎的右键扫描项。\n\n"
            "这期间请不要操作鼠标键盘，几秒后会自动切回。",
        )

        ok, msg = scan_by_rightclick(targets, engine_key)
        if ok:
            QMessageBox.information(self, "已触发扫描", msg)
            return

        # 回退：火绒的右键菜单不响应程序化点击（实测菜单里根本没有它那一项），
        # 改走它的私有协议 HipsMain -S（需管理员权限）。
        if engine_key == "huorong":
            from avscan.huorong import PERMISSION_HINT, is_admin, trigger_scan

            if not is_admin():
                QMessageBox.warning(
                    self,
                    "模拟右键对火绒无效",
                    msg + "\n\n" + PERMISSION_HINT,
                )
                return

            ok2, msg2 = trigger_scan(targets)
            if ok2:
                QMessageBox.information(
                    self,
                    "已通过火绒协议触发",
                    msg2 + "\n\n（右键菜单方式对火绒无效，已自动改用它的私有协议）",
                )
                return
            QMessageBox.warning(self, "无法自动触发", msg + "\n\n" + msg2)
            return

        QMessageBox.warning(
            self,
            "无法自动触发",
            msg + "\n\n可在资源管理器里右键目标 → 引擎的扫描项，扫完回来点「回填」。",
        )

    def _locate_target(self) -> None:
        """打开目标位置，让用户用引擎自己的右键扫描——比程序硬拉进程可靠。"""
        if self._outcome is None:
            return
        targets = [
            str(t.get("path", ""))
            for t in self._outcome.meta.get("targets", [])
            if t.get("path")
        ]
        if not targets:
            QMessageBox.information(self, "无目标", "当前运行没有可定位的目标路径。")
            return

        target = Path(targets[0])
        try:
            if target.is_dir():
                os.startfile(str(target))  # noqa: S606
            else:
                # 尽量在资源管理器里选中该文件，失败就退回打开父目录
                shell32 = ctypes.windll.shell32
                code = shell32.ShellExecuteW(
                    None, "open", "explorer.exe", f'/select,"{target}"', None, 1
                )
                if int(code) <= 32:
                    os.startfile(str(target.parent))  # noqa: S606
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "无法打开位置", str(exc))
            return

        QMessageBox.information(
            self,
            "用引擎自己的右键扫描",
            "已打开目标位置。\n\n"
            "在文件（或文件夹）上右键，选择引擎的扫描项：\n"
            "  · 火绒安全软件 → 使用火绒安全进行杀毒\n"
            "  · 使用 Microsoft Defender 扫描...\n\n"
            "这样走的是引擎自己的扫描引擎，不受权限与自我保护限制。\n"
            "扫完回到这里点「回填」记录结论。",
        )

    def _trigger_manual(self) -> None:
        """按火绒右键菜单的协议发起扫描。受其自我保护限制，需要管理员权限。"""
        if self._outcome is None:
            return
        targets = [
            str(t.get("path", ""))
            for t in self._outcome.meta.get("targets", [])
            if t.get("path")
        ]
        if not targets:
            QMessageBox.information(self, "无目标", "当前运行没有可扫描的目标路径。")
            return

        from avscan.huorong import PERMISSION_HINT, is_admin, trigger_scan

        # 先讲清楚权限，别让人点了才发现被拒
        if not is_admin():
            QMessageBox.information(self, "需要管理员权限", PERMISSION_HINT)
            return

        ok, msg = trigger_scan(targets)
        if ok:
            QMessageBox.information(
                self,
                "已发起扫描",
                msg + "\n\n扫完后回到这里点「回填」记录结论。",
            )
        else:
            QMessageBox.warning(self, "无法自动触发", msg)

    def _fill_manual(self, engine_key: str) -> None:
        if self._outcome is None:
            return

        run_dir = self._outcome.run_dir
        targets = self._outcome.meta.get("targets", [])
        hint = "、".join(str(t.get("path", "")) for t in targets[:2])

        dlg = ManualResultDialog(engine_key, hint, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        payload = dlg.payload()
        path = run_dir / "manual_results.json"
        data: dict = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
        data[engine_key] = payload
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        # 重算报告，让 md/csv/json 与界面口径一致
        publish_reports(run_dir, self._outcome.meta, self._outcome.results)
        self._refresh_after_manual()

    def _refresh_after_manual(self) -> None:
        if self._outcome is None:
            return
        run_dir = self._outcome.run_dir
        agg = apply_manual_results(aggregate(self._outcome.results), load_manual_results(run_dir))
        # 与报告同口径：缺截图证据的「无毒」要降级
        shots_dir = run_dir / "screenshots"
        if shots_dir.is_dir():
            agg = mark_missing_evidence(agg, shots_dir)
        verdict, _ = verdict_of(agg)

        kind, label = VERDICT_KIND.get(verdict, ("gray", verdict))
        bg, fg = Badge._COLORS.get(kind, Badge._COLORS["gray"])
        self.verdict_badge.setText(label)
        self.verdict_badge.setStyleSheet(
            f"background:{bg}; color:{fg}; border-radius:4px;"
            "padding:4px 10px; font-size:13px; font-weight:600;"
        )
        self.verdict_text.setText(VERDICT_TEXT.get(verdict, ""))

        for i in range(self.result_table.rowCount()):
            item = self.result_table.item(i, 0)
            if item is None:
                continue
            entry = agg.get(item.data(Qt.ItemDataRole.UserRole))
            if not entry:
                continue
            new_status = entry.get("status", "")
            self.result_table.setItem(
                i, 1, QTableWidgetItem(STATUS_LABEL.get(new_status, new_status))
            )
            msgs = entry.get("messages") or []
            if msgs:
                self.result_table.setItem(i, 4, QTableWidgetItem(str(msgs[-1])))
            # 只有状态真的变了才移除按钮——manual 状态下必须保留「触发/回填」入口
            if new_status != "manual" and self.result_table.cellWidget(i, 5) is not None:
                self.result_table.removeCellWidget(i, 5)
                done = QLabel("已回填")
                done.setStyleSheet(f"color:{theme.GREEN}; font-size:11px;")
                self.result_table.setCellWidget(i, 5, done)

    # ---- 打开产物 ----
    def _open_report(self) -> None:
        if self._outcome and self._outcome.report_md and self._outcome.report_md.is_file():
            os.startfile(str(self._outcome.report_md))  # noqa: S606

    def _open_folder(self) -> None:
        if self._outcome:
            subprocess.Popen(["explorer", str(self._outcome.run_dir)])
