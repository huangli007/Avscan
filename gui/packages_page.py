"""安装包页：集中管理归档的安装包，一键安装或打开文件夹手动安装。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from avscan.packages import KIND_LABEL, Pkg, find, load_manifest, summary

from . import theme
from .widgets import Badge, HLine, Section, tiny
from .worker import InstallWorker, OpenWorker, VerifyWorker

MODE_KIND = {"silent": "green", "manual": "gray", "portable": "blue"}


class PackagesPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._pkgs: list[Pkg] = []
        self._workers: list = []

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

        root.addWidget(self._build_header())
        root.addWidget(HLine())
        root.addWidget(self._build_table_section())
        root.addWidget(self._build_action_section())
        root.addStretch(1)

        scroll.setWidget(content)
        self.reload()

    # ---- 构建 ----
    def _build_header(self) -> QWidget:
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(4)
        title = QLabel("安装包")
        title.setObjectName("PageTitle")
        v.addWidget(title)
        desc = QLabel("带实时防护的杀软无法免安装，这里是归档的安装包：能静默的一键装，其余走手动")
        desc.setObjectName("PageDesc")
        v.addWidget(desc)
        return box

    def _build_table_section(self) -> QWidget:
        verify_btn = QPushButton("校验签名")
        verify_btn.setObjectName("Ghost")
        verify_btn.clicked.connect(self._on_verify)

        section = Section("归档清单", action=verify_btn)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "名称", "安装方式", "版本", "类型", "大小"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.setMinimumHeight(280)
        self.table.itemSelectionChanged.connect(self._on_select)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in (2, 3, 4, 5):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        section.body.addWidget(self.table)

        self.summary_label = tiny("")
        section.body.addWidget(self.summary_label)
        return section

    def _build_action_section(self) -> QWidget:
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        self.hint = QLabel("选中一行后可操作")
        self.hint.setObjectName("Muted")
        v.addWidget(self.hint)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.btn_install = QPushButton("一键安装")
        self.btn_install.setObjectName("Primary")
        self.btn_install.setEnabled(False)
        self.btn_install.clicked.connect(self._on_install)
        row.addWidget(self.btn_install)

        self.btn_open = QPushButton("打开文件夹")
        self.btn_open.setEnabled(False)
        self.btn_open.clicked.connect(self._on_open)
        row.addWidget(self.btn_open)
        row.addStretch(1)
        v.addLayout(row)
        return box

    # ---- 数据 ----
    def reload(self) -> None:
        try:
            self._pkgs = load_manifest()
        except FileNotFoundError:
            self.summary_label.setText("未找到 packages/manifest.json")
            return

        self.table.setRowCount(len(self._pkgs))
        for i, p in enumerate(self._pkgs):
            self.table.setItem(i, 0, QTableWidgetItem(p.id))
            self.table.setItem(i, 1, QTableWidgetItem(p.display))
            mode_item = QTableWidgetItem("文件缺失" if not p.exists else p.mode_label)
            self.table.setItem(i, 2, mode_item)
            self.table.setItem(i, 3, QTableWidgetItem(p.version))
            self.table.setItem(i, 4, QTableWidgetItem(KIND_LABEL.get(p.kind, p.kind)))
            self.table.setItem(i, 5, QTableWidgetItem(f"{p.size_mb:.0f} MB"))

        # 高度贴合行数，避免出现滚动条压住右侧列
        row_h = self.table.verticalHeader().defaultSectionSize()
        self.table.setFixedHeight(min(row_h * len(self._pkgs) + 42, 460))

        s = summary(self._pkgs)
        self.summary_label.setText(
            f"{s['total']} 个包 · {s['total_mb']:.0f} MB ｜ "
            f"可一键安装 {s['silent_ready']} · 需手动 {s['manual_only']} · 免安装 {s['portable']}"
        )

    def _current(self) -> Pkg | None:
        row = self.table.currentRow()
        if 0 <= row < len(self._pkgs):
            return self._pkgs[row]
        return None

    def _on_select(self) -> None:
        pkg = self._current()
        if pkg is None:
            self.btn_install.setEnabled(False)
            self.btn_open.setEnabled(False)
            self.hint.setText("选中一行后可操作")
            return

        can_install = pkg.mode == "silent" and pkg.exists
        self.btn_install.setEnabled(can_install)
        self.btn_open.setEnabled(pkg.exists)

        if pkg.mode == "silent":
            args = " ".join(pkg.silent_args)
            verified = "" if pkg.silent_verified else "（参数未实测，建议先手动装一次）"
            self.hint.setText(f"静默参数：{args} {verified}".strip())
        elif pkg.mode == "portable":
            self.hint.setText("免安装包，直接运行 exe 即可，无需安装")
        else:
            self.hint.setText(pkg.note or "该包没有可靠的静默参数，请用「打开文件夹」手动安装")

    # ---- 操作 ----
    def _on_open(self) -> None:
        pkg = self._current()
        if pkg is None:
            return
        worker = OpenWorker(pkg)
        worker.done.connect(lambda ok, msg: None if ok else QMessageBox.warning(self, "打开失败", msg))
        worker.start()
        self._workers.append(worker)

    def _on_install(self) -> None:
        pkg = self._current()
        if pkg is None or pkg.mode != "silent":
            return

        risks = ["会安装内核驱动，可能与其他安全软件冲突"]
        if pkg.needs_reboot:
            risks.append("安装完成后通常需要重启才能生效")
        if pkg.kind == "online":
            risks.append("在线安装器，需要联网下载主体")

        text = (
            f"即将静默安装：\n\n{pkg.display} {pkg.version}\n\n"
            f"命令：{pkg.file.name} {' '.join(pkg.silent_args)}\n\n"
            + "\n".join(f"· {r}" for r in risks)
            + "\n\n确定继续？"
        )
        reply = QMessageBox.question(
            self,
            "确认安装",
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.btn_install.setEnabled(False)
        self.btn_install.setText("安装中 ...")
        self.hint.setText(f"正在安装 {pkg.display}，请勿关闭窗口 ...")

        worker = InstallWorker(pkg)
        worker.done.connect(self._on_install_done)
        worker.start()
        self._workers.append(worker)

    def _on_install_done(self, ok: bool, message: str) -> None:
        self.btn_install.setText("一键安装")
        self.btn_install.setEnabled(True)
        self.hint.setText(message)
        if ok:
            QMessageBox.information(self, "安装完成", message)
        else:
            QMessageBox.warning(self, "安装未完成", message)

    def _on_verify(self) -> None:
        self.hint.setText("正在校验签名 ...")
        worker = VerifyWorker(self._pkgs)
        worker.done.connect(self._on_verified)
        worker.failed.connect(lambda m: self.hint.setText(f"校验失败：{m}"))
        worker.start()
        self._workers.append(worker)

    def _on_verified(self, rows: list[dict]) -> None:
        bad = [r for r in rows if r["status"] != "Valid"]
        if bad:
            names = "、".join(f"{r['id']}({r['status']})" for r in bad)
            self.hint.setText(f"签名异常：{names}")
            QMessageBox.warning(self, "签名异常", f"以下包签名不通过：\n{names}")
        else:
            self.hint.setText(f"签名全部有效（{len(rows)} 个包）")
