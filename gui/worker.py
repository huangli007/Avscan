"""后台线程：引擎探测、扫描执行、安装包操作。界面线程只负责渲染。"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from avscan.packages import Pkg, install_package, open_package, verify_packages
from avscan.pipeline import ScanPlan, run_scan


class ProbeWorker(QThread):
    """启动时探测引擎。全盘枚举耗时 1~3 秒，不能放在界面线程。"""

    done = Signal(object)  # list[EngineStatus]
    failed = Signal(str)

    def run(self) -> None:  # noqa: D102
        try:
            from avscan.engines import probe_all

            self.done.emit(probe_all())
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class ScanWorker(QThread):
    progress = Signal(str, str)   # stage, message
    done = Signal(object)         # ScanOutcome
    failed = Signal(str)

    def __init__(self, plan: ScanPlan, label: str, timeout: int, dry_run: bool):
        super().__init__()
        self._plan = plan
        self._label = label
        self._timeout = timeout
        self._dry_run = dry_run
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:  # noqa: D102
        try:
            outcome = run_scan(
                self._plan,
                label=self._label,
                timeout=self._timeout,
                dry_run=self._dry_run,
                on_progress=lambda stage, msg: self.progress.emit(stage, msg),
                should_cancel=lambda: self._cancelled,
            )
            self.done.emit(outcome)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class OpenWorker(QThread):
    """打开资源管理器，失败时回报原因。"""

    done = Signal(bool, str)

    def __init__(self, pkg: Pkg):
        super().__init__()
        self._pkg = pkg

    def run(self) -> None:  # noqa: D102
        ok, msg = open_package(self._pkg)
        self.done.emit(ok, msg)


class InstallWorker(QThread):
    """执行静默安装。杀软安装耗时长，必须放后台并允许超时。"""

    done = Signal(bool, str)

    def __init__(self, pkg: Pkg, timeout: int = 1800):
        super().__init__()
        self._pkg = pkg
        self._timeout = timeout

    def run(self) -> None:  # noqa: D102
        ok, msg = install_package(self._pkg, confirm=True, wait=True, timeout=self._timeout)
        self.done.emit(ok, msg)


class VerifyWorker(QThread):
    """校验归档包签名与哈希。"""

    done = Signal(object)  # list[dict]
    failed = Signal(str)

    def __init__(self, pkgs: list[Pkg]):
        super().__init__()
        self._pkgs = pkgs

    def run(self) -> None:  # noqa: D102
        try:
            self.done.emit(verify_packages(self._pkgs))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
