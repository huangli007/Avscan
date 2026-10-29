"""扫描目标解析：安装包单文件、整个安装目录，或按文件清单批量。

目录默认作为一个扫描单元整体交给引擎（引擎自己递归，最快）；
加 --per-file 才逐文件调用（慢，但能定位到具体文件）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# 高危可执行体
EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi",
    ".mui", ".ax", ".acm", ".tsp",
}
# 脚本类（常被捆绑器用作投放载荷）
SCRIPT_EXTS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".jar", ".py", ".sh", ".reg",
}
# 安装/自解压包
ARCHIVE_EXTS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso",
    ".msi", ".msp", ".appx", ".msix", ".apk", ".dmg", ".pkg", ".deb", ".rpm",
}
# 可携带宏/脚本的文档
DOC_EXTS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf", ".rtf", ".lnk"}

RISK_EXTS = EXEC_EXTS | SCRIPT_EXTS | ARCHIVE_EXTS | DOC_EXTS

_STAT_FILE_LIMIT = 200_000


@dataclass
class Target:
    path: Path
    kind: str                 # "file" | "dir"
    file_count: int = 1
    total_bytes: int = 0
    truncated: bool = False   # 统计被上限截断

    @property
    def label(self) -> str:
        return str(self.path)

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "truncated": self.truncated,
        }


@dataclass
class TargetSet:
    targets: list[Target] = field(default_factory=list)
    mode: str = "dir"         # "dir" 整体扫描 | "file" 逐文件
    excluded: int = 0

    @property
    def file_total(self) -> int:
        return sum(t.file_count for t in self.targets)

    @property
    def byte_total(self) -> int:
        return sum(t.total_bytes for t in self.targets)


def _walk_stats(root: Path) -> tuple[int, int, bool]:
    count = 0
    size = 0
    truncated = False
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            count += 1
                            size += entry.stat(follow_symlinks=False).st_size
                            if count >= _STAT_FILE_LIMIT:
                                return count, size, True
                    except OSError:
                        continue
        except OSError:
            continue
    return count, size, truncated


def walk_stats(root: Path) -> tuple[int, int, bool]:
    """公开别名：统计目录下的文件数与总字节数（供界面展示）。"""
    return _walk_stats(root)


def count_risk_files(root: Path, extensions: set[str] | None = None) -> int:
    """统计目录下符合高危扩展名的文件数（供界面预估逐文件扫描的规模）。"""
    exts = extensions if extensions is not None else RISK_EXTS
    count = 0
    for file in _iter_files(root):
        if file.suffix.lower() in exts:
            count += 1
    return count


def _iter_files(root: Path):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue


def build_target_set(
    specs: list[str],
    *,
    per_file: bool = False,
    extensions: set[str] | None = None,
) -> TargetSet:
    """把命令行传入的路径清单解析成扫描单元。

    extensions 非空时，逐文件模式只保留这些扩展名（目录整体模式不受影响）。
    """
    targets: list[Target] = []
    excluded = 0
    mode = "file" if per_file else "dir"

    for spec in specs:
        path = Path(spec).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"路径不存在: {path}")

        path = path.resolve()

        if path.is_file():
            targets.append(Target(path=path, kind="file", file_count=1, total_bytes=path.stat().st_size))
            continue

        if not per_file:
            count, size, truncated = _walk_stats(path)
            targets.append(
                Target(path=path, kind="dir", file_count=count, total_bytes=size, truncated=truncated)
            )
            continue

        for file in _iter_files(path):
            if extensions and file.suffix.lower() not in extensions:
                excluded += 1
                continue
            try:
                size = file.stat().st_size
            except OSError:
                size = 0
            targets.append(Target(path=file, kind="file", file_count=1, total_bytes=size))

    if not targets:
        raise ValueError("没有可扫描的目标（检查路径或 --mode 过滤条件）")

    return TargetSet(targets=targets, mode=mode, excluded=excluded)


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"
