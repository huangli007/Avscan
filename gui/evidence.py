"""扫描证据截图：把引擎原始输出渲染成图片，供报告直接引用。

命令行引擎没有界面，"截图"就是把它的原始输出渲染成终端风格的图片——
这才是它真正的证据。GUI 引擎（火绒等）的界面截图由用户手动放进同一目录，
文件名与引擎 key 一致，报告会自动引用。
"""

from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QTextDocument

BG = "#1e1e1e"
FG = "#d4d4d4"
BAR = "#323233"
ACCENT = "#4ec9b0"


def _esc(text: str) -> str:
    return html.escape(text)


def render_output_png(
    title: str,
    body: str,
    out_path: Path,
    subtitle: str = "",
    max_lines: int = 400,
) -> Path | None:
    """把一段终端输出渲染成 PNG。"""
    raw_lines = body.splitlines()
    truncated = 0
    if len(raw_lines) > max_lines:
        truncated = len(raw_lines) - max_lines
        raw_lines = raw_lines[:max_lines]

    numbered = "\n".join(
        f'<span style="color:#6a9955">{i:>4}</span>  '
        f'<span style="color:#d4d4d4">{_esc(line) or "&nbsp;"}</span>'
        for i, line in enumerate(raw_lines, 1)
    )
    if truncated:
        numbered += f'\n<span style="color:#808080">... 还有 {truncated} 行未显示</span>'

    head = (
        f'<div style="background:{BAR}; padding:8px 12px;">'
        f'<span style="color:#ffffff; font-size:12pt; font-weight:600;">{_esc(title)}</span>'
        + (
            f'<span style="color:#9cdcfe; font-size:9pt;">　{_esc(subtitle)}</span>'
            if subtitle
            else ""
        )
        + "</div>"
    )

    doc = QTextDocument()
    doc.setDocumentMargin(0)
    doc.setDefaultFont(QFont("Consolas", 9))
    doc.setHtml(
        f'<body style="background:{BG}; color:{FG};">'
        f"{head}<pre style='margin:8px 12px;'>{numbered or '&nbsp;'}</pre>"
        f"</body>"
    )

    size = doc.size()
    width = max(760, int(size.width()))
    height = max(140, int(size.height()))
    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor(BG))

    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    doc.drawContents(painter)
    painter.end()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if image.save(str(out_path), "PNG"):
        return out_path
    return None
