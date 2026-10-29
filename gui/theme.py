"""Notion 极简风格：配色 / 字体 / 全局样式表。

原则：无阴影、无渐变，只用 1px 细线与留白建立层次；
主色只有一个强调蓝，其余状态色降饱和，避免像后台管理系统。
"""

from __future__ import annotations

import platform

# ---- 配色 ------------------------------------------------------------------
BG = "#FFFFFF"
BG_SIDEBAR = "#FBFBFA"
BG_HOVER = "#F1F1EF"
BG_ACTIVE = "#EFEFED"
BG_CODE = "#F7F7F5"

BORDER = "#E9E9E7"
BORDER_STRONG = "#DFDFDC"

TEXT = "#37352F"
TEXT_SECONDARY = "#787774"
TEXT_TERTIARY = "#9B9A97"

ACCENT = "#2383E2"
ACCENT_SOFT = "#E7F0FB"

GREEN = "#0F7B6C"
GREEN_SOFT = "#E4F2EF"
RED = "#EB5757"
RED_SOFT = "#FBEAEA"
YELLOW = "#B58A00"
YELLOW_SOFT = "#FBF3E0"
GRAY_SOFT = "#F1F1EF"


def font_family() -> str:
    system = platform.system()
    if system == "Windows":
        return "Microsoft YaHei UI"
    if system == "Darwin":
        return "-apple-system"
    return "Noto Sans CJK SC"


FONT = font_family()
MONO = "Consolas" if platform.system() == "Windows" else "Menlo"


def stylesheet() -> str:
    return f"""
* {{
    font-family: "{FONT}";
    font-size: 13px;
    color: {TEXT};
    outline: none;
}}

QWidget#Root, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {{
    background: {BG};
}}

/* ---------- 侧边栏 ---------- */
QWidget#Sidebar {{
    background: {BG_SIDEBAR};
    border-right: 1px solid {BORDER};
}}
QLabel#Brand {{
    font-size: 14px;
    font-weight: 600;
    color: {TEXT};
}}
QLabel#BrandSub {{
    font-size: 11px;
    color: {TEXT_TERTIARY};
}}
QListWidget#Nav {{
    background: transparent;
    border: none;
    padding: 2px 8px;
}}
QListWidget#Nav::item {{
    height: 32px;
    padding-left: 10px;
    border-radius: 4px;
    color: {TEXT_SECONDARY};
    margin: 1px 0;
}}
QListWidget#Nav::item:hover {{
    background: {BG_HOVER};
    color: {TEXT};
}}
QListWidget#Nav::item:selected {{
    background: {BG_ACTIVE};
    color: {TEXT};
    font-weight: 600;
}}

/* ---------- 标题 ---------- */
QLabel#PageTitle {{
    font-size: 22px;
    font-weight: 700;
    color: {TEXT};
}}
QLabel#PageDesc {{
    font-size: 12px;
    color: {TEXT_TERTIARY};
}}
QLabel#SectionTitle {{
    font-size: 13px;
    font-weight: 600;
    color: {TEXT};
}}
QLabel#SectionSub {{
    font-size: 12px;
    color: {TEXT_TERTIARY};
}}
QLabel#Muted {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
}}
QLabel#Tiny {{
    color: {TEXT_TERTIARY};
    font-size: 11px;
}}
QFrame#HLine {{
    background: {BORDER};
    max-height: 1px;
    min-height: 1px;
    border: none;
}}

/* ---------- 按钮 ---------- */
QPushButton {{
    background: {BG};
    border: 1px solid {BORDER_STRONG};
    border-radius: 4px;
    padding: 5px 12px;
    color: {TEXT};
    font-size: 12px;
}}
QPushButton:hover {{
    background: {BG_HOVER};
}}
QPushButton:pressed {{
    background: {BG_ACTIVE};
}}
QPushButton:disabled {{
    color: {TEXT_TERTIARY};
    border-color: {BORDER};
    background: {BG};
}}
QPushButton#Primary {{
    background: {TEXT};
    border: 1px solid {TEXT};
    color: #FFFFFF;
    font-weight: 600;
    padding: 6px 16px;
}}
QPushButton#Primary:hover {{
    background: #2F2D28;
}}
QPushButton#Primary:disabled {{
    background: {BORDER_STRONG};
    border-color: {BORDER_STRONG};
    color: #FFFFFF;
}}
QPushButton#Ghost {{
    background: transparent;
    border: none;
    color: {TEXT_SECONDARY};
    padding: 4px 8px;
}}
QPushButton#Ghost:hover {{
    background: {BG_HOVER};
    color: {TEXT};
}}
QPushButton#Link {{
    background: transparent;
    border: none;
    color: {ACCENT};
    padding: 2px 0;
    text-align: left;
}}
QPushButton#Link:hover {{
    text-decoration: underline;
}}

/* ---------- 输入 ---------- */
QLineEdit, QTextEdit {{
    background: {BG};
    border: 1px solid {BORDER_STRONG};
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT};
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color: {ACCENT};
}}

/* ---------- 拖拽区 ---------- */
QFrame#DropZone {{
    background: {BG};
    border: 1px dashed {BORDER_STRONG};
    border-radius: 6px;
}}
QFrame#DropZone[dragging="true"] {{
    background: {ACCENT_SOFT};
    border: 1px dashed {ACCENT};
}}

/* ---------- 表格 ---------- */
QTableWidget {{
    background: {BG};
    border: none;
    gridline-color: transparent;
}}
QTableWidget::item {{
    padding: 7px 6px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT};
}}
QTableWidget::item:selected {{
    background: {BG_ACTIVE};
    color: {TEXT};
}}
QHeaderView::section {{
    background: {BG};
    border: none;
    border-bottom: 1px solid {BORDER_STRONG};
    padding: 7px 6px;
    color: {TEXT_TERTIARY};
    font-size: 11px;
    font-weight: 600;
    text-align: left;
}}
QTableCornerButton::section {{
    background: {BG};
    border: none;
}}

/* ---------- 列表 ---------- */
QListWidget {{
    background: {BG};
    border: none;
}}
QListWidget::item {{
    padding: 6px 8px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT};
}}
QListWidget::item:hover {{
    background: {BG_HOVER};
}}

/* ---------- 复选 ---------- */
QCheckBox {{
    spacing: 8px;
    color: {TEXT};
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {BORDER_STRONG};
    border-radius: 3px;
    background: {BG};
}}
QCheckBox::indicator:hover {{
    border-color: {TEXT_TERTIARY};
}}
QCheckBox::indicator:checked {{
    background: {TEXT};
    border-color: {TEXT};
}}

/* ---------- 进度条 ---------- */
QProgressBar {{
    background: {GRAY_SOFT};
    border: none;
    border-radius: 2px;
    height: 4px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {TEXT};
    border-radius: 2px;
}}

/* ---------- 滚动条 ---------- */
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: #D9D9D6;
    border-radius: 4px;
    min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{
    background: #C4C4C1;
}}
QScrollBar::add-line, QScrollBar::sub-line,
QScrollBar::add-page, QScrollBar::sub-page {{
    height: 0;
    background: transparent;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
}}
QScrollBar::handle:horizontal {{
    background: #D9D9D6;
    border-radius: 4px;
    min-width: 28px;
}}

/* ---------- 分隔与提示 ---------- */
QSplitter::handle {{
    background: {BORDER};
}}
QToolTip {{
    background: {TEXT};
    color: #FFFFFF;
    border: none;
    padding: 5px 8px;
    border-radius: 4px;
    font-size: 11px;
}}
"""
