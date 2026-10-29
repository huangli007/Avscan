"""生成 avscan logo：圆角深底 + 三道同心扫描弧 + 中心原点。

几何全部按画布比例计算，超采样 4 倍后缩放，保证小尺寸不糊。
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parent.parent / "assets"
BG = (55, 53, 47)        # #37352F Notion 主文字色，用作图标底
FG = (255, 255, 255)
ACCENT = (35, 131, 226)  # #2383E2 强调蓝，仅用于中心点

SUPERSAMPLE = 4


def draw_master(size: int = 1024, *, dark_bg: bool = True, accent_dot: bool = True) -> Image.Image:
    w = size * SUPERSAMPLE
    img = Image.new("RGBA", (w, w), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 圆角方块底
    margin = int(w * 0.055)
    radius = int(w * 0.225)
    if dark_bg:
        d.rounded_rectangle(
            [margin, margin, w - margin, w - margin], radius=radius, fill=BG
        )

    cx = cy = w // 2
    ink = FG if dark_bg else BG

    # 16/24 px 下三层细节会糊成一片，直接简化为「单环 + 中心点」
    simple = size <= 24

    if simple:
        r_out = w * 0.33
        lw_out = max(2, int(w * 0.105))
        d.ellipse(
            [cx - r_out, cy - r_out, cx + r_out, cy + r_out],
            outline=ink,
            width=lw_out,
        )
        dot_r = int(w * 0.105)
    else:
        # 外环：留 90° 缺口（缺口落在右上），暗示"扫描进行中"
        # PIL 角度为顺时针、0°=3点钟：0→270 覆盖其余三象限，缺口正好在右上
        r_out = w * 0.355
        lw_out = max(2, int(w * 0.052))
        d.arc(
            [cx - r_out, cy - r_out, cx + r_out, cy + r_out],
            start=0,
            end=270,
            fill=ink,
            width=lw_out,
        )

        # 内环：完整闭合，作为视觉锚点
        r_in = w * 0.205
        lw_in = max(2, int(w * 0.046))
        d.ellipse(
            [cx - r_in, cy - r_in, cx + r_in, cy + r_in],
            outline=ink,
            width=lw_in,
        )
        dot_r = int(w * 0.062)

    # 中心原点：强调蓝，代表"检出点"
    dot_fill = ACCENT if accent_dot else ink
    d.ellipse([cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r], fill=dot_fill)

    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    ASSETS.mkdir(parents=True, exist_ok=True)

    master = draw_master(1024)
    master.save(ASSETS / "logo_1024.png")
    print("logo_1024.png")

    # 界面用小图
    for px in (32, 24, 20):
        draw_master(px).save(ASSETS / f"logo_{px}.png")
        print(f"logo_{px}.png")

    # exe 图标：多尺寸 ICO
    icon_sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [draw_master(s) for s in icon_sizes]
    frames[-1].save(
        ASSETS / "avscan.ico",
        format="ICO",
        sizes=[(s, s) for s in icon_sizes],
        append_images=frames[:-1],
    )
    print("avscan.ico  sizes:", icon_sizes)

    # 浅色版（白底深图），用于浅色背景或文档
    light = draw_master(512, dark_bg=False, accent_dot=True)
    light.save(ASSETS / "logo_light_512.png")
    print("logo_light_512.png")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
