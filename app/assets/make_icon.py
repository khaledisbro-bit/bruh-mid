#!/usr/bin/env python3
"""Generate VmSmart's app icon: a glowing purple rounded square with a script
glyph. Writes icon.png (512) and icon.ico (multi-size)."""
from PIL import Image, ImageDraw, ImageFilter
import os

HERE = os.path.dirname(os.path.abspath(__file__))
S = 512


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded(size, radius, fill):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=fill)
    return img


# base: diagonal purple gradient
base = Image.new("RGBA", (S, S), (0, 0, 0, 0))
grad = Image.new("RGB", (S, S))
gd = grad.load()
c0, c1 = (124, 77, 255), (176, 128, 255)
for y in range(S):
    for x in range(S):
        t = (x + y) / (2 * S)
        gd[x, y] = lerp(c0, c1, t)
mask = rounded(S, 116, (255, 255, 255, 255)).split()[3]
base.paste(grad, (0, 0), mask)

# subtle top glow
glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
gdrw = ImageDraw.Draw(glow)
gdrw.ellipse([S * 0.1, -S * 0.35, S * 0.9, S * 0.4], fill=(220, 200, 255, 90))
glow = glow.filter(ImageFilter.GaussianBlur(40))
base = Image.alpha_composite(base, Image.composite(glow, Image.new("RGBA", (S, S), (0, 0, 0, 0)), mask))

d = ImageDraw.Draw(base)

# script/document glyph
white = (255, 255, 255, 255)
soft = (255, 255, 255, 235)
x0, y0, x1, y1 = 168, 128, 344, 384
# page body
d.rounded_rectangle([x0, y0, x1, y1], radius=26, fill=None, outline=white, width=16)
# folded corner
d.line([(x1 - 56, y0), (x1 - 56, y0 + 56)], fill=white, width=16)
d.line([(x1 - 56, y0 + 56), (x1, y0 + 56)], fill=white, width=16)
d.line([(x1 - 56, y0), (x1, y0 + 56)], fill=white, width=16)
# code chevron  < / >
cx, cy = 256, 268
d.line([(cx - 20, cy - 26), (cx - 44, cy), (cx - 20, cy + 26)], fill=soft, width=15, joint="curve")
d.line([(cx + 20, cy - 26), (cx + 44, cy), (cx + 20, cy + 26)], fill=soft, width=15, joint="curve")
d.line([(cx + 8, cy - 34), (cx - 8, cy + 34)], fill=soft, width=13)

# glow pass on the glyph
glyph_glow = base.filter(ImageFilter.GaussianBlur(6))
base = Image.alpha_composite(glyph_glow, base)

base.save(os.path.join(HERE, "icon.png"))
base.resize((256, 256), Image.LANCZOS).save(
    os.path.join(HERE, "icon.ico"),
    sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("wrote icon.png and icon.ico")
