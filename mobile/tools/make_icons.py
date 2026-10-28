"""Generates launcher icons, splash screens and Play Store graphics.
Run: python3 tools/make_icons.py   (needs Pillow)"""
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, 'android/app/src/main/res')
NAVY, WHITE, RED, PAPER = (19, 32, 58), (255, 255, 255), (191, 36, 48), (237, 241, 245)
SS = 4  # supersampling


def glyph(size, bg=None, scale=1.0):
    """Speech bubble with a magnifier: 'check this message'."""
    S = size * SS
    im = Image.new('RGBA', (S, S), bg + (255,) if bg else (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    c = S / 2
    w = S * 0.58 * scale
    h = S * 0.44 * scale
    x0, y0 = c - w / 2, c - h / 2 - S * 0.04 * scale
    r = h * 0.28
    d.rounded_rectangle([x0, y0, x0 + w, y0 + h], radius=r, fill=WHITE)
    # tail
    tx = x0 + w * 0.24
    d.polygon([(tx, y0 + h - 2), (tx + w * 0.16, y0 + h - 2), (tx - w * 0.02, y0 + h + h * 0.30)], fill=WHITE)
    # magnifier
    mr = h * 0.25
    mcx, mcy = c - w * 0.06, y0 + h * 0.46
    lw = max(2, int(h * 0.085))
    d.ellipse([mcx - mr, mcy - mr, mcx + mr, mcy + mr], outline=NAVY, width=lw)
    ang = 0.7071
    hx0, hy0 = mcx + mr * ang * 0.95, mcy + mr * ang * 0.95
    d.line([hx0, hy0, hx0 + mr * 0.9, hy0 + mr * 0.9], fill=NAVY, width=int(lw * 1.35))
    # red alert dot: the "scam" signal
    dr = h * 0.11
    dx, dy = x0 + w * 0.80, y0 + h * 0.30
    d.ellipse([dx - dr, dy - dr, dx + dr, dy + dr], fill=RED)
    return im.resize((size, size), Image.LANCZOS)


def save(im, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    im.save(path)


legacy = {'mdpi': 48, 'hdpi': 72, 'xhdpi': 96, 'xxhdpi': 144, 'xxxhdpi': 192}
for dpi, px in legacy.items():
    sq = glyph(px, NAVY, 1.05)
    save(sq, f'{RES}/mipmap-{dpi}/ic_launcher.png')
    mask = Image.new('L', (px * SS, px * SS), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, px * SS, px * SS], fill=255)
    rnd = Image.new('RGBA', (px, px), (0, 0, 0, 0))
    rnd.paste(sq, (0, 0), mask.resize((px, px), Image.LANCZOS))
    save(rnd, f'{RES}/mipmap-{dpi}/ic_launcher_round.png')
    # adaptive foreground: 108dp canvas, art inside the 66dp safe zone
    fg = round(px * 108 / 48)
    save(glyph(fg, None, 0.66), f'{RES}/mipmap-{dpi}/ic_launcher_foreground.png')

# splash screens (centered mark on navy)
for d in os.listdir(RES):
    p = os.path.join(RES, d, 'splash.png')
    if os.path.exists(p):
        w, h = Image.open(p).size
        sp = Image.new('RGB', (w, h), NAVY)
        m = min(w, h) // 3
        sp.paste(glyph(m, None, 1.0), ((w - m) // 2, (h - m) // 2), glyph(m, None, 1.0))
        sp.save(p)

# Play Store graphics
store = os.path.join(ROOT, 'store')
os.makedirs(store, exist_ok=True)
glyph(512, NAVY, 1.05).convert('RGB').save(f'{store}/icon-512.png')

fg = Image.new('RGB', (1024, 500), NAVY)
fg.paste(glyph(340, None, 1.0), (40, 80), glyph(340, None, 1.0))
d = ImageDraw.Draw(fg)
font_path = os.path.join(ROOT, 'node_modules/@fontsource-variable/archivo/files/archivo-latin-wdth-normal.woff2')
try:
    big = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 76)
    small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 32)
except OSError:
    big = small = ImageFont.load_default()
d.text((410, 150), 'Scam or not?', font=big, fill=WHITE)
d.text((414, 260), 'Share any SMS, WhatsApp message,', font=small, fill=PAPER)
d.text((414, 304), 'link or email. Get a clear verdict.', font=small, fill=PAPER)
fg.save(f'{store}/feature-graphic-1024x500.png')
print('ok')
