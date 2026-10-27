#!/usr/bin/env python3
"""Convert icon.png into a multi-resolution Windows icon.

    pip install pillow
    python make_ico.py
"""
from PIL import Image

SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

img = Image.open("icon.png").convert("RGBA")
img.save("icon.ico", format="ICO", sizes=SIZES)
print("wrote icon.ico:", ", ".join(f"{w}x{h}" for w, h in SIZES))