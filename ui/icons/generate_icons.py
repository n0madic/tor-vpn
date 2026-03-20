#!/usr/bin/env python3
"""Generate all icon sizes from SVG for Tauri app."""
import os
import subprocess
import shutil
import cairosvg
from PIL import Image

ICONS_DIR = os.path.dirname(os.path.abspath(__file__))
SVG_FILE = os.path.join(ICONS_DIR, "icon.svg")

def svg_to_png(svg_path, png_path, size):
    """Convert SVG to PNG at given size."""
    cairosvg.svg2png(
        url=svg_path,
        write_to=png_path,
        output_width=size,
        output_height=size,
    )
    print(f"  Generated {os.path.basename(png_path)} ({size}x{size})")

def generate_ico(png_path, ico_path):
    """Generate ICO with multiple sizes."""
    img = Image.open(png_path)
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    imgs = [img.resize(s, Image.LANCZOS) for s in sizes]
    imgs[0].save(ico_path, format="ICO", sizes=sizes, append_images=imgs[1:])
    print("  Generated icon.ico (multi-size)")

def generate_icns(icons_dir):
    """Generate ICNS using macOS iconutil."""
    iconset_dir = os.path.join(icons_dir, "icon.iconset")
    os.makedirs(iconset_dir, exist_ok=True)

    # iconutil requires specific filenames
    size_map = {
        "icon_16x16.png": 16,
        "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32,
        "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128,
        "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256,
        "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512,
        "icon_512x512@2x.png": 1024,
    }

    for name, size in size_map.items():
        svg_to_png(SVG_FILE, os.path.join(iconset_dir, name), size)

    subprocess.run(
        ["iconutil", "-c", "icns", iconset_dir, "-o", os.path.join(icons_dir, "icon.icns")],
        check=True,
    )
    print("  Generated icon.icns")

    # Cleanup iconset
    shutil.rmtree(iconset_dir)

def main():
    print("Generating icons from SVG...")

    # Tauri required PNGs
    svg_to_png(SVG_FILE, os.path.join(ICONS_DIR, "32x32.png"), 32)
    svg_to_png(SVG_FILE, os.path.join(ICONS_DIR, "128x128.png"), 128)
    svg_to_png(SVG_FILE, os.path.join(ICONS_DIR, "128x128@2x.png"), 256)
    svg_to_png(SVG_FILE, os.path.join(ICONS_DIR, "icon.png"), 512)

    # ICO for Windows
    generate_ico(os.path.join(ICONS_DIR, "icon.png"), os.path.join(ICONS_DIR, "icon.ico"))

    # ICNS for macOS
    generate_icns(ICONS_DIR)

    print("Done!")

if __name__ == "__main__":
    main()
