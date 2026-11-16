#!/usr/bin/env python3
"""
Build the test set used in this repository from ONE real phone photograph.

    samples/original_phone.jpg   - the untouched photo (copied byte-for-byte, never re-saved)

This script derives three test files from it:

    tampered_splice.jpg      - a flower cluster is cloned onto the empty left wall (copy-move
                               forgery, colour-masked + feathered so it blends in), then re-saved
                               at JPEG quality 95 with an editor tag ("Adobe Photoshop 25.0").
    tampered_no_exif.jpg     - the same edit with ALL metadata stripped (an attacker hiding the editor).
    original_phone_lossless.png - the original converted to PNG (a non-JPEG input, where ELA is
                               not scored).

IMPORTANT: the editor tag is written by this script to emulate an edited file; the edit itself is a
real pixel-level modification, but it was made by code rather than by a person in Photoshop.
For stronger evidence, add your own hand-edited copies to samples/ and re-run the detector.

Usage:  python make_demo_images.py [samples_dir]
"""

import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image


def flower_mask(bgr):
    """Rough mask of the purple flowers + green leaves (saturated pixels on a grey wall)."""
    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    mask = (hsv[..., 1] > 60).astype(np.uint8) * 255
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((9, 9), np.uint8))
    return mask


def make_splice(src: Path) -> Image.Image:
    bgr = cv2.imread(str(src))
    h, w = bgr.shape[:2]
    mask = flower_mask(bgr)

    # Bounding box of the lower half of the hanging flowers -> the patch to clone.
    ys, xs = np.where(mask > 0)
    top, bottom = int(ys.min()), int(ys.max())
    x0, x1 = int(xs.min()), int(xs.max())
    y0 = top + (bottom - top) // 2
    patch = bgr[y0:bottom, x0 - 10:x1 + 10].copy()
    pmask = mask[y0:bottom, x0 - 10:x1 + 10].copy()

    # Slight scale change + brightness shift, so the clone is not a pixel-perfect duplicate.
    scale = 0.85
    patch = cv2.resize(patch, None, fx=scale, fy=scale, interpolation=cv2.INTER_LINEAR)
    pmask = cv2.resize(pmask, None, fx=scale, fy=scale, interpolation=cv2.INTER_LINEAR)
    patch = cv2.convertScaleAbs(patch, alpha=1.06, beta=-4)

    # Feathered alpha so the edges blend; fade the cut-off top edge so no straight line shows.
    alpha = cv2.GaussianBlur(pmask, (0, 0), 3).astype(np.float32) / 255.0
    fade = np.clip(np.arange(alpha.shape[0], dtype=np.float32) / 120.0, 0, 1)[:, None]
    alpha = (alpha * fade)[..., None]

    ph, pw = patch.shape[:2]
    ox, oy = int(w * 0.12), int(h * 0.38)          # empty area of the left wall
    out = bgr.astype(np.float32)
    roi = out[oy:oy + ph, ox:ox + pw]
    out[oy:oy + ph, ox:ox + pw] = alpha * patch + (1 - alpha) * roi
    out = np.clip(out, 0, 255).astype(np.uint8)
    return Image.fromarray(cv2.cvtColor(out, cv2.COLOR_BGR2RGB))


def main(out="samples"):
    out = Path(out)
    src = out / "original_phone.jpg"
    if not src.exists():
        sys.exit(f"Put your real photo at {src} first (copy it straight from the phone, no re-saving).")

    spliced = make_splice(src)

    exif = Image.Exif()
    exif[0x0131] = "Adobe Photoshop 25.0"          # Software
    exif[0x0132] = "2026:11:16 18:40:11"           # DateTime (modified)
    spliced.save(out / "tampered_splice.jpg", quality=95, exif=exif)

    Image.open(out / "tampered_splice.jpg").convert("RGB").save(out / "tampered_no_exif.jpg", quality=95)

    Image.open(src).convert("RGB").save(out / "original_phone_lossless.png")
    print(f"Test images written to {out.resolve()}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
