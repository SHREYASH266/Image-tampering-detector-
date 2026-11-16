#!/usr/bin/env python3
"""
Image Tampering Detector using Error Level Analysis (ELA) & Metadata Inspection
===============================================================================
Mini-project for Cyber Security and Digital Forensics (CSDF).

Pipeline (per image), as described in the project report:
    1. File validation + basic properties (format, size, dimensions, mode)
    2. SHA-256 hash (optional MD5 / SHA-1) of the exact file bytes
    3. EXIF metadata extraction
    4. Error Level Analysis  ->  ELA(x,y) = k * |I(x,y) - I_q(x,y)|
    5. RGB channel statistics + block-wise anomaly check
    6. Metadata consistency checks (editing software, missing EXIF, time mismatch)
    7. Rule-based suspicion score (0-100) with a documented weight per indicator
    8. Integrity comparison against trusted reference hashes (optional)
    9. Text + CSV report, ELA images saved alongside

IMPORTANT: results are *indicators for further expert examination*, not proof
that an image is genuine or forged. All weights/thresholds below are
demonstration values and should be tuned on your own labelled test images.

Usage examples
--------------
    python image_tampering_detector.py photo1.jpg photo2.jpg
    python image_tampering_detector.py ./evidence_folder -o results
    python image_tampering_detector.py ./evidence_folder --save-baseline baseline.csv
    python image_tampering_detector.py ./evidence_folder --reference baseline.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import cv2
import matplotlib

matplotlib.use("Agg")  # headless: works in Colab, servers and local terminals
import matplotlib.pyplot as plt
import numpy as np
from PIL import ExifTags, Image, ImageChops

# --------------------------------------------------------------------------- #
# Configuration (all tunable constants live here, so the method is documented
# and repeatable - see report Section 5.1)
# --------------------------------------------------------------------------- #


@dataclass
class Config:
    # --- ELA ---
    ela_quality: int = 90            # JPEG quality used for the resave
    ela_scale: float = 15.0          # amplification factor k
    high_error_level: float = 120.0  # amplified-error level counted as "high"
    ela_mean_threshold: float = 25.0         # mean amplified error considered high
    high_error_ratio_threshold: float = 0.10 # fraction of "high" pixels considered large
    ela_block_z_threshold: float = 3.0       # robust z-score of log(ELA / texture) for an outlier block
    ela_mad_floor: float = 0.1               # floor for the spread of that log-ratio (avoids dividing by ~0)
    ela_texture_floor: float = 15.0          # blocks flatter than this (mean Sobel gradient) are ignored
    region_ratio_threshold: float = 0.002    # largest outlier-block cluster (fraction of image blocks)

    # --- RGB block-wise analysis ---
    block_size: int = 32
    block_z_threshold: float = 4.0           # robust z-score for an anomalous block
    block_anomaly_ratio_threshold: float = 0.08  # fraction of anomalous blocks that raises the flag

    # --- Suspicion score weights (report Section 3.8; they sum to 100) ---
    weights: dict = field(default_factory=lambda: {
        "ela": 40,
        "editing_software": 20,
        "time_mismatch": 15,
        "missing_exif": 10,
        "block_anomaly": 15,
    })

    # --- Review levels (report Section 3.8) ---
    medium_from: int = 30
    high_from: int = 60

    # --- Metadata keywords that indicate an image editor ---
    editor_keywords: tuple = (
        "photoshop", "gimp", "lightroom", "paint.net", "pixlr", "affinity",
        "corel", "paintshop", "snapseed", "canva", "picsart", "krita",
        "photoscape", "fotor", "illustrator", "capture one", "darktable",
    )


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}

EXIF_IFD_POINTER = 0x8769  # Exif sub-IFD (holds DateTimeOriginal etc.)

# --------------------------------------------------------------------------- #
# 1-2. File validation, basic properties, hashes
# --------------------------------------------------------------------------- #


def compute_hashes(path: Path) -> dict:
    """SHA-256 (primary) plus MD5 / SHA-1 (legacy reference) of the exact file bytes."""
    sha256, md5, sha1 = hashlib.sha256(), hashlib.md5(), hashlib.sha1()
    with open(path, "rb") as f:  # read-only: the evidence file is never modified
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "sha1": sha1.hexdigest()}


def basic_properties(path: Path, image: Image.Image) -> dict:
    return {
        "file_name": path.name,
        "format": image.format or "Unknown",
        "width": image.width,
        "height": image.height,
        "color_mode": image.mode,
        "file_size_bytes": path.stat().st_size,
    }


# --------------------------------------------------------------------------- #
# 3. EXIF metadata
# --------------------------------------------------------------------------- #


def _clean(value) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).strip().strip("\x00")


def read_exif(image: Image.Image) -> dict:
    """Return EXIF as {readable_tag_name: value}, merging the main IFD and the Exif sub-IFD."""
    meta: dict = {}
    try:
        exif = image.getexif()
        if not exif:
            return meta
        for tag_id, value in exif.items():
            meta[ExifTags.TAGS.get(tag_id, str(tag_id))] = _clean(value)
        try:
            for tag_id, value in exif.get_ifd(EXIF_IFD_POINTER).items():
                meta[ExifTags.TAGS.get(tag_id, str(tag_id))] = _clean(value)
        except Exception:
            pass
    except Exception:
        pass
    return meta


def parse_exif_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value[:19], fmt)
        except ValueError:
            continue
    return None


def metadata_checks(meta: dict, fmt: str, claims_camera: bool, cfg: Config) -> dict:
    """Metadata consistency checks (report Section 3.5)."""
    flags: list[str] = []

    software = meta.get("Software", "")
    editor_hit = next((k for k in cfg.editor_keywords if k in software.lower()), None)
    if editor_hit:
        flags.append(f"Software tag names an image editor: '{software}'")

    capture = parse_exif_datetime(meta.get("DateTimeOriginal"))
    modified = parse_exif_datetime(meta.get("DateTime"))
    time_mismatch = bool(capture and modified and modified > capture)
    if time_mismatch:
        flags.append(f"Modification time ({modified}) is later than capture time ({capture})")

    missing_exif = bool(claims_camera and fmt == "JPEG" and not meta)
    if missing_exif:
        flags.append("No EXIF metadata on a JPEG treated as a camera photograph")

    return {
        "editing_software": bool(editor_hit),
        "time_mismatch": time_mismatch,
        "missing_exif": missing_exif,
        "flags": flags,
    }


# --------------------------------------------------------------------------- #
# 4. Error Level Analysis
# --------------------------------------------------------------------------- #


def run_ela(rgb: Image.Image, cfg: Config) -> tuple[np.ndarray, dict]:
    """
    Resave at a fixed JPEG quality and amplify the absolute difference:
        ELA(x, y) = k * |I(x, y) - I_q(x, y)|
    The resave happens in memory, so no temporary file is written.
    """
    buffer = io.BytesIO()
    rgb.save(buffer, "JPEG", quality=cfg.ela_quality)
    buffer.seek(0)
    resaved = Image.open(buffer).convert("RGB")

    diff = ImageChops.difference(rgb, resaved)
    ela = np.asarray(diff, dtype=np.float32) * cfg.ela_scale  # may exceed 255 (kept for statistics)
    per_pixel = ela.max(axis=2)

    high_mask = per_pixel > cfg.high_error_level
    high_ratio = float(high_mask.mean())

    # Isolated pasted/edited areas carry a different compression history from the rest of the
    # image. Raw ELA is strongly driven by texture (a detailed object always has more error than
    # a plain wall), so each block's mean error is normalised by its own texture strength
    # (mean Sobel gradient). Textured blocks whose error is unusually high *for their texture*
    # are outliers; we measure the largest connected cluster of them.
    largest_region_ratio = 0.0
    b = cfg.block_size
    by, bx = per_pixel.shape[0] // b, per_pixel.shape[1] // b
    if by >= 4 and bx >= 4:
        gray = cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2GRAY).astype(np.float32)
        texture = np.hypot(cv2.Sobel(gray, cv2.CV_32F, 1, 0), cv2.Sobel(gray, cv2.CV_32F, 0, 1))
        blk = lambda a: a[: by * b, : bx * b].reshape(by, b, bx, b).mean(axis=(1, 3))
        block_err, block_tex = blk(per_pixel), blk(texture)
        textured = block_tex > cfg.ela_texture_floor
        if textured.sum() >= 20:
            ratio = np.log((block_err + 1.0) / (block_tex + 1.0))
            med = np.median(ratio[textured])
            mad = max(np.median(np.abs(ratio[textured] - med)) * 1.4826, cfg.ela_mad_floor)
            outlier = (((ratio - med) / mad > cfg.ela_block_z_threshold) & textured).astype(np.uint8)
            if outlier.any():
                n_labels, _, stats, _ = cv2.connectedComponentsWithStats(outlier, connectivity=4)
                if n_labels > 1:
                    largest_region_ratio = float(stats[1:, cv2.CC_STAT_AREA].max() / outlier.size)

    return ela, {
        "ela_mean": float(ela.mean()),
        "ela_max": float(ela.max()),
        "high_error_ratio": high_ratio,
        "largest_high_error_region_ratio": largest_region_ratio,
    }


def save_ela_images(ela: np.ndarray, stem: str, out_dir: Path) -> tuple[Path, np.ndarray]:
    """Save the amplified ELA image; also return a colour heatmap (RGB) for the figure."""
    ela_u8 = np.clip(ela, 0, 255).astype(np.uint8)
    ela_path = out_dir / f"{stem}_ela.png"
    Image.fromarray(ela_u8).save(ela_path)

    gray = ela_u8.max(axis=2)
    heat_bgr = cv2.applyColorMap(gray, cv2.COLORMAP_JET)
    heat_rgb = cv2.cvtColor(heat_bgr, cv2.COLOR_BGR2RGB)
    return ela_path, heat_rgb


# --------------------------------------------------------------------------- #
# 5. RGB channel statistics + block-wise anomalies
# --------------------------------------------------------------------------- #


def channel_analysis(rgb: Image.Image, cfg: Config) -> dict:
    arr = np.asarray(rgb, dtype=np.float32)
    means = arr.mean(axis=(0, 1))
    stds = arr.std(axis=(0, 1))
    result = {
        "mean_r": float(means[0]), "mean_g": float(means[1]), "mean_b": float(means[2]),
        "std_r": float(stds[0]), "std_g": float(stds[1]), "std_b": float(stds[2]),
        "blocks_total": 0, "anomalous_blocks": 0, "anomaly_ratio": 0.0,
    }

    b = cfg.block_size
    by, bx = arr.shape[0] // b, arr.shape[1] // b
    if by < 4 or bx < 4:  # too small for a meaningful block comparison
        return result

    blocks = arr[: by * b, : bx * b].reshape(by, b, bx, b, 3)
    block_mean = blocks.mean(axis=(1, 3))   # (by, bx, 3)

    # Noise level per block from the Laplacian residual (median-based, so edges barely matter).
    gray = cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2GRAY).astype(np.float32)
    lap = np.abs(cv2.Laplacian(gray, cv2.CV_32F))[: by * b, : bx * b].reshape(by, b, bx, b)
    block_noise = np.median(lap, axis=(1, 3)) / 0.6745

    # Features: colour balance (R-G, B-G) and noise level - a region from another source
    # often differs in these even when it blends in visually.
    feats = np.stack([
        block_mean[..., 0] - block_mean[..., 1],
        block_mean[..., 2] - block_mean[..., 1],
        np.log1p(block_noise),
    ], axis=-1).reshape(-1, 3)

    # Robust z-score (median / MAD) so a few odd blocks do not distort the baseline.
    med = np.median(feats, axis=0)
    mad = np.median(np.abs(feats - med), axis=0) * 1.4826
    mad = np.maximum(mad, np.array([2.0, 2.0, 0.15]))  # floors avoid division by ~0 on flat images
    z = np.abs(feats - med) / mad
    anomalous = (z.max(axis=1) > cfg.block_z_threshold)

    result["blocks_total"] = int(anomalous.size)
    result["anomalous_blocks"] = int(anomalous.sum())
    result["anomaly_ratio"] = float(anomalous.mean())
    return result


# --------------------------------------------------------------------------- #
# 7. Suspicion score
# --------------------------------------------------------------------------- #


def score_image(is_jpeg: bool, ela_stats: dict, chan: dict, meta_res: dict, cfg: Config) -> dict:
    contributions: list[tuple[str, int]] = []

    ela_flag = False
    if is_jpeg:  # ELA is only meaningful for JPEG (report Section 2.3 / 6.2)
        ela_flag = (
            ela_stats["ela_mean"] > cfg.ela_mean_threshold
            or ela_stats["high_error_ratio"] > cfg.high_error_ratio_threshold
            or ela_stats["largest_high_error_region_ratio"] > cfg.region_ratio_threshold
        )
    block_flag = chan["anomaly_ratio"] > cfg.block_anomaly_ratio_threshold

    if ela_flag:
        contributions.append(("High ELA mean or large high-error region", cfg.weights["ela"]))
    if meta_res["editing_software"]:
        contributions.append(("Editing-software tag present", cfg.weights["editing_software"]))
    if meta_res["time_mismatch"]:
        contributions.append(("Modification time later than capture time", cfg.weights["time_mismatch"]))
    if meta_res["missing_exif"]:
        contributions.append(("Missing EXIF on a claimed camera photo", cfg.weights["missing_exif"]))
    if block_flag:
        contributions.append(("Block-wise channel anomaly", cfg.weights["block_anomaly"]))

    score = min(100, sum(w for _, w in contributions))
    if score >= cfg.high_from:
        level = "High - detailed expert examination needed"
    elif score >= cfg.medium_from:
        level = "Medium - manual review suggested"
    else:
        level = "Low - no strong indicators"
    return {"score": score, "level": level, "contributions": contributions,
            "ela_flag": ela_flag, "block_flag": block_flag}


# --------------------------------------------------------------------------- #
# 8. Reference-hash integrity comparison
# --------------------------------------------------------------------------- #


def load_reference_hashes(path: str) -> dict:
    """Load trusted hashes as {file_name: sha256}. Accepts CSV (file_name,sha256) or JSON."""
    p = Path(path)
    if p.suffix.lower() == ".json":
        return {k: v.lower() for k, v in json.loads(p.read_text()).items()}
    refs = {}
    with open(p, newline="") as f:
        for row in csv.DictReader(f):
            refs[row["file_name"]] = row["sha256"].strip().lower()
    return refs


def integrity_status(name: str, sha256: str, refs: dict | None) -> str:
    if refs is None:
        return "NO REFERENCE SUPPLIED"
    if name not in refs:
        return "NOT IN REFERENCE LIST"
    return "MATCH" if refs[name] == sha256 else "MISMATCH - file bytes have changed"


# --------------------------------------------------------------------------- #
# Per-image driver
# --------------------------------------------------------------------------- #


def analyze_image(path: Path, out_dir: Path, cfg: Config, refs: dict | None,
                  claims_camera: bool, make_figure: bool = True) -> dict:
    result: dict = {"file_name": path.name, "path": str(path)}
    try:
        hashes = compute_hashes(path)
        with Image.open(path) as image:
            image.load()
            props = basic_properties(path, image)
            meta = read_exif(image)
            rgb = image.convert("RGB")
    except Exception as exc:  # corrupt / unsupported file: report it, keep going
        result["error"] = f"Could not open as an image: {exc}"
        return result

    is_jpeg = props["format"] == "JPEG"
    ela, ela_stats = run_ela(rgb, cfg)
    stem = path.stem
    ela_path, heat_rgb = save_ela_images(ela, stem, out_dir)
    chan = channel_analysis(rgb, cfg)
    meta_res = metadata_checks(meta, props["format"], claims_camera, cfg)
    scoring = score_image(is_jpeg, ela_stats, chan, meta_res, cfg)

    notes = []
    if not is_jpeg:
        notes.append(f"Format is {props['format']}, not JPEG: ELA is unreliable and was not scored.")

    result.update(props)
    result.update(hashes)
    result.update({
        "exif": meta, "is_jpeg": is_jpeg,
        "ela": ela_stats, "channels": chan, "metadata_checks": meta_res,
        "scoring": scoring, "notes": notes,
        "integrity": integrity_status(path.name, hashes["sha256"], refs),
        "ela_image": str(ela_path),
    })

    if make_figure:
        fig_path = out_dir / f"{stem}_analysis.png"
        _save_figure(rgb, heat_rgb, result, fig_path, cfg)
        result["figure"] = str(fig_path)
    return result


def _save_figure(rgb: Image.Image, heat_rgb: np.ndarray, r: dict, out_path: Path, cfg: Config) -> None:
    """Original | ELA heatmap | RGB histograms, with the verdict in the title."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6))
    axes[0].imshow(rgb)
    axes[0].set_title("Original")
    axes[1].imshow(heat_rgb)
    axes[1].set_title(f"ELA heatmap (q={cfg.ela_quality}, k={cfg.ela_scale:g})")
    for ax in axes[:2]:
        ax.axis("off")
    arr = np.asarray(rgb)
    for idx, (name, colour) in enumerate((("R", "red"), ("G", "green"), ("B", "blue"))):
        axes[2].hist(arr[..., idx].ravel(), bins=64, range=(0, 255),
                     color=colour, alpha=0.45, label=name)
    axes[2].set_title("RGB channel histograms")
    axes[2].legend()
    fig.suptitle(f"{r['file_name']}  -  score {r['scoring']['score']}/100  -  {r['scoring']['level']}",
                 fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=110)
    plt.close(fig)


# --------------------------------------------------------------------------- #
# 9. Reports
# --------------------------------------------------------------------------- #

CAVEAT = (
    "CAVEAT: These results are screening indicators, not proof. Resaving, resizing and "
    "social-media compression can create misleading ELA patterns; metadata can be edited or "
    "stripped; a hash only proves integrity when compared with a trusted earlier value. "
    "Interpret findings together with acquisition context and other evidence."
)


def format_text_report(results: list[dict], cfg: Config) -> str:
    lines = ["=" * 78, "IMAGE TAMPERING SCREENING REPORT", "=" * 78,
             f"Generated : {datetime.now():%Y-%m-%d %H:%M:%S}",
             f"Images    : {len(results)}",
             f"ELA setup : JPEG quality {cfg.ela_quality}, amplification k = {cfg.ela_scale:g}", ""]

    for r in results:
        lines += ["-" * 78, f"FILE: {r['file_name']}", "-" * 78]
        if "error" in r:
            lines += [f"  ERROR: {r['error']}", ""]
            continue
        e, c, m, s = r["ela"], r["channels"], r["metadata_checks"], r["scoring"]
        exif = r["exif"]
        lines += [
            "[File information]",
            f"  Format / mode : {r['format']} / {r['color_mode']}",
            f"  Dimensions    : {r['width']} x {r['height']}",
            f"  File size     : {r['file_size_bytes']:,} bytes",
            f"  SHA-256       : {r['sha256']}",
            f"  MD5 / SHA-1   : {r['md5']} / {r['sha1']}",
            f"  Integrity     : {r['integrity']}",
            "",
            "[EXIF metadata]",
        ]
        if exif:
            for key in ("Make", "Model", "Software", "DateTimeOriginal", "DateTime"):
                lines.append(f"  {key:<17}: {exif.get(key, 'Not available')}")
        else:
            lines.append("  No EXIF metadata found")
        lines += [
            "",
            "[Error Level Analysis]",
            f"  Mean error level          : {e['ela_mean']:.2f}",
            f"  Maximum error level       : {e['ela_max']:.2f}",
            f"  High-error pixel ratio    : {e['high_error_ratio']:.4f}",
            f"  Largest outlier-error block cluster : {e['largest_high_error_region_ratio']:.1%} of image blocks",
            f"  ELA flag                  : {'YES' if s['ela_flag'] else 'no'}",
            f"  ELA image                 : {Path(r['ela_image']).name}",
            "",
            "[RGB channel statistics]",
            f"  Mean (R,G,B) : {c['mean_r']:.1f}, {c['mean_g']:.1f}, {c['mean_b']:.1f}",
            f"  Std  (R,G,B) : {c['std_r']:.1f}, {c['std_g']:.1f}, {c['std_b']:.1f}",
            f"  Anomalous blocks : {c['anomalous_blocks']} / {c['blocks_total']} "
            f"({c['anomaly_ratio']:.1%})",
            "",
            "[Metadata flags]",
        ]
        lines += [f"  - {f}" for f in m["flags"]] or ["  None"]
        lines += ["", "[Suspicion score]"]
        for label, w in s["contributions"]:
            lines.append(f"  +{w:<3} {label}")
        if not s["contributions"]:
            lines.append("  (no indicators triggered)")
        lines += [f"  TOTAL: {s['score']} / 100  ->  {s['level']}"]
        for note in r["notes"]:
            lines.append(f"  Note: {note}")
        lines.append("")

    ok = [r for r in results if "error" not in r]
    lows = sum(r["scoring"]["score"] < cfg.medium_from for r in ok)
    meds = sum(cfg.medium_from <= r["scoring"]["score"] < cfg.high_from for r in ok)
    highs = sum(r["scoring"]["score"] >= cfg.high_from for r in ok)
    mismatches = sum(r["integrity"].startswith("MISMATCH") for r in ok)
    lines += ["=" * 78, "BATCH SUMMARY", "=" * 78,
              f"  Total images processed : {len(results)}  (unreadable: {len(results) - len(ok)})",
              f"  Rated Low              : {lows}",
              f"  Rated Medium           : {meds}",
              f"  Rated High             : {highs}",
              f"  Reference-hash mismatches : {mismatches}",
              "", CAVEAT, ""]
    return "\n".join(lines)


CSV_COLUMNS = [
    "file_name", "format", "width", "height", "file_size_bytes", "sha256", "md5", "sha1",
    "integrity", "exif_make", "exif_model", "exif_software", "exif_datetime_original", "exif_datetime",
    "ela_mean", "ela_max", "high_error_ratio", "largest_high_error_region_ratio",
    "anomalous_blocks", "blocks_total", "metadata_flags", "suspicion_score", "review_level", "error",
]


def write_csv(results: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in results:
            if "error" in r:
                w.writerow({"file_name": r["file_name"], "error": r["error"]})
                continue
            ex = r["exif"]
            w.writerow({
                "file_name": r["file_name"], "format": r["format"], "width": r["width"],
                "height": r["height"], "file_size_bytes": r["file_size_bytes"],
                "sha256": r["sha256"], "md5": r["md5"], "sha1": r["sha1"], "integrity": r["integrity"],
                "exif_make": ex.get("Make", ""), "exif_model": ex.get("Model", ""),
                "exif_software": ex.get("Software", ""),
                "exif_datetime_original": ex.get("DateTimeOriginal", ""),
                "exif_datetime": ex.get("DateTime", ""),
                "ela_mean": round(r["ela"]["ela_mean"], 3), "ela_max": round(r["ela"]["ela_max"], 3),
                "high_error_ratio": round(r["ela"]["high_error_ratio"], 5),
                "largest_high_error_region_ratio": round(r["ela"]["largest_high_error_region_ratio"], 5),
                "anomalous_blocks": r["channels"]["anomalous_blocks"],
                "blocks_total": r["channels"]["blocks_total"],
                "metadata_flags": " | ".join(r["metadata_checks"]["flags"]),
                "suspicion_score": r["scoring"]["score"], "review_level": r["scoring"]["level"],
                "error": "",
            })


def write_baseline(results: list[dict], path: Path) -> None:
    """Record trusted SHA-256 values now, to compare against in a later run (--reference)."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file_name", "sha256"])
        for r in results:
            if "error" not in r:
                w.writerow([r["file_name"], r["sha256"]])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def collect_files(inputs: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            files += sorted(f for f in p.iterdir() if f.suffix.lower() in SUPPORTED_EXTENSIONS)
        elif p.is_file():
            files.append(p)
        else:
            print(f"Warning: '{item}' not found, skipping.", file=sys.stderr)
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Screen images for possible tampering (ELA + metadata + hashing).")
    ap.add_argument("inputs", nargs="+", help="image files and/or folders")
    ap.add_argument("-o", "--output", default="tamper_report", help="output folder (default: tamper_report)")
    ap.add_argument("--reference", help="trusted hashes (CSV with file_name,sha256 columns, or JSON {name: sha256})")
    ap.add_argument("--save-baseline", metavar="CSV", help="write current SHA-256 hashes as a baseline for later runs")
    ap.add_argument("--no-camera-claim", action="store_true",
                    help="do not treat JPEGs as camera photos (disables the missing-EXIF indicator)")
    ap.add_argument("--no-figures", action="store_true", help="skip the per-image analysis figure")
    args = ap.parse_args(argv)

    cfg = Config()
    files = collect_files(args.inputs)
    if not files:
        print("No images to analyse.", file=sys.stderr)
        return 1

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    refs = load_reference_hashes(args.reference) if args.reference else None

    results = []
    for i, path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {path.name}")
        results.append(analyze_image(path, out_dir, cfg, refs,
                                     claims_camera=not args.no_camera_claim,
                                     make_figure=not args.no_figures))

    report = format_text_report(results, cfg)
    (out_dir / "tampering_report.txt").write_text(report, encoding="utf-8")
    write_csv(results, out_dir / "tampering_report.csv")
    if args.save_baseline:
        write_baseline(results, Path(args.save_baseline))

    print("\n" + "-" * 60)
    print(f"{'File':<32}{'Score':>6}  Review level")
    for r in results:
        if "error" in r:
            print(f"{r['file_name']:<32}{'--':>6}  ERROR: {r['error']}")
        else:
            print(f"{r['file_name']:<32}{r['scoring']['score']:>6}  {r['scoring']['level']}")
    print("-" * 60)
    print(f"Report written to: {out_dir.resolve()}")
    print(CAVEAT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
