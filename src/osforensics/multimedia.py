"""Multimedia Forensics Analysis.

Analyses media files (images, video, audio) found within a filesystem
snapshot and extracts forensically meaningful artefacts.

Subsections
-----------
1. File discovery          – walk the fs, collect media by MIME/extension
2. EXIF / metadata         – extract camera, GPS, timestamps, software tags
3. Steganography indicators – entropy, appended data, size anomalies
4. File integrity          – metadata/filesystem timestamp mismatch
5. Thumbnail recovery      – extract embedded JFIF/EXIF thumbnails
6. Video metadata          – ffprobe: encoder, timestamps, GPS, streams
7. Audio metadata          – mutagen: tags, recording device, encoder
8. File-type mismatch      – python-magic MIME vs declared extension
9. Media timeline          – correlate media timestamps with analysis ts
"""
from __future__ import annotations

import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .extractor import FilesystemAccessor

# ── Optional dependencies (graceful fallbacks) ────────────────────────────────

try:
    import exifread as _exifread
    _HAS_EXIFREAD = True
except Exception:
    _exifread = None  # type: ignore
    _HAS_EXIFREAD = False

try:
    from PIL import Image as _PILImage
    _HAS_PIL = True
except Exception:
    _PILImage = None  # type: ignore
    _HAS_PIL = False

try:
    import magic as _magic
    _HAS_MAGIC = True
except Exception:
    _magic = None  # type: ignore
    _HAS_MAGIC = False

try:
    import mutagen as _mutagen
    _HAS_MUTAGEN = True
except Exception:
    _mutagen = None  # type: ignore
    _HAS_MUTAGEN = False

_HAS_FFPROBE = bool(shutil.which("ffprobe"))

# ── Extension / MIME mappings ─────────────────────────────────────────────────

IMAGE_EXTS = frozenset(
    ".jpg .jpeg .png .gif .bmp .tiff .tif .webp .heic .heif .raw .cr2 .nef .arw".split()
)
VIDEO_EXTS = frozenset(
    ".mp4 .mkv .avi .mov .wmv .flv .webm .m4v .mpeg .mpg .ts .mts .3gp".split()
)
AUDIO_EXTS = frozenset(
    ".mp3 .flac .wav .ogg .m4a .aac .wma .opus .aiff .aif .mid .midi".split()
)
ALL_MEDIA_EXTS = IMAGE_EXTS | VIDEO_EXTS | AUDIO_EXTS

# Maps extension → canonical MIME; used in type-mismatch detection
EXT_TO_MIME: Dict[str, str] = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".png": "image/png", ".gif": "image/gif",
    ".bmp": "image/bmp", ".webp": "image/webp",
    ".tiff": "image/tiff", ".tif": "image/tiff",
    ".mp4": "video/mp4", ".mkv": "video/x-matroska",
    ".avi": "video/x-msvideo", ".mov": "video/quicktime",
    ".wmv": "video/x-ms-wmv", ".flv": "video/x-flv",
    ".webm": "video/webm", ".m4v": "video/mp4",
    ".mp3": "audio/mpeg", ".flac": "audio/flac",
    ".wav": "audio/wav", ".ogg": "audio/ogg",
    ".m4a": "audio/mp4", ".aac": "audio/aac",
    ".wma": "audio/x-ms-wma", ".opus": "audio/ogg",
}

# Suspicious software strings in EXIF / tags
SUSPICIOUS_SOFTWARE = frozenset([
    "metasploit", "kali", "steghide", "outguess", "stegify",
    "stegano", "openstego", "invisible secrets", "camouflage",
])

# ── Helpers ───────────────────────────────────────────────────────────────────

def _media_type(ext: str) -> str:
    if ext in IMAGE_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    if ext in AUDIO_EXTS:
        return "audio"
    return "media"


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _ts_from_exif(val: Any) -> Optional[str]:
    """Convert an exifread IfdTag datetime string to ISO-8601."""
    try:
        s = str(val).strip()
        # EXIF format: "YYYY:MM:DD HH:MM:SS"
        dt = datetime.strptime(s, "%Y:%m:%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _flag(flags: list, key: str, label: str) -> None:
    if key not in flags:
        flags.append(key)


# ── File discovery ────────────────────────────────────────────────────────────

_SCAN_DIRS = [
    "/home", "/root", "/tmp", "/var/tmp",
    "/var/www", "/srv", "/opt", "/usr/share",
    "/media", "/mnt",
]
_MAX_FILES   = 500    # hard cap on media files examined
_MAX_READ_MB = 20     # max bytes read per file for analysis

def _discover_media(fs: FilesystemAccessor) -> List[Tuple[str, str]]:
    """Return list of (path, media_type) for media files found in common dirs."""
    found: list = []

    def _walk(directory: str, depth: int) -> None:
        if depth > 6 or len(found) >= _MAX_FILES:
            return
        entries = fs.list_dir(directory)
        for entry in entries:
            if len(found) >= _MAX_FILES:
                return
            if entry.startswith(".") and depth > 0:
                # skip hidden subdirs; still scan hidden files at top level
                continue
            full = f"{directory.rstrip('/')}/{entry}"
            ext = os.path.splitext(entry)[1].lower()
            if ext in ALL_MEDIA_EXTS:
                found.append((full, _media_type(ext)))
            elif "." not in entry:
                _walk(full, depth + 1)
            elif ext not in (".txt", ".log", ".conf", ".py", ".sh", ".pl", ".rb"):
                _walk(full, depth + 1)

    for d in _SCAN_DIRS:
        if fs.exists(d):
            _walk(d, 0)

    return found


# ── EXIF / metadata extraction ────────────────────────────────────────────────

_GPS_TAG = {
    "GPS GPSLatitude":  "lat",
    "GPS GPSLongitude": "lon",
    "GPS GPSLatitudeRef":  "lat_ref",
    "GPS GPSLongitudeRef": "lon_ref",
    "GPS GPSAltitude": "altitude",
    "GPS GPSDateStamp": "gps_date",
    "GPS GPSTimeStamp": "gps_time",
}


def _dms_to_decimal(dms_tag, ref: str) -> Optional[float]:
    """Convert a GPS DMS IfdTag to decimal degrees."""
    try:
        vals = dms_tag.values
        d = float(vals[0].num) / float(vals[0].den)
        m = float(vals[1].num) / float(vals[1].den)
        s = float(vals[2].num) / float(vals[2].den)
        dd = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            dd = -dd
        return round(dd, 6)
    except Exception:
        return None


def _extract_exif(raw_bytes: bytes) -> Dict[str, Any]:
    """Extract EXIF tags from image bytes using exifread."""
    result: Dict[str, Any] = {}
    if not (_HAS_EXIFREAD and raw_bytes):
        return result
    try:
        tags = _exifread.process_file(io.BytesIO(raw_bytes), details=False, stop_tag="EOF")
    except Exception:
        return result

    # Core fields
    field_map = {
        "Image Make":            "camera_make",
        "Image Model":           "camera_model",
        "EXIF DateTimeOriginal": "datetime_original",
        "EXIF DateTimeDigitized":"datetime_digitized",
        "Image DateTime":        "datetime_modified",
        "Image Software":        "software",
        "Image Artist":          "artist",
        "Image Copyright":       "copyright",
        "EXIF ExifImageWidth":   "width",
        "EXIF ExifImageLength":  "height",
        "EXIF Flash":            "flash",
        "EXIF FocalLength":      "focal_length",
        "EXIF ISOSpeedRatings":  "iso",
        "EXIF ExposureTime":     "exposure_time",
        "EXIF FNumber":          "fnumber",
        "EXIF LensModel":        "lens_model",
        "MakerNote SerialNumber":"serial_number",
        "EXIF BodySerialNumber": "body_serial",
    }
    for tag_name, key in field_map.items():
        if tag_name in tags:
            result[key] = str(tags[tag_name])

    # Convert datetime strings
    for k in ("datetime_original", "datetime_digitized", "datetime_modified"):
        if k in result:
            ts = _ts_from_exif(result[k])
            if ts:
                result[k] = ts

    # GPS
    gps_raw: Dict[str, Any] = {}
    for tag_name, key in _GPS_TAG.items():
        if tag_name in tags:
            gps_raw[key] = tags[tag_name]

    if "lat" in gps_raw and "lon" in gps_raw:
        lat = _dms_to_decimal(gps_raw["lat"], str(gps_raw.get("lat_ref", "N")))
        lon = _dms_to_decimal(gps_raw["lon"], str(gps_raw.get("lon_ref", "E")))
        if lat is not None and lon is not None:
            result["gps_lat"] = lat
            result["gps_lon"] = lon
            # Build a Google Maps link (purely for display)
            result["gps_maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"
    if "altitude" in gps_raw:
        try:
            alt_tag = gps_raw["altitude"]
            result["gps_alt_m"] = round(
                float(alt_tag.values[0].num) / float(alt_tag.values[0].den), 1
            )
        except Exception:
            pass

    return result


def _extract_pil_info(raw_bytes: bytes) -> Dict[str, Any]:
    """Extract info Pillow can read that exifread might miss (dimensions, mode, etc.)."""
    if not (_HAS_PIL and raw_bytes):
        return {}
    try:
        img = _PILImage.open(io.BytesIO(raw_bytes))
        info: Dict[str, Any] = {
            "width_px":  img.width,
            "height_px": img.height,
            "mode":      img.mode,
            "format":    img.format,
        }
        # Embedded thumbnail extraction (JFIF APP0 / EXIF thumbnail)
        try:
            if hasattr(img, "_getexif") and callable(img._getexif):
                raw_exif = img._getexif()
                if raw_exif and 0x0201 in raw_exif:   # JPEGInterchangeFormat
                    info["has_embedded_thumbnail"] = True
            elif hasattr(img, "thumbnail"):
                info["has_embedded_thumbnail"] = True
        except Exception:
            pass
        return info
    except Exception:
        return {}


# ── Steganography indicator detection ─────────────────────────────────────────

# Appended archive magic bytes (after normal image EOF)
_APPENDED_SIGS = [
    (b"PK\x03\x04",     "ZIP archive"),
    (b"\x1f\x8b\x08",   "GZIP archive"),
    (b"Rar!",           "RAR archive"),
    (b"7z\xbc\xaf",     "7-Zip archive"),
    (b"\x7fELF",        "ELF executable"),
    (b"MZ",             "DOS/PE executable"),
    (b"%PDF",           "PDF document"),
]
_JPEG_EOF    = b"\xff\xd9"
_PNG_EOF     = b"IEND\xaeB`\x82"


def _detect_appended_data(raw_bytes: bytes, ext: str) -> Optional[str]:
    """Check if foreign data is appended after the image's logical end."""
    eof_marker: Optional[bytes] = None
    if ext in (".jpg", ".jpeg"):
        eof_marker = _JPEG_EOF
    elif ext == ".png":
        eof_marker = _PNG_EOF

    if not eof_marker:
        return None

    pos = raw_bytes.rfind(eof_marker)
    if pos == -1:
        return None

    trailer = raw_bytes[pos + len(eof_marker):]
    if len(trailer) < 4:
        return None

    for sig, label in _APPENDED_SIGS:
        if trailer.lstrip(b"\x00").startswith(sig):
            return f"Appended {label} after image EOF ({len(trailer)} bytes)"

    # More than 128 bytes of non-null data after EOF is suspicious
    non_null = sum(1 for b in trailer if b != 0)
    if non_null > 128:
        return f"Suspicious data ({non_null} non-null bytes) appended after image EOF"
    return None


def _check_jpeg_size_anomaly(raw_bytes: bytes, reported_dimensions: Tuple[int, int]) -> Optional[str]:
    """A JPEG image with very high entropy but very small dimensions may contain hidden data."""
    if not reported_dimensions[0] or not reported_dimensions[1]:
        return None
    # Expected uncompressed size (rough lower bound)
    expected_min = (reported_dimensions[0] * reported_dimensions[1] * 3) // 100
    if len(raw_bytes) > expected_min * 20:
        return (
            f"File size ({_fmt_size(len(raw_bytes))}) is unusually large "
            f"for {reported_dimensions[0]}×{reported_dimensions[1]} resolution — "
            f"possible hidden payload"
        )
    return None


def _lsb_entropy_check(raw_bytes: bytes) -> Tuple[float, Optional[str]]:
    """Calculate overall byte entropy and flag high values (>7.2) for images."""
    entropy = _shannon_entropy(raw_bytes[:128 * 1024])   # sample first 128KB
    msg = None
    if entropy > 7.5:
        msg = (
            f"Very high entropy ({entropy:.2f}/8.0) — data may be encrypted "
            f"or contain a hidden steganographic payload"
        )
    elif entropy > 7.2:
        msg = f"Elevated entropy ({entropy:.2f}/8.0) — possible steganography or compression anomaly"
    return entropy, msg


def _lsb_plane_entropy(data: bytes, max_samples: int = 200_000) -> Tuple[float, float]:
    """Return (entropy_bits, p_one) for the least-significant-bit plane.

    This is a coarse heuristic: many steganography tools randomise the LSB
    plane, driving its entropy close to 1.0 bit with a near 50/50 split of
    0/1 values. We compute:
      - p_one: proportion of 1 bits in the sampled LSBs
      - entropy_bits: Shannon entropy of the Bernoulli(p_one) distribution
    """
    if not data:
        return 0.0, 0.0
    sample = data[:max_samples]
    n = len(sample)
    ones = sum(b & 1 for b in sample)
    p_one = ones / n
    p_zero = 1.0 - p_one
    entropy = 0.0
    if 0.0 < p_one < 1.0:
        entropy -= p_one * math.log2(p_one)
    if 0.0 < p_zero < 1.0:
        entropy -= p_zero * math.log2(p_zero)
    return entropy, p_one


def _lsb_stego_indicator(raw_bytes: bytes, ext: str) -> Optional[str]:
    """Heuristic LSB-plane steganography indicator for common raster formats.

    Uses the LSB plane entropy and bias; flags highly random, near 50/50
    LSB distributions that are often produced by LSB embedding schemes.
    """
    if ext not in (".jpg", ".jpeg", ".png", ".bmp"):
        return None
    if len(raw_bytes) < 10_000:
        return None

    # Prefer decoded pixel bytes when Pillow is available; fall back to the
    # container bytes otherwise (still a useful signal for many images).
    data: bytes
    if _HAS_PIL:
        try:
            img = _PILImage.open(io.BytesIO(raw_bytes))
            data = img.tobytes()
        except Exception:
            data = raw_bytes
    else:
        data = raw_bytes

    if len(data) < 10_000:
        return None

    ent, p_one = _lsb_plane_entropy(data)
    # Store into metadata at the call-site; here we only decide on flags.
    # Only flag when both entropy is high and the balance is close to 50/50.
    if ent >= 0.97 and 0.45 <= p_one <= 0.55:
        return (
            f"LSB plane looks randomly distributed (entropy {ent:.3f} bits, "
            f"p(1)={p_one:.3f}) — possible LSB steganography"
        )
    if ent >= 0.9 and 0.40 <= p_one <= 0.60:
        return (
            f"Elevated LSB-plane entropy (entropy {ent:.3f} bits, p(1)={p_one:.3f}) "
            f"— potential steganographic modification"
        )
    return None


# ── File integrity / tampering detection ─────────────────────────────────────

def _check_timestamp_mismatch(
    exif_datetime: Optional[str],
    fs_mtime: Optional[float],
    path: str,
) -> Optional[str]:
    """Compare EXIF DateTimeOriginal to filesystem mtime."""
    if not exif_datetime or not fs_mtime:
        return None
    try:
        exif_dt = datetime.strptime(exif_datetime, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        fs_dt   = datetime.fromtimestamp(fs_mtime, tz=timezone.utc)
        diff_h  = abs((fs_dt - exif_dt).total_seconds()) / 3600.0
        if diff_h > 72:
            return (
                f"Timestamp mismatch: EXIF says {exif_datetime}, "
                f"filesystem mtime is {fs_dt.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"(difference: {diff_h:.0f} hours) — possible file tampering"
            )
    except Exception:
        pass
    return None


# ── Video metadata extraction via ffprobe ────────────────────────────────────

def _ffprobe_metadata(local_path: str) -> Dict[str, Any]:
    """Run ffprobe on a local file and parse JSON output."""
    if not _HAS_FFPROBE:
        return {}
    try:
        result = subprocess.run(
            [
                "ffprobe", "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                local_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {}
        data = json.loads(result.stdout)
    except Exception:
        return {}

    out: Dict[str, Any] = {}
    fmt = data.get("format", {})
    tags = fmt.get("tags", {})

    # Normalise tag keys to lowercase
    tags = {k.lower(): v for k, v in tags.items()}

    out["container"]      = fmt.get("format_long_name") or fmt.get("format_name")
    out["duration_s"]     = float(fmt.get("duration", 0)) or None
    out["size_bytes"]     = int(fmt.get("size", 0)) or None
    out["bit_rate"]       = int(fmt.get("bit_rate", 0)) or None
    out["creation_time"]  = tags.get("creation_time") or tags.get("date")
    out["encoder"]        = tags.get("encoder") or tags.get("software") or tags.get("encoded_by")
    out["comment"]        = tags.get("comment")
    out["title"]          = tags.get("title")
    out["artist"]         = tags.get("artist") or tags.get("author")
    out["location"]       = tags.get("location") or tags.get("com.apple.quicktime.location.iso6709")

    # Parse ISO 6709 location string (±DD.DDDD±DDD.DDDD+EEE/)
    if out["location"]:
        try:
            m = re.match(r"([+-]\d+\.\d+)([+-]\d+\.\d+)", out["location"])
            if m:
                out["gps_lat"] = float(m.group(1))
                out["gps_lon"] = float(m.group(2))
                out["gps_maps_url"] = f"https://www.google.com/maps?q={out['gps_lat']},{out['gps_lon']}"
        except Exception:
            pass

    # Streams
    streams = []
    for s in data.get("streams", [])[:10]:
        stream_tags = {k.lower(): v for k, v in s.get("tags", {}).items()}
        st: Dict[str, Any] = {
            "index":     s.get("index"),
            "type":      s.get("codec_type"),
            "codec":     s.get("codec_long_name") or s.get("codec_name"),
            "language":  stream_tags.get("language"),
        }
        if s.get("codec_type") == "video":
            st.update({
                "width":  s.get("width"),
                "height": s.get("height"),
                "fps":    s.get("r_frame_rate"),
            })
        elif s.get("codec_type") == "audio":
            st.update({
                "sample_rate":  s.get("sample_rate"),
                "channels":     s.get("channels"),
                "channel_layout": s.get("channel_layout"),
            })
        streams.append(st)
    if streams:
        out["streams"] = streams

    # Remove None values
    return {k: v for k, v in out.items() if v is not None}


# ── Audio metadata extraction via mutagen ────────────────────────────────────

_MUTAGEN_TAG_MAP = {
    "TIT2": "title",    "TPE1": "artist",   "TALB": "album",
    "TDRC": "date",     "TENC": "encoder",  "TMED": "media_type",
    "TSSE": "encoder",  "COMM": "comment",  "TCOP": "copyright",
    "TOFN": "original_filename",
}


def _mutagen_metadata(raw_bytes: bytes, ext: str) -> Dict[str, Any]:
    """Extract audio tag metadata from raw bytes via mutagen."""
    if not (_HAS_MUTAGEN and raw_bytes):
        return {}
    try:
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
            tf.write(raw_bytes)
            tmp = tf.name
        try:
            import mutagen
            f = mutagen.File(tmp, easy=False)
            if f is None:
                return {}
            info: Dict[str, Any] = {}
            # Try easy tags first (ogg, flac, mp4)
            try:
                import mutagen.easyid3
                easy = mutagen.File(tmp, easy=True)
                if easy:
                    for k, v in easy.items():
                        info[k] = v[0] if isinstance(v, list) and v else str(v)
            except Exception:
                pass
            # ID3 frames (mp3)
            for frame_id, key in _MUTAGEN_TAG_MAP.items():
                if hasattr(f, "tags") and f.tags and frame_id in f.tags:
                    info[key] = str(f.tags[frame_id])
            # Duration / bitrate from audio info
            if hasattr(f, "info"):
                ai = f.info
                if hasattr(ai, "length"):   info["duration_s"] = round(float(ai.length), 2)
                if hasattr(ai, "bitrate"):  info["bitrate_kbps"] = int(ai.bitrate) // 1000
                if hasattr(ai, "channels"): info["channels"] = ai.channels
                if hasattr(ai, "sample_rate"): info["sample_rate"] = ai.sample_rate
            return {k: v for k, v in info.items() if v not in (None, "", [])}
        finally:
            os.unlink(tmp)
    except Exception:
        return {}


# ── MIME type detection ───────────────────────────────────────────────────────

def _detect_mime(raw_bytes: bytes) -> Optional[str]:
    if not (_HAS_MAGIC and raw_bytes):
        return None
    try:
        return _magic.from_buffer(raw_bytes[:4096], mime=True)
    except Exception:
        return None


# ── Per-file analysis ─────────────────────────────────────────────────────────

def _analyse_file(
    fs: FilesystemAccessor,
    path: str,
    media_type: str,
) -> Optional[Dict[str, Any]]:
    ext = os.path.splitext(path)[1].lower()
    max_read = _MAX_READ_MB * 1024 * 1024
    raw = fs.read_file(path, max_bytes=max_read)
    if not raw or len(raw) < 4:
        return None

    name = os.path.basename(path)
    findings: List[str] = []     # human-readable issue descriptions
    flags: List[str] = []        # machine tags

    # ── Filesystem mtime ──────────────────────────────────────────────────────
    fs_mtime: Optional[float] = None
    if fs.mode == "local":
        try:
            fs_mtime = os.path.getmtime(
                fs.path.rstrip("/") + "/" + path.lstrip("/")
            )
        except Exception:
            pass

    result: Dict[str, Any] = {
        "path":       path,
        "name":       name,
        "media_type": media_type,
        "ext":        ext,
        "size":       len(raw),
        "severity":   "info",
        "flags":      [],
        "findings":   [],
        "metadata":   {},
        "streams":    [],
        "gps":        {},
        "thumbnail":  None,
    }

    # ── MIME / type mismatch ──────────────────────────────────────────────────
    real_mime = _detect_mime(raw)
    declared_mime = EXT_TO_MIME.get(ext)
    if real_mime and declared_mime:
        if not real_mime.startswith(declared_mime.split("/")[0]) and real_mime != declared_mime:
            findings.append(
                f"File-type mismatch: extension is {ext!r} but actual MIME is {real_mime!r}"
            )
            _flag(flags, "type-mismatch", "")
            result["severity"] = "high"
    if real_mime:
        result["metadata"]["mime_detected"] = real_mime

    # ── Image analysis ────────────────────────────────────────────────────────
    if media_type == "image":
        # EXIF
        exif = _extract_exif(raw)
        pil_info = _extract_pil_info(raw)
        result["metadata"].update(exif)
        result["metadata"].update(pil_info)

        # GPS present?
        if "gps_lat" in exif and "gps_lon" in exif:
            result["gps"] = {
                "lat":      exif["gps_lat"],
                "lon":      exif["gps_lon"],
                "maps_url": exif.get("gps_maps_url", ""),
                "alt_m":    exif.get("gps_alt_m"),
            }
            _flag(flags, "gps-location", "")
            findings.append(
                f"GPS coordinates embedded: {exif['gps_lat']}, {exif['gps_lon']}"
            )
            result["severity"] = _max_sev(result["severity"], "medium")

        # Suspicious software
        sw = exif.get("software", "").lower()
        for sus in SUSPICIOUS_SOFTWARE:
            if sus in sw:
                findings.append(f"Suspicious software tag: {exif['software']!r}")
                _flag(flags, "suspicious-software", "")
                result["severity"] = "high"
                break

        # Timestamp mismatch
        mm = _check_timestamp_mismatch(
            exif.get("datetime_original"),
            fs_mtime,
            path,
        )
        if mm:
            findings.append(mm)
            _flag(flags, "timestamp-mismatch", "")
            result["severity"] = _max_sev(result["severity"], "medium")

        # Steganography indicators
        entropy, entropy_msg = _lsb_entropy_check(raw)
        result["metadata"]["entropy"] = round(entropy, 3)
        if entropy_msg:
            findings.append(entropy_msg)
            _flag(flags, "high-entropy", "")
            result["severity"] = _max_sev(result["severity"], "medium")

        # LSB-plane steganography heuristics (on decoded pixels when possible)
        # Also capture quantitative metrics for UI display.
        if _HAS_PIL:
            try:
                _img = _PILImage.open(io.BytesIO(raw))
                pixel_bytes = _img.tobytes()
            except Exception:
                pixel_bytes = raw
        else:
            pixel_bytes = raw

        if len(pixel_bytes) >= 10_000:
            lsb_entropy, lsb_p_one = _lsb_plane_entropy(pixel_bytes)
            result["metadata"]["lsb_entropy_bits"] = round(lsb_entropy, 4)
            result["metadata"]["lsb_p_one"] = round(lsb_p_one, 4)

        lsb_msg = _lsb_stego_indicator(raw, ext)
        if lsb_msg:
            findings.append(lsb_msg)
            _flag(flags, "lsb-stego-suspected", "")
            result["severity"] = _max_sev(result["severity"], "medium")

        appended = _detect_appended_data(raw, ext)
        if appended:
            findings.append(appended)
            _flag(flags, "appended-data", "")
            result["severity"] = "high"

        w = exif.get("width_px") or pil_info.get("width_px") or 0
        h = exif.get("height_px") or pil_info.get("height_px") or 0
        if w and h and ext in (".jpg", ".jpeg"):
            size_anom = _check_jpeg_size_anomaly(raw, (w, h))
            if size_anom:
                findings.append(size_anom)
                _flag(flags, "size-anomaly", "")
                result["severity"] = _max_sev(result["severity"], "medium")

        # Embedded thumbnail extraction
        result["thumbnail"] = _extract_thumbnail(raw, ext)
        if pil_info.get("has_embedded_thumbnail"):
            _flag(flags, "has-thumbnail", "")

    # ── Video analysis ────────────────────────────────────────────────────────
    elif media_type == "video":
        if fs.mode == "local":
            local_path = fs.path.rstrip("/") + "/" + path.lstrip("/")
            vmd = _ffprobe_metadata(local_path)
        else:
            # Write to temp file for ffprobe
            try:
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                    tf.write(raw)
                    tmp = tf.name
                vmd = _ffprobe_metadata(tmp)
                os.unlink(tmp)
            except Exception:
                vmd = {}

        result["metadata"].update({k: v for k, v in vmd.items() if k != "streams"})
        result["streams"] = vmd.get("streams", [])

        if vmd.get("gps_lat") is not None:
            result["gps"] = {
                "lat":      vmd["gps_lat"],
                "lon":      vmd["gps_lon"],
                "maps_url": vmd.get("gps_maps_url", ""),
            }
            _flag(flags, "gps-location", "")
            findings.append(
                f"GPS coordinates in video: {vmd['gps_lat']}, {vmd['gps_lon']}"
            )
            result["severity"] = _max_sev(result["severity"], "medium")

        encoder = vmd.get("encoder", "").lower()
        for sus in SUSPICIOUS_SOFTWARE:
            if sus in encoder:
                findings.append(f"Suspicious encoder: {vmd['encoder']!r}")
                _flag(flags, "suspicious-software", "")
                result["severity"] = "high"
                break

        mismatch = _check_timestamp_mismatch(vmd.get("creation_time"), fs_mtime, path)
        if mismatch:
            findings.append(mismatch)
            _flag(flags, "timestamp-mismatch", "")
            result["severity"] = _max_sev(result["severity"], "medium")

    # ── Audio analysis ────────────────────────────────────────────────────────
    elif media_type == "audio":
        amd = _mutagen_metadata(raw, ext)
        result["metadata"].update(amd)

        enc = amd.get("encoder", "").lower()
        for sus in SUSPICIOUS_SOFTWARE:
            if sus in enc:
                findings.append(f"Suspicious encoder tag: {amd['encoder']!r}")
                _flag(flags, "suspicious-software", "")
                result["severity"] = "high"
                break

    # ── Screenshot detection heuristic ───────────────────────────────────────
    if media_type == "image":
        w = result["metadata"].get("width_px", 0)
        h = result["metadata"].get("height_px", 0)
        sw = result["metadata"].get("software", "").lower()
        is_screenshot_sw = any(x in sw for x in ("screenshot", "snipping", "gnome-screenshot", "scrot", "flameshot"))
        is_screenshot_dims = (w and h) and (
            # Common screen aspect ratios at standard resolutions
            (w >= 1280 and h >= 720 and abs(w / h - 16 / 9) < 0.05) or
            (w >= 1280 and h >= 800 and abs(w / h - 16 / 10) < 0.05) or
            (w == 1920 and h == 1080) or (w == 2560 and h == 1440) or
            (w == 3840 and h == 2160)
        )
        if is_screenshot_sw or is_screenshot_dims:
            findings.append(
                "Possible screenshot: "
                + (f"software={result['metadata']['software']!r}" if is_screenshot_sw
                   else f"resolution {w}×{h} matches common screen dimensions")
            )
            _flag(flags, "screenshot", "")
            result["severity"] = _max_sev(result["severity"], "medium")

    result["flags"]    = flags
    result["findings"] = findings
    if findings and result["severity"] == "info":
        result["severity"] = "medium"
    return result


def _max_sev(a: str, b: str) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return a if order.get(a, 0) >= order.get(b, 0) else b


# ── Thumbnail extraction ──────────────────────────────────────────────────────

def _extract_thumbnail(raw_bytes: bytes, ext: str) -> Optional[Dict[str, Any]]:
    """Extract the embedded thumbnail from a JPEG/TIFF as a base64 data URI."""
    if not (_HAS_PIL and raw_bytes and ext in (".jpg", ".jpeg", ".tiff", ".tif", ".heic")):
        return None
    try:
        import base64
        img = _PILImage.open(io.BytesIO(raw_bytes))
        if not hasattr(img, "_getexif") or not callable(img._getexif):
            return None
        raw_exif = img._getexif()
        if not raw_exif:
            return None
        # 0x0201 = JPEGInterchangeFormat (thumbnail offset)
        # 0x0202 = JPEGInterchangeFormatLength
        tn_offset = raw_exif.get(0x0201)
        tn_length = raw_exif.get(0x0202)
        if tn_offset and tn_length:
            tn_bytes = raw_bytes[tn_offset: tn_offset + tn_length]
            if tn_bytes[:3] == b"\xff\xd8\xff":
                b64 = base64.b64encode(tn_bytes).decode()
                tn_img = _PILImage.open(io.BytesIO(tn_bytes))
                return {
                    "data_uri": f"data:image/jpeg;base64,{b64}",
                    "width":    tn_img.width,
                    "height":   tn_img.height,
                }
    except Exception:
        pass
    return None


# ── Public entry point ────────────────────────────────────────────────────────

def analyze_multimedia(fs: FilesystemAccessor) -> List[Dict[str, Any]]:
    """Discover and forensically analyse all media files on the filesystem.

    Returns a list of per-file analysis dicts compatible with the
    MediaFinding Pydantic model.
    """
    media_files = _discover_media(fs)
    results: list = []
    for path, media_type in media_files:
        try:
            r = _analyse_file(fs, path, media_type)
            if r:
                results.append(r)
        except Exception:
            pass
    return results
