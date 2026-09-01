"""
Generate the full Aura Decomp Tool icon set from scratch (pure Python, no deps).

Produces (in src-tauri/icons/):
  icon.png          512x512
  128x128.png       128x128
  32x32.png         32x32
  128x128@2x.png    256x256
  icon.ico          multi-size Windows ICO (256..16, 32-bit DIB/BMP entries)
  icon.icns         macOS ICNS (512 / 256 / 128 PNG entries)

Design: rounded-square with an indigo -> violet diagonal gradient and a white
"A" monogram, rendered with signed-distance-field anti-aliasing.
"""

import math
import struct
import zlib


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    out = struct.pack(">I", len(data)) + tag + data
    return out + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def write_png(width: int, height: int, rgba: bytes) -> bytes:
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)
        raw += rgba[y * stride:(y + 1) * stride]
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _png_chunk(b"IEND", b"")
    )


def sd_round_rect(px, py, cx, cy, hw, hh, r):
    dx = abs(px - cx) - (hw - r)
    dy = abs(py - cy) - (hh - r)
    ox, oy = max(dx, 0.0), max(dy, 0.0)
    return math.hypot(ox, oy) + min(max(dx, dy), 0.0) - r


def sd_segment(px, py, ax, ay, bx, by):
    abx, aby = bx - ax, by - ay
    t = ((px - ax) * abx + (py - ay) * aby) / (abx * abx + aby * aby)
    t = max(0.0, min(1.0, t))
    return math.hypot(px - (ax + abx * t), py - (ay + aby * t))


def clamp01(v):
    return 0.0 if v < 0.0 else (1.0 if v > 1.0 else v)
# "A" monogram as line segments in normalized [0..1] coordinates (y down).
A_SEGMENTS = [
    (0.50, 0.24, 0.28, 0.80),  # left leg
    (0.50, 0.24, 0.72, 0.80),  # right leg
    (0.345, 0.62, 0.655, 0.62),  # crossbar
]
A_THICKNESS = 0.105

GRAD = [(0.62, 0.35, 0.88), (0.55, 0.35, 0.95)]  # indigo -> violet


def render(size: int, aa: int = 2) -> bytes:
    N = size * aa
    rgba = bytearray(N * N * 4)
    cxc = cyc = 0.5
    hw = hh = 0.5 - 0.035
    radius = 0.22
    for j in range(N):
        py = (j + 0.5) / N
        for i in range(N):
            px = (i + 0.5) / N
            d = sd_round_rect(px, py, cxc, cyc, hw, hh, radius) * N
            cov = clamp01(0.5 - d)
            if cov <= 0.0:
                continue
            t = clamp01((px + py) / 1.6)
            cr = GRAD[0][0] + (GRAD[1][0] - GRAD[0][0]) * t
            cg = GRAD[0][1] + (GRAD[1][1] - GRAD[0][1]) * t
            cb = GRAD[0][2] + (GRAD[1][2] - GRAD[0][2]) * t
            d_letter = min(sd_segment(px, py, *s) for s in A_SEGMENTS)
            letter = clamp01((A_THICKNESS / 2.0) * N - d_letter * N)
            r = cr + (1.0 - cr) * letter
            g = cg + (1.0 - cg) * letter
            b = cb + (1.0 - cb) * letter
            idx = (j * N + i) * 4
            rgba[idx] = int(round(r * 255 * cov))
            rgba[idx + 1] = int(round(g * 255 * cov))
            rgba[idx + 2] = int(round(b * 255 * cov))
            rgba[idx + 3] = int(round(cov * 255))
    return _box_downsample(bytes(rgba), N, size)


def _box_downsample(rgba: bytes, src: int, dst: int) -> bytes:
    if src == dst:
        return rgba
    out = bytearray(dst * dst * 4)
    step = src / dst
    for j in range(dst):
        y0 = int(j * step)
        y1 = max(y0 + 1, int((j + 1) * step))
        for i in range(dst):
            x0 = int(i * step)
            x1 = max(x0 + 1, int((i + 1) * step))
            r = g = b = a = 0
            n = 0
            for yy in range(y0, min(y1, src)):
                row = yy * src * 4
                for xx in range(x0, min(x1, src)):
                    o = row + xx * 4
                    r += rgba[o]
                    g += rgba[o + 1]
                    b += rgba[o + 2]
                    a += rgba[o + 3]
                    n += 1
            if n:
                o = (j * dst + i) * 4
                out[o] = r // n
                out[o + 1] = g // n
                out[o + 2] = b // n
                out[o + 3] = a // n
    return bytes(out)

def _dib_ico_entry(size: int, rgba: bytes) -> bytes:
    """Build one 32-bit BGRA DIB (BITMAPINFOHEADER) + AND-mask for an .ico entry.

    rc.exe rejects PNG-compressed icon entries ('RC2176: old DIB'), so the .ico
    must use classic uncompressed DIB data instead of embedded PNGs.
    """
    header = struct.pack(
        "<IiiHHIIiiII",
        40,       # biSize: BITMAPINFOHEADER
        size,     # biWidth
        size * 2, # biHeight: XOR image + AND mask
        1,        # biPlanes
        32,       # biBitCount
        0,        # biCompression: BI_RGB
        0,        # biSizeImage (0 is fine for BI_RGB)
        0, 0,     # biXPelsPerMeter, biYPelsPerMeter
        0, 0,     # biClrUsed, biClrImportant
    )
    # RGBA -> BGRA, bottom-up scanlines.
    bgra = bytearray(size * size * 4)
    for y in range(size):
        src = y * size * 4
        dst = (size - 1 - y) * size * 4
        for x in range(size):
            o = src + x * 4
            d = dst + x * 4
            bgra[d] = rgba[o + 2]
            bgra[d + 1] = rgba[o + 1]
            bgra[d + 2] = rgba[o]
            bgra[d + 3] = rgba[o + 3]
    # AND mask: 1bpp, rows padded to 4 bytes, all zeros (alpha channel drives
    # transparency on modern Windows).
    row_bytes = ((size + 31) // 32) * 4
    and_mask = b"\x00" * (row_bytes * size)
    return header + bytes(bgra) + and_mask


def write_ico(sizes_entries):
    """sizes_entries: list of (size, rgba_bytes) -> rc.exe-compatible .ico."""
    header = struct.pack("<HHH", 0, 1, len(sizes_entries))
    dir_entries = b""
    payload = b""
    offset = 6 + 16 * len(sizes_entries)
    for size, rgba in sizes_entries:
        dib = _dib_ico_entry(size, rgba)
        dim = size if size < 256 else 0  # 256 is stored as 0 in the dir entry
        dir_entries += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(dib), offset
        )
        payload += dib
        offset += len(dib)
    return header + dir_entries + payload


def write_icns(entries):
    body = b"".join(
        tag + struct.pack(">I", len(png) + 8) + png for tag, png in entries
    )
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def main():
    import os

    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "icons"))
    os.makedirs(out_dir, exist_ok=True)

    png512 = render(512)
    png256 = _box_downsample(png512, 512, 256)
    png128 = _box_downsample(png512, 512, 128)
    png032 = _box_downsample(png512, 512, 32)

    files = {
        "icon.png": write_png(512, 512, png512),
        "128x128.png": write_png(128, 128, png128),
        "32x32.png": write_png(32, 32, png032),
        "128x128@2x.png": write_png(256, 256, png256),
        "icon.ico": write_ico(
            [
                (256, png256),
                (128, png128),
                (48, _box_downsample(png512, 512, 48)),
                (32, png032),
                (16, _box_downsample(png512, 512, 16)),
            ]
        ),
        "icon.icns": write_icns(
            [(b"ic09", png512), (b"ic08", png256), (b"ic07", png128)]
        ),
    }
    for name, data in files.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
        print(f"wrote {name}: {len(data)} bytes")


if __name__ == "__main__":
    main()