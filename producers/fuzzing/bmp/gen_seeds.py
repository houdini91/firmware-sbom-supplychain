#!/usr/bin/env python3
"""
gen_seeds.py — emit tiny, valid-ish BMP seeds for the TranslateBmpToGopBlt fuzzer.

Every seed is crafted to pass ALL of the target's up-front validation so the
fuzzer starts from inputs that actually reach the pixel-translation loop (the
interesting code). libFuzzer then mutates from here.

The BMP_IMAGE_HEADER the target expects (packed, 54 bytes) is:

  off  size  field
    0   1    CharB            'B'
    1   1    CharM            'M'
    2   4    Size             total file size (== BmpImageSize)
    6   4    Reserved[2]      0
   10   4    ImageOffset      offset to pixel data
   14   4    HeaderSize       MUST be 54 - 14 = 40
   18   4    PixelWidth
   22   4    PixelHeight
   26   2    Planes           1
   28   2    BitPerPixel      1/4/8/24/32
   30   4    CompressionType  MUST be 0
   34   4    ImageSize        (informational; not validated)
   38   4    XPixelsPerMeter  0
   42   4    YPixelsPerMeter  0
   46   4    NumberOfColors   0
   50   4    ImportantColors  0

Target invariants we satisfy:
  * HeaderSize == 40
  * CompressionType == 0
  * PixelWidth != 0 and PixelHeight != 0
  * DataSizePerLine = ((PixelWidth*BitPerPixel + 31) >> 3) & ~3   (row, 4-byte aligned)
  * DataSize        = DataSizePerLine * PixelHeight
  * Size            == ImageOffset + DataSize   (and Size == total bytes)
  * ImageOffset >= 54; for indexed modes ImageOffset-54 >= 4*ColorMapNum
"""

import struct
import os

HDR = 54  # sizeof(BMP_IMAGE_HEADER), packed

def row_bytes(width, bpp):
    # exact replica of the target's DataSizePerLine computation
    return ((width * bpp + 31) >> 3) & ~0x3

def build_bmp(width, height, bpp, colormap_entries=0):
    row = row_bytes(width, bpp)
    data_size = row * height

    colormap_bytes = 4 * colormap_entries          # BMP_COLOR_MAP is 4 bytes
    image_offset = HDR + colormap_bytes
    total = image_offset + data_size

    hdr = struct.pack(
        "<2cIHHIIIIHHIIIIII",
        b'B', b'M',
        total,            # Size
        0, 0,             # Reserved[2]
        image_offset,     # ImageOffset
        HDR - 14,         # HeaderSize == 40
        width,            # PixelWidth
        height,           # PixelHeight
        1,                # Planes
        bpp,              # BitPerPixel
        0,                # CompressionType
        data_size,        # ImageSize (informational)
        0, 0,             # X/Y PixelsPerMeter
        colormap_entries, # NumberOfColors
        0,                # ImportantColors
    )
    assert len(hdr) == HDR, f"header is {len(hdr)} bytes, expected {HDR}"

    body = bytearray()
    body += hdr
    # color map (grayscale ramp so it is deterministic and valid)
    for i in range(colormap_entries):
        v = (i * 255 // max(1, colormap_entries - 1)) & 0xFF
        body += bytes((v, v, v, 0))  # Blue, Green, Red, Reserved
    # pixel data (fill with a simple pattern; padding bytes left as zero)
    pix = bytearray(data_size)
    for i in range(len(pix)):
        pix[i] = (i * 37) & 0xFF
    body += pix

    assert len(body) == total, f"body {len(body)} != declared Size {total}"
    return bytes(body)

def main():
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")
    os.makedirs(out_dir, exist_ok=True)

    seeds = {
        # smallest well-formed 24-bpp truecolor image
        "seed_1x1_24bpp.bmp": build_bmp(1, 1, 24),
        # 2x2 24-bpp: exercises row padding + the height flip indexing
        "seed_2x2_24bpp.bmp": build_bmp(2, 2, 24),
        # 4x4 8-bpp palette: exercises the BmpColorMap[] indexing path,
        # which is the most interesting out-of-bounds-read surface
        "seed_4x4_8bpp.bmp": build_bmp(4, 4, 8, colormap_entries=256),
    }

    for name, blob in seeds.items():
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(blob)
        print(f"wrote {path} ({len(blob)} bytes)")

if __name__ == "__main__":
    main()
