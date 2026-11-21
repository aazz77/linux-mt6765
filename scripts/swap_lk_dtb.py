#!/usr/bin/env python3
"""Swap the DTB embedded inside the MTK LK partition image (lk.img).

The stock LK of the TB-X606F carries the base device tree inside its image
(found by scanning for the FDT magic `d00dfeed`).  LK merges the dtbo
partition overlay onto it at boot and passes the result to the kernel.

To boot a mainline kernel, replace that embedded DTB with the mainline one
(e.g. mt6765-x606f.dtb).  The replacement DTB must not be larger than the
original (101747 bytes); the tail is padded with 0xFF.

Usage:
  python swap_lk_dtb.py lk.img mt6765-x606f.dtb -o lk-mainline.img
  python swap_lk_dtb.py --info lk.img
"""
import argparse
import struct
import sys

FDT_MAGIC = bytes.fromhex("d00dfeed")
DTB_MIN = 1024
DTB_MAX = 0x400000


def find_dtbs(lk):
    hits = []
    off = 0
    while True:
        i = lk.find(FDT_MAGIC, off)
        if i < 0:
            break
        tot = struct.unpack(">I", lk[i + 4:i + 8])[0]
        if DTB_MIN <= tot <= DTB_MAX:
            hits.append((i, tot))
        off = i + 1
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lk", nargs="?")
    ap.add_argument("dtb", nargs="?")
    ap.add_argument("-o", "--output")
    ap.add_argument("--info", action="store_true")
    a = ap.parse_args()

    lk = open(a.lk, "rb").read()
    hits = find_dtbs(lk)
    print(f"DTB candidates in {a.lk}: {[(hex(o), s) for o, s in hits]}")
    if a.info:
        return
    if len(hits) != 1:
        sys.exit(f"expected exactly 1 embedded DTB, found {len(hits)}; aborting")

    off, size = hits[0]
    dtb = open(a.dtb, "rb").read()
    if len(dtb) > size:
        sys.exit(f"new DTB ({len(dtb)} bytes) larger than slot ({size} bytes)")

    out = bytearray(lk)
    out[off:off + size] = dtb + b"\xff" * (size - len(dtb))
    with open(a.output, "wb") as f:
        f.write(out)
    print(f"wrote {a.output}: DTB at {off:#x}, {len(dtb)} bytes "
          f"(slot {size} bytes, padded {size - len(dtb)})")


if __name__ == "__main__":
    sys.exit(main())
