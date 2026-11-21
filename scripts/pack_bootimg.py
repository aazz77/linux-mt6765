#!/usr/bin/env python3
"""Pack an Android boot image (header v2) for the Lenovo TB-X606F (MT8768/MT6765).

Header parameters are taken from the stock boot.img so that LK accepts it:
  page_size        2048
  kernel_addr      0x40080000
  ramdisk_addr     0x51b00000
  second_addr      0x40f00000
  tags_addr        0x47880000
  os_version       0x14000149
  header_version   2

The v2 header has a dedicated DTB section (dtb_size/dtb_addr at offset 1676).
This LK variant reads dtb_kernel_addr from the boot image when present, so
the mainline DTB travels inside the boot image -- no lk partition flash
needed for a `fastboot boot` test.

Usage:
  python pack_bootimg.py --kernel Image.gz --dtb mt6765-x606f.dtb -o boot.img
  python pack_bootimg.py --kernel Image.gz --dtb mt6765-x606f.dtb \
      --ramdisk ramdisk.img -o boot.img
  python pack_bootimg.py --info boot.img
"""
import argparse
import hashlib
import struct
import sys

PAGE = 2048
KERNEL_ADDR = 0x40080000
RAMDISK_ADDR = 0x51B00000
SECOND_ADDR = 0x40F00000
TAGS_ADDR = 0x47880000
DTB_ADDR = 0x4D800000  # MTK default dtb load address
OS_VERSION = 0x14000149
CMDLINE = "bootopt=64S3,32N2,64N2 buildvariant=user"
# NO panic= here: a hung kernel keeps the failed boot's LK log intact in
# expdb (each subsequent boot overwrites it).  Recover = power-cycle; the
# lk partition used with this flow boots Android normally.
# ramoops.* params register the pstore backend at postcore_initcall,
# earlier than the DT-node probe, so mid-boot panics get logged too.
EXTRA_CMDLINE = ("console=ttyS0,921600n8 earlycon ignore_loglevel "
                 "ramoops.mem_address=0x47c90000 ramoops.mem_size=0xe0000 "
                 "ramoops.console_size=0x40000 ramoops.pmsg_size=0x10000 "
                 "ramoops.record_size=0x1000 ramoops.ftrace_size=0x1000 "
                 "ramoops.ecc=0")


def align(x, n=PAGE):
    return (x + n - 1) // n * n


def p32(x):
    return struct.pack("<I", x)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def parse_info(path):
    d = read(path)
    magic, ks, ka, rs, ra, ss, sa, ta, ps, hv = struct.unpack_from("<8s9I", d, 0)
    print(f"magic={magic} kernel={ks}@{ka:#x} ramdisk={rs}@{ra:#x} "
          f"second={ss}@{sa:#x} tags={ta:#x} page={ps} hdr_ver={hv}")
    if hv >= 1:
        rds, rdo, hs = struct.unpack_from("<IIQ", d, 1660)  # v1: rdsize rdoff hdrsize
    if hv >= 2:
        ds, da = struct.unpack_from("<II", d, 1676)
        print(f"  dtb={ds}@{da:#x}")


def pack(kernel, dtb=None, ramdisk=None):
    hdr = bytearray(1684)  # v2 header size
    hdr[0:8] = b"ANDROID!"

    def put(off, data):
        hdr[off:off + len(data)] = data

    put(8, p32(len(kernel)))
    put(12, p32(KERNEL_ADDR))
    put(16, p32(len(ramdisk)))
    put(20, p32(RAMDISK_ADDR))
    put(24, p32(0))               # second
    put(28, p32(SECOND_ADDR))
    put(32, p32(TAGS_ADDR))
    put(36, p32(PAGE))
    put(40, p32(2))               # header version 2
    put(44, p32(OS_VERSION))
    name = b"x606f-mainline"[:16]
    put(48, name)
    cmd = CMDLINE.encode()[:511]
    put(64, cmd)
    put(608, EXTRA_CMDLINE.encode()[:1023])

    # sha1 over (kernel + ramdisk + second) sizes+contents
    h = hashlib.sha1()
    h.update(p32(len(kernel)) + kernel)
    h.update(p32(len(ramdisk)) + ramdisk)
    h.update(p32(0))
    put(576, h.digest())

    if dtb is not None:
        put(1676, p32(len(dtb)))
        put(1680, p32(DTB_ADDR))

    out = bytearray(hdr)
    out += b"\x00" * (align(len(hdr)) - len(hdr))
    out += kernel
    out += b"\x00" * (align(len(kernel)) - len(kernel))
    out += ramdisk
    out += b"\x00" * (align(len(ramdisk)) - len(ramdisk))
    if dtb is not None:
        out += dtb
        out += b"\x00" * (align(len(dtb)) - len(dtb))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=False)
    ap.add_argument("--dtb", required=False)
    ap.add_argument("--ramdisk", default=None)
    ap.add_argument("-o", "--output", default="boot.img")
    ap.add_argument("--info", help="show header info of a boot image")
    a = ap.parse_args()

    if a.info:
        parse_info(a.info)
        return

    if not a.kernel:
        ap.error("--kernel or --info required")

    kernel = read(a.kernel)
    dtb = read(a.dtb) if a.dtb else None
    ramdisk = read(a.ramdisk) if a.ramdisk else b""

    img = pack(kernel, dtb, ramdisk)
    with open(a.output, "wb") as f:
        f.write(img)
    print(f"wrote {a.output}: kernel={len(kernel)} ramdisk={len(ramdisk)} "
          f"dtb={len(dtb) if dtb else 0} total={len(img)}")


if __name__ == "__main__":
    sys.exit(main())
