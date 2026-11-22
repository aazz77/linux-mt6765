#!/usr/bin/env python3
"""Build a minimal gzip-compressed cpio (newc) initramfs for X606F mainline.

Pure Python so it runs on the Linux CI runner without depending on a
system `cpio` binary.  Everything under the source directory is packed;
regular files keep their on-disk mode, except that `init` and anything
under `bin/` are forced executable (Windows checkouts lose the +x bit).

A hardcoded set of busybox symlinks is added so that the `#!/bin/sh`
shebang in /init resolves before userspace runs `busybox --install`.

Usage:
  python3 make_initramfs.py --src board/x606f/initramfs -o out/ramdisk.img
"""
import argparse
import gzip
import os
import sys

NEWC_MAGIC = "070701"


def align4(n):
    return (n + 3) & ~3


def cpio_header(name, mode, uid, gid, nlink, mtime, filesize,
                devmajor=0, devminor=0, rdevmajor=0, rdevminor=0, check=0):
    """Standard newc header: 6-byte magic + 13 x 8-hex-digit fields = 110 bytes."""
    namesize = len(name.encode()) + 1
    fields = [NEWC_MAGIC,
              f"{0:08x}",                # ino
              f"{mode:08x}", f"{uid:08x}", f"{gid:08x}",
              f"{nlink:08x}", f"{mtime:08x}", f"{filesize:08x}",
              f"{devmajor:08x}", f"{devminor:08x}",
              f"{rdevmajor:08x}", f"{rdevminor:08x}",
              f"{namesize:08x}", f"{check:08x}"]
    hdr = "".join(fields).encode("ascii")
    assert len(hdr) == 110, f"bad newc header size {len(hdr)}"
    return hdr


def add_entry(out, name, mode, data):
    """name uses a leading '/', stored without it in cpio (kernel expects no leading /)."""
    stored = name.lstrip("/")
    hdr = cpio_header(stored, mode, 0, 0, 1, 0, len(data))
    out += hdr
    out += stored.encode() + b"\0"
    out += b"\0" * (align4(len(hdr) + len(stored) + 1) - len(hdr) - len(stored) - 1)
    out += data
    out += b"\0" * (align4(len(data)) - len(data))


def add_symlink(out, name, target):
    stored = name.lstrip("/")
    mode = 0o120777
    data = target.encode()
    hdr = cpio_header(stored, mode, 0, 0, 1, 0, len(data))
    out += hdr
    out += stored.encode() + b"\0"
    out += b"\0" * (align4(len(hdr) + len(stored) + 1) - len(hdr) - len(stored) - 1)
    out += data
    out += b"\0" * (align4(len(data)) - len(data))


def build(src):
    out = bytearray()
    # Directory entries first (kernel creates them implicitly, but explicit is safe).
    for d in ["/bin", "/sbin", "/proc", "/sys", "/dev", "/tmp"]:
        add_entry(out, d + "/", 0o040755, b"")

    # Files, deterministic order.
    for root, dirs, files in os.walk(src):
        dirs.sort()
        files.sort()
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, src).replace("\\", "/")
            name = "/" + rel
            data = open(full, "rb").read()
            st = os.stat(full)
            mode = st.st_mode & 0o777
            if mode == 0:
                mode = 0o644
            # Force executables: /init and everything in bin/.
            # Set an exact 0755 (checkouts on Windows often give 0666 or 0644).
            if name == "/init" or rel.startswith("bin/"):
                mode = 0o755
            add_entry(out, name, 0o100000 | mode, data)
            print(f"  file {name} mode={mode:o} size={len(data)}")

    # Symlinks required before /init's shebang is evaluated.
    for link, target in [("/bin/sh", "busybox"),
                         ("/bin/ash", "busybox"),
                         ("/sbin/init", "/bin/busybox")]:
        add_symlink(out, link, target)
        print(f"  link {link} -> {target}")

    # newc trailer
    add_entry(out, "TRAILER!!!", 0, b"")
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="rootfs source directory")
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    cpio = build(a.src)
    with open(a.output, "wb") as f:
        f.write(gzip.compress(cpio, mtime=0))
    print(f"wrote {a.output}: cpio={len(cpio)} gzip={os.path.getsize(a.output)}")


if __name__ == "__main__":
    sys.exit(main())
