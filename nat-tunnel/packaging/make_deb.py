#!/usr/bin/env python3
"""Build a .deb without dpkg. usage: make_deb.py <binary> <version> <amd64|arm64> <icons-dir> <out.deb>
Installs /usr/lib/strait/nat-tunnel (+ /usr/bin/strait and /usr/bin/nat-tunnel links), a menu entry and icons."""
import gzip, io, os, sys, tarfile, time

binary, version, arch, icons, out = sys.argv[1:6]
now = int(time.time())
DEPENDS = ("libc6 (>= 2.31), libgl1, libegl1, libxkbcommon0, libxkbcommon-x11-0, libwayland-client0, "
           "libx11-6, libx11-xcb1, libxcb1, libxcursor1, libxi6, libxrandr2")
RECOMMENDS = "policykit-1 | pkexec, libgl1-mesa-dri"
DESKTOP = """[Desktop Entry]
Type=Application
Name=Strait
GenericName=Direct internet sharing
Comment=Use or share an internet connection, peer to peer, with no server in the middle
Exec=strait gui
Icon=strait
Terminal=false
Categories=Network;
StartupWMClass=Strait
"""

def add(tf, name, data=b"", mode=0o644, typ=tarfile.REGTYPE, link=""):
    ti = tarfile.TarInfo(name); ti.mtime = now; ti.uid = ti.gid = 0; ti.uname = ti.gname = "root"; ti.mode = mode; ti.type = typ
    if typ == tarfile.SYMTYPE: ti.linkname = link; tf.addfile(ti)
    elif typ == tarfile.DIRTYPE: tf.addfile(ti)
    else: ti.size = len(data); tf.addfile(ti, io.BytesIO(data))

def tgz(fill):
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=now) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf: fill(tf)
    return raw.getvalue()

bin_data = open(binary, "rb").read()
def data(tf):
    for d in ("./usr", "./usr/bin", "./usr/lib", "./usr/lib/strait", "./usr/share", "./usr/share/applications",
              "./usr/share/icons", "./usr/share/icons/hicolor", "./usr/share/doc", "./usr/share/doc/strait"):
        add(tf, d, mode=0o755, typ=tarfile.DIRTYPE)
    add(tf, "./usr/lib/strait/nat-tunnel", bin_data, 0o755)
    add(tf, "./usr/bin/strait", typ=tarfile.SYMTYPE, link="../lib/strait/nat-tunnel", mode=0o777)
    add(tf, "./usr/bin/nat-tunnel", typ=tarfile.SYMTYPE, link="../lib/strait/nat-tunnel", mode=0o777)
    add(tf, "./usr/share/applications/strait.desktop", DESKTOP.encode())
    for n in (16, 32, 64, 128, 256, 512):
        p = os.path.join(icons, f"app-icon-{n}.png")
        if os.path.exists(p):
            d = f"./usr/share/icons/hicolor/{n}x{n}"; add(tf, d, mode=0o755, typ=tarfile.DIRTYPE); add(tf, d + "/apps", mode=0o755, typ=tarfile.DIRTYPE)
            add(tf, d + "/apps/strait.png", open(p, "rb").read())
    add(tf, "./usr/share/doc/strait/copyright", b"Apache-2.0. See https://github.com/TheGreatDaniad/strait\n")
installed = (len(bin_data) + 60000) // 1024
control = f"""Package: strait
Version: {version}
Architecture: {arch}
Maintainer: Strait <noreply@users.noreply.github.com>
Installed-Size: {installed}
Depends: {DEPENDS}
Recommends: {RECOMMENDS}
Section: net
Priority: optional
Homepage: https://github.com/TheGreatDaniad/strait
Description: Direct peer-to-peer internet sharing, no relay
 Share your home connection with someone you trust, or use theirs, over a direct
 encrypted tunnel. Servers are only used for the first meeting.
""".encode()
ctl = tgz(lambda tf: add(tf, "./control", control))
dat = tgz(data)

def member(name, body):
    h = f"{name:<16}{now:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
    return h + body + (b"\n" if len(body) % 2 else b"")
with open(out, "wb") as f:
    f.write(b"!<arch>\n"); f.write(member("debian-binary", b"2.0\n")); f.write(member("control.tar.gz", ctl)); f.write(member("data.tar.gz", dat))
print("wrote", out, os.path.getsize(out))
