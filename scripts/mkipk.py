#!/usr/bin/env python3
# mkipk.py - 无 buildroot 组装 OpenWrt ipk
#
# OpenWrt 的 ipk（ipkg-build 约定）是**外层 gzip tar**，内含三个成员：
#   ./debian-binary（内容 "2.0\n"）、./control.tar.gz、./data.tar.gz
# 注意不是 Debian .deb 的 ar 格式——路由器上的 opkg 只认外层 tar.gz。
# 用法：
#   python3 mkipk.py --name luci-app-cqie-auth --version 1.9.0 --release 1 \
#       --arch all --control build/luci-ipk/control --data build/luci-ipk/data \
#       -o luci-app-cqie-auth_1.9.0-1_all.ipk
#
# 文件权限规则（Windows 文件系统没有 exec 位，无法从磁盘推断）：
#   目录、*/bin/*、*/libexec/* -> 0755，其余 -> 0644
#
# 仅用标准库；Windows/WSL 双端行为一致。
import argparse
import gzip
import io
import os
import sys
import tarfile


def is_exec(rel):
    p = "/" + rel.replace("\\", "/")
    return "/bin/" in p or "/libexec/" in p


def mode_for(rel, is_dir):
    if is_dir:
        return 0o755
    return 0o755 if is_exec(rel) else 0o644


def entries_sorted(dirpath):
    """父目录先于子项；同层按名字排序，保证产物确定性。"""
    out = []
    for root, dirs, files in os.walk(dirpath):
        dirs.sort()
        files.sort()
        for d in dirs:
            out.append((os.path.join(root, d), True))
        for f in files:
            out.append((os.path.join(root, f), False))
    return out


def tar_gz(dirpath):
    """目录 -> tar.gz（条目名带 ./ 前缀，对齐 ipkg-build 习惯）。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for path, is_dir in entries_sorted(dirpath):
            rel = os.path.relpath(path, dirpath).replace("\\", "/")
            ti = tarfile.TarInfo("./" + rel)
            ti.mode = mode_for(rel, is_dir)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            if is_dir:
                ti.type = tarfile.DIRTYPE
                ti.size = 0
                tf.addfile(ti)
            else:
                with open(path, "rb") as f:
                    ti.size = os.fstat(f.fileno()).st_size
                    tf.addfile(ti, f)
    return gzip_compress(buf.getvalue())


def gzip_compress(data):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()


def outer_tar(members):
    """OpenWrt ipk 的外壳是 gzip tar（ipkg-build 约定），内含三个成员：
    ./debian-binary、./control.tar.gz、./data.tar.gz。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data in members:
            ti = tarfile.TarInfo("./" + name)
            ti.size = len(data)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    return gzip_compress(buf.getvalue())


def main():
    ap = argparse.ArgumentParser(description="无 buildroot 组装 OpenWrt ipk")
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--release", required=True)
    ap.add_argument("--arch", required=True)
    ap.add_argument("--control", required=True, help="control 目录（含 control 文件）")
    ap.add_argument("--data", required=True, help="data 目录（安装文件树）")
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    control = tar_gz(args.control)
    data = tar_gz(args.data)

    ipk = outer_tar([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", control),
        ("data.tar.gz", data),
    ])
    with open(args.output, "wb") as f:
        f.write(ipk)
    print("%s  (%d bytes, arch=%s)" % (args.output, len(ipk), args.arch))


if __name__ == "__main__":
    sys.exit(main())
