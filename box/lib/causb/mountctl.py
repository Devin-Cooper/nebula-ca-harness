"""Pinned-vfat mount + hardened remount/umount (S7.1, S7.9, D18, R3).

`mount_ro()` implements S7.1/D18's core defense: the media parser is
distrusted, so the filesystem TYPE is pinned via `mount -t vfat` rather than
letting the kernel auto-probe a block device's superblock -- "a signature
check does not protect the layers that run before it," and letting `mount`
guess the type would hand an attacker-controlled block device straight to
whichever big, built-in kernel FS parser it can get to guess-match (ext4,
exfat, ...) before anything is authenticated. Passing `-t vfat` explicitly
makes `mount(8)`/the kernel itself refuse a superblock that isn't actually
FAT -- there is no separate "detect and reject" step to get right, because
the pinned type IS the rejection mechanism. This module additionally reads
back the resulting entry in `/proc/mounts` after a "successful" mount and
raises `MountError` if it somehow disagrees (defense in depth against a
mount(8)/kernel combination that could otherwise silently do the wrong
thing; believed unreachable in practice, since a non-FAT superblock makes
`mount -t vfat` fail outright, but cheap to assert explicitly rather than
trust the exit code alone).

`mount_rw()` re-asserts all three hardening flags on every remount (S7.9:
"remount,rw" must not accidentally relax `noexec,nosuid,nodev` -- a mount
option is not implicitly retained across a remount unless re-stated).

`umount()` retries ONLY on a busy target (S7.10/R3), with backoff, and
NEVER passes `-l` (lazy unmount): a lazy unmount detaches the mountpoint
from the namespace immediately while the underlying device may still be
in use, which is exactly backwards for a hardware USB stick the box is
about to tell the operator is safe to physically remove (D13's
SAFE-TO-REMOVE gate is only meaningful if the medium is ACTUALLY
unmounted, not merely hidden from the mount table). It returns (None) only
on a genuine rc==0; any other outcome raises.

Every mount(8) invocation goes through an injectable `runner` (defaults to
the real `subprocess.run`) as an argv LIST -- never `shell=True`, never a
string command -- so a test can assert on the exact argv without actually
invoking `mount`. Real-hardware behavior (an actual `mount -t vfat`
genuinely refusing an ext4 loop device, a real EBUSY retry) is exercised by
`tests/integration/hw_root.py`, run as root on the box.
"""

import os
import subprocess
import time

_MOUNT_OPTS_RO = "ro,noexec,nosuid,nodev,iocharset=ascii,utf8=0"
_REMOUNT_OPTS_RW = "remount,rw,noexec,nosuid,nodev"

_DEFAULT_MOUNTS_PATH = "/proc/mounts"


class MountError(Exception):
    """A mount(8)/umount(8) operation failed. `reason` is one of the fixed
    S19 R10a status.json.error enum strings this module is responsible
    for: "mount_failed" (the initial pinned-vfat mount, or a remount,
    failed -- including a `mount -t vfat` that exited 0 but whose
    resulting /proc/mounts entry does not actually say "vfat") or
    "deliver_failed" (umount could not complete after exhausting its
    EBUSY retry budget, or failed for a non-busy reason) -- this is a wire
    contract relied on by later tasks; the strings must not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _run(runner, argv):
    # Force the C locale so umount(8)'s human-readable stderr ("target is
    # busy") is stable regardless of the box's ambient LANG/LC_* -- the
    # EBUSY retry-vs-fail-fast decision in umount() matches on that English
    # substring, and a non-English locale would otherwise silently defeat
    # the retry (a genuine EBUSY would be misread as a permanent failure).
    # Merged OVER os.environ (not a bare dict) so PATH etc. still resolve
    # `mount`/`umount`. Success itself is exit-code-gated, not text-gated;
    # this only stabilizes the busy-detection branch.
    env = dict(os.environ, LC_ALL="C", LANG="C")
    return runner(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def _decode(data):
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace")
    return str(data)


def _mounted_fstype(mp, mounts_path):
    """Return the fstype `/proc/mounts` (or an injected equivalent) reports
    for mountpoint `mp`, or None if `mp` has no entry at all. Reads the
    THIRD whitespace-separated field of the matching line (device,
    mountpoint, fstype, options, dump, pass) -- robust to whatever the
    options field contains.
    """
    with open(mounts_path) as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == mp:
                return fields[2]
    return None


def mount_ro(dev, mp, runner=subprocess.run, mounts_path=_DEFAULT_MOUNTS_PATH):
    """Mount `dev` read-only at `mp`, pinned to vfat (S7.1): `mount -t vfat
    -o ro,noexec,nosuid,nodev,iocharset=ascii,utf8=0 dev mp`. NEVER probes
    the filesystem type -- if `dev` is not actually FAT, `mount(8)` itself
    refuses (non-zero exit), which this function surfaces as
    `MountError("mount_failed")`. After a reported success, also reads
    back `mounts_path` and raises the same error if the resulting fstype
    isn't exactly "vfat" or the mountpoint is missing entirely (belt and
    suspenders; see module docstring). Returns None on success.
    """
    argv = ["mount", "-t", "vfat", "-o", _MOUNT_OPTS_RO, dev, mp]
    result = _run(runner, argv)
    if result.returncode != 0:
        raise MountError("mount_failed")

    fstype = _mounted_fstype(mp, mounts_path)
    if fstype != "vfat":
        raise MountError("mount_failed")


def mount_rw(mp, runner=subprocess.run):
    """Remount `mp` read-write, re-asserting all three hardening flags
    (S7.9): `mount -o remount,rw,noexec,nosuid,nodev mp`. Raises
    `MountError("mount_failed")` on a non-zero exit. Returns None on
    success.
    """
    argv = ["mount", "-o", _REMOUNT_OPTS_RW, mp]
    result = _run(runner, argv)
    if result.returncode != 0:
        raise MountError("mount_failed")


def umount(mp, runner=subprocess.run, max_attempts=6, initial_backoff_s=0.25):
    """Unmount `mp`, retrying ONLY a busy target with exponential backoff
    (S7.10/R3), NEVER passing `-l` (see module docstring). Returns None
    only when `umount` actually exits 0; any other outcome -- a non-busy
    failure (no retry attempted), or a busy target that is still busy
    after `max_attempts` -- raises `MountError("deliver_failed")`.
    """
    argv = ["umount", mp]
    backoff = initial_backoff_s
    result = None
    for attempt in range(max_attempts):
        result = _run(runner, argv)
        if result.returncode == 0:
            return
        if "busy" not in _decode(result.stderr).lower():
            raise MountError("deliver_failed")
        if attempt < max_attempts - 1:
            time.sleep(backoff)
            backoff *= 2
    raise MountError("deliver_failed")
