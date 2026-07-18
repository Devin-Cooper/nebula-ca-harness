"""Tests for causb.mountctl: pinned-vfat mount + hardened remount/umount
(S7.1/S7.9, D18, R3).

Every test here runs WITHOUT root and WITHOUT a real block device: `mount`/
`umount` are never actually executed. Each function under test accepts an
injectable `runner` (defaults to `subprocess.run` in production) so tests
can assert on the EXACT argv a call would make while a `_RecordingRunner`
stub stands in for the real subprocess call -- this is the "stub subprocess
runner, don't execute" posture the brief calls for. `mount_ro`'s post-mount
fstype read-back similarly takes an injectable `mounts_path` so it can be
pointed at a hand-written fake `/proc/mounts`-shaped file instead of the
real one.

Real-hardware behavior (an actual `mount -t vfat` genuinely refusing an
ext4-formatted loop device, a real EBUSY retry, etc.) is exercised
separately by `tests/integration/hw_root.py`, run as root on the box.
"""

import os
import subprocess
import tempfile
import unittest

from causb.mountctl import MountError, mount_ro, mount_rw, umount


class _EnvCapturingRunner:
    """Minimal stub that only records the kwargs of its single call, so a
    test can assert on the `env` passed through to subprocess.run."""

    def __init__(self):
        self.kwargs = None

    def __call__(self, argv, **kwargs):
        self.kwargs = kwargs
        return subprocess.CompletedProcess(list(argv), 0, stdout=b"", stderr=b"")


class _RecordingRunner:
    """Stands in for `subprocess.run`. `results` is a list of (returncode,
    stderr_bytes) tuples, one per expected call, in order; the last entry
    repeats for any call beyond the list's length. Every call is recorded
    (argv + kwargs) and asserted, INLINE, to never use shell=True or a
    lazy (`-l`) umount -- so any test built on this stub fails loudly if
    production code ever regresses either invariant, without needing a
    dedicated test for it.
    """

    def __init__(self, results):
        self._results = list(results)
        self.calls = []  # list of (argv, kwargs)

    def __call__(self, argv, **kwargs):
        assert kwargs.get("shell") is not True, "must never use shell=True"
        assert "-l" not in argv, "must never use lazy umount (-l)"
        argv = list(argv)
        self.calls.append((argv, kwargs))
        idx = min(len(self.calls) - 1, len(self._results) - 1)
        rc, stderr = self._results[idx]
        return subprocess.CompletedProcess(argv, rc, stdout=b"", stderr=stderr)


class _TmpMounts:
    """A temp file in `/proc/mounts` line format the tests point mountctl's
    injectable `mounts_path` at, so `mount_ro`'s fstype read-back can be
    exercised without a real mount table."""

    def __init__(self, lines):
        fd, self.path = tempfile.mkstemp(prefix="causb-mounts-")
        with os.fdopen(fd, "w") as f:
            for line in lines:
                f.write(line + "\n")

    def cleanup(self):
        os.unlink(self.path)


class TestMountRo(unittest.TestCase):
    DEV = "/dev/loop0"
    MP = "/mnt/causb-priv"

    def test_builds_exact_argv_and_succeeds_with_matching_readback(self):
        runner = _RecordingRunner([(0, b"")])
        mounts = _TmpMounts([f"{self.DEV} {self.MP} vfat ro,relatime 0 0"])
        try:
            mount_ro(self.DEV, self.MP, runner=runner, mounts_path=mounts.path)
        finally:
            mounts.cleanup()

        assert len(runner.calls) == 1
        argv, kwargs = runner.calls[0]
        assert argv == [
            "mount", "-t", "vfat", "-o",
            "ro,noexec,nosuid,nodev,iocharset=ascii,utf8=0",
            self.DEV, self.MP,
        ]
        assert kwargs.get("shell") is not True

    def test_raises_mount_failed_on_nonzero_exit_and_never_reads_mounts(self):
        runner = _RecordingRunner([(32, b"mount: wrong fs type, bad option, bad superblock")])
        # A path that doesn't exist -- if mount_ro tried to read it after a
        # failed mount command, this would raise FileNotFoundError instead
        # of MountError, proving the read-back is (correctly) skipped.
        bogus_mounts_path = "/nonexistent/causb-mounts-should-not-be-read"

        with self.assertRaises(MountError) as cm:
            mount_ro(self.DEV, self.MP, runner=runner, mounts_path=bogus_mounts_path)

        assert cm.exception.reason == "mount_failed"
        assert len(runner.calls) == 1

    def test_raises_when_readback_fstype_is_not_vfat(self):
        # Belt-and-suspenders: `mount -t vfat` reported success (rc==0) but
        # the mount table disagrees about the resulting fstype -- must
        # still fail closed rather than trust the exit code alone.
        runner = _RecordingRunner([(0, b"")])
        mounts = _TmpMounts([f"{self.DEV} {self.MP} ext4 rw,relatime 0 0"])
        try:
            with self.assertRaises(MountError) as cm:
                mount_ro(self.DEV, self.MP, runner=runner, mounts_path=mounts.path)
        finally:
            mounts.cleanup()
        assert cm.exception.reason == "mount_failed"

    def test_raises_when_mountpoint_absent_from_readback(self):
        runner = _RecordingRunner([(0, b"")])
        mounts = _TmpMounts(["/dev/sda1 /some/other/mp vfat ro 0 0"])
        try:
            with self.assertRaises(MountError) as cm:
                mount_ro(self.DEV, self.MP, runner=runner, mounts_path=mounts.path)
        finally:
            mounts.cleanup()
        assert cm.exception.reason == "mount_failed"


class TestMountRw(unittest.TestCase):
    MP = "/mnt/causb-priv"

    def test_builds_exact_argv_and_succeeds(self):
        runner = _RecordingRunner([(0, b"")])
        mount_rw(self.MP, runner=runner)
        assert len(runner.calls) == 1
        argv, _ = runner.calls[0]
        assert argv == ["mount", "-o", "remount,rw,noexec,nosuid,nodev", self.MP]

    def test_raises_mount_failed_on_nonzero_exit(self):
        runner = _RecordingRunner([(1, b"mount: /mnt/causb-priv: mount point not mounted")])
        with self.assertRaises(MountError) as cm:
            mount_rw(self.MP, runner=runner)
        assert cm.exception.reason == "mount_failed"


class TestUmount(unittest.TestCase):
    MP = "/mnt/causb-priv"

    def test_succeeds_on_first_try(self):
        runner = _RecordingRunner([(0, b"")])
        umount(self.MP, runner=runner)
        assert len(runner.calls) == 1
        argv, _ = runner.calls[0]
        assert argv == ["umount", self.MP]

    def test_retries_on_busy_then_succeeds(self):
        runner = _RecordingRunner(
            [
                (1, b"umount: /mnt/causb-priv: target is busy."),
                (1, b"umount: /mnt/causb-priv: target is busy."),
                (0, b""),
            ]
        )
        umount(self.MP, runner=runner, max_attempts=5, initial_backoff_s=0.001)
        assert len(runner.calls) == 3
        for argv, _ in runner.calls:
            assert argv == ["umount", self.MP]

    def test_raises_deliver_failed_after_exhausting_retries_on_persistent_busy(self):
        runner = _RecordingRunner([(1, b"umount: /mnt/causb-priv: target is busy.")])
        with self.assertRaises(MountError) as cm:
            umount(self.MP, runner=runner, max_attempts=3, initial_backoff_s=0.001)
        assert cm.exception.reason == "deliver_failed"
        assert len(runner.calls) == 3

    def test_raises_immediately_on_non_busy_error_without_retrying(self):
        runner = _RecordingRunner([(1, b"umount: /mnt/causb-priv: not mounted.")])
        with self.assertRaises(MountError) as cm:
            umount(self.MP, runner=runner, max_attempts=5, initial_backoff_s=0.001)
        assert cm.exception.reason == "deliver_failed"
        assert len(runner.calls) == 1  # no retry for a non-EBUSY failure

    def test_never_returns_on_nonzero_rc(self):
        # umount() must "return only on rc==0 (else raises)" -- a bare
        # non-busy, non-zero exit must raise, never return None silently.
        runner = _RecordingRunner([(1, b"umount: some other failure")])
        with self.assertRaises(MountError):
            umount(self.MP, runner=runner, max_attempts=1, initial_backoff_s=0.001)


class TestRunForcesCLocale(unittest.TestCase):
    """HARDENING (item 2): every mount(8)/umount(8) call must run under the
    C locale so umount()'s EBUSY retry -- which matches the English "busy"
    substring in stderr -- can't be silently defeated by an ambient
    non-English LANG/LC_*."""

    def test_umount_call_passes_c_locale_env_merged_over_environ(self):
        runner = _EnvCapturingRunner()
        umount("/mnt/causb-priv", runner=runner)
        env = runner.kwargs.get("env")
        assert env is not None, "must pass an explicit env, not inherit ambient locale"
        assert env.get("LC_ALL") == "C"
        assert env.get("LANG") == "C"
        # Merged OVER os.environ (not a bare 2-key dict) so PATH still resolves.
        assert "PATH" in env

    def test_mount_ro_call_also_forces_c_locale(self):
        runner = _EnvCapturingRunner()
        mounts = _TmpMounts(["/dev/loop0 /mnt/causb-priv vfat ro 0 0"])
        try:
            mount_ro("/dev/loop0", "/mnt/causb-priv", runner=runner, mounts_path=mounts.path)
        finally:
            mounts.cleanup()
        env = runner.kwargs.get("env")
        assert env is not None
        assert env.get("LC_ALL") == "C"
        assert env.get("LANG") == "C"


if __name__ == "__main__":
    unittest.main()
