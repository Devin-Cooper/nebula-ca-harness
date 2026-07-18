"""Tests for causb.collect: symlink-safe output collection from an
unprivileged run-script's out_dir into the root-owned results_dir
(S19 R1 -- the rev-3 BLOCKER -- and S7.8-9).

Every hostile fixture (symlink, hardlink, FIFO, Unix socket) is a REAL
filesystem object created in-test via stdlib os/socket calls -- unlike
test_extract.py's hand-built TarInfo headers, out_dir here must contain
real directory entries for os.walk to discover, so there is no way to
fabricate an in-memory "hostile tar member" equivalent. Each such fixture
carries a distinctive secret byte string and lives OUTSIDE out_dir (in a
location the fixture setup controls, standing in for something like
/var/lib/nebula-ca/ca/ca.key); every rejection test asserts that secret
never appears anywhere under results_dir afterward, which is the direct
proof that the ca.key-exfil scenario S19 R1 exists to prevent -- a
run-script job plants an out_dir entry pointing at something it must not
be able to disclose, and root's collection step refuses to read through
it -- cannot happen.
"""

import errno
import hashlib
import os
import shutil
import socket
import tempfile
import unittest
from unittest import mock

from causb import config
from causb.collect import CollectError, collect


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-collect-test-")
        self.out_dir = os.path.join(self.tmp, "out")
        self.results_dir = os.path.join(self.tmp, "results")
        os.mkdir(self.out_dir)
        os.mkdir(self.results_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _all_result_bytes(self):
        """Concatenate the content of every file collect() actually wrote
        under results_dir -- used to assert a secret never landed there,
        regardless of what relative path it might have landed under."""
        blob = b""
        for root, _dirs, files in os.walk(self.results_dir):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    blob += f.read()
        return blob

    def _result_names(self):
        names = []
        for _root, _dirs, files in os.walk(self.results_dir):
            names.extend(files)
        return names

    # --- the one accept path ---

    def test_plaintext_file_copies_and_hashes_correctly(self):
        content = b"hello from an unprivileged run-script job\n"
        with open(os.path.join(self.out_dir, "output.txt"), "wb") as f:
            f.write(content)

        outputs = collect(self.out_dir, self.results_dir)

        # sha256 verified against an INDEPENDENT hashlib computation over
        # the same bytes, per the task's constraint -- not just trusting
        # whatever collect() itself computed internally.
        expected_sha256 = hashlib.sha256(content).hexdigest()
        assert outputs == [
            {"path": "output.txt", "sha256": expected_sha256, "bytes": len(content)}
        ]
        with open(os.path.join(self.results_dir, "output.txt"), "rb") as f:
            assert f.read() == content

    # --- brief-mandated rejections ---

    def test_symlink_to_sensitive_fixture_is_refused_and_not_copied(self):
        secret = b"THE-REAL-CA-KEY-BYTES-must-never-leave-this-fixture-file"
        ca_key_fixture = os.path.join(self.tmp, "ca.key")
        with open(ca_key_fixture, "wb") as f:
            f.write(secret)

        os.symlink(ca_key_fixture, os.path.join(self.out_dir, "x"))

        with self.assertRaises(CollectError) as cm:
            collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "path_traversal"

        assert secret not in self._all_result_bytes()
        assert "x" not in self._result_names()

    def test_hardlink_is_refused(self):
        content = b"content reachable via a second directory entry"
        fixture = os.path.join(self.tmp, "original-outside-out-dir.bin")
        with open(fixture, "wb") as f:
            f.write(content)

        os.link(fixture, os.path.join(self.out_dir, "x"))

        with self.assertRaises(CollectError) as cm:
            collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "path_traversal"

        assert content not in self._all_result_bytes()
        assert "x" not in self._result_names()

    def test_over_cap_file_count_raises_cap_exceeded(self):
        for i in range(config.CAPS["tar_files"] + 1):
            with open(os.path.join(self.out_dir, f"f{i}"), "wb") as f:
                f.write(b"x")

        with self.assertRaises(CollectError) as cm:
            collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "cap_exceeded"

    # --- boundary + hardening beyond the bare minimum (extract.py precedent) ---

    def test_at_cap_file_count_succeeds(self):
        assert config.CAPS["tar_files"] == 64  # guards the fixture if the cap moves
        for i in range(config.CAPS["tar_files"]):
            with open(os.path.join(self.out_dir, f"f{i}"), "wb") as f:
                f.write(b"x")

        outputs = collect(self.out_dir, self.results_dir)
        assert len(outputs) == config.CAPS["tar_files"]

    @staticmethod
    def _fdopen_failing_write(err):
        """A `causb.collect.os.fdopen` side_effect: real file for reads ('rb'),
        but a write-mode ('wb') open whose `.write()` raises `OSError(err)`. A
        real file object has no writable `.write` attribute, so wrap it (and
        still close its fd on exit, so no descriptor leaks)."""
        real_fdopen = os.fdopen

        class _FailWrite:
            def __init__(self, f):
                self._f = f

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._f.close()
                return False

            def write(self, _data):
                raise OSError(err, os.strerror(err))

        def _side(fd, mode, *a, **k):
            f = real_fdopen(fd, mode, *a, **k)
            return _FailWrite(f) if "w" in mode else f

        return _side

    def test_write_side_enospc_folds_to_cap_exceeded(self):
        # out_dir and collect_dir share the box's 32M tmpfs, so a large output
        # exhausts it -> ENOSPC while collect COPIES into results_dir. That must
        # fold into the enum (cap_exceeded), never escape as a raw OSError -> a
        # bare FAULT with no operator-readable reason.
        with open(os.path.join(self.out_dir, "big.txt"), "wb") as f:
            f.write(b"payload")
        with mock.patch("causb.collect.os.fdopen",
                        side_effect=self._fdopen_failing_write(errno.ENOSPC)):
            with self.assertRaises(CollectError) as cm:
                collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "cap_exceeded"

    def test_write_side_generic_oserror_folds_to_bad_output(self):
        with open(os.path.join(self.out_dir, "f.txt"), "wb") as f:
            f.write(b"payload")
        with mock.patch("causb.collect.os.fdopen",
                        side_effect=self._fdopen_failing_write(errno.EIO)):
            with self.assertRaises(CollectError) as cm:
                collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "bad_output"

    def test_symlinked_subdirectory_is_refused_and_contents_not_collected(self):
        # A directory symlink is at least as dangerous as a file symlink:
        # if collect() ever descended into it, os.walk would enumerate
        # and copy out whatever real (possibly sensitive) tree it points
        # at, with no single "planted file" needed at all.
        secret = b"topology-and-secrets-that-must-never-leave-via-a-dir-symlink"
        sensitive_dir = os.path.join(self.tmp, "sensitive")
        os.mkdir(sensitive_dir)
        with open(os.path.join(sensitive_dir, "secret.txt"), "wb") as f:
            f.write(secret)

        os.symlink(sensitive_dir, os.path.join(self.out_dir, "evil_dir"))

        with self.assertRaises(CollectError) as cm:
            collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "path_traversal"

        assert secret not in self._all_result_bytes()
        assert "secret.txt" not in self._result_names()

    def test_nested_subdirectory_file_is_collected_with_relative_path(self):
        os.mkdir(os.path.join(self.out_dir, "sub"))
        content = b"nested output"
        with open(os.path.join(self.out_dir, "sub", "report.txt"), "wb") as f:
            f.write(content)

        outputs = collect(self.out_dir, self.results_dir)

        assert outputs == [
            {
                "path": "sub/report.txt",
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
        ]
        with open(os.path.join(self.results_dir, "sub", "report.txt"), "rb") as f:
            assert f.read() == content

    def test_fifo_is_refused(self):
        # Opened internally with O_NONBLOCK specifically so a FIFO with no
        # writer can never hang the harness -- this test itself hanging
        # would be the signal that hardening is missing.
        os.mkfifo(os.path.join(self.out_dir, "x"))

        with self.assertRaises(CollectError) as cm:
            collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "path_traversal"

        assert "x" not in self._result_names()

    def test_unix_socket_is_refused(self):
        sock_path = os.path.join(self.out_dir, "x")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(sock_path)

            with self.assertRaises(CollectError) as cm:
                collect(self.out_dir, self.results_dir)
            assert cm.exception.reason == "path_traversal"

            assert "x" not in self._result_names()
        finally:
            s.close()

    def test_empty_out_dir_returns_empty_list(self):
        assert collect(self.out_dir, self.results_dir) == []

    # --- review finding 1 [CRITICAL]: intermediate-dir-symlink TOCTOU on the read side ---

    def test_intermediate_dir_symlink_swap_race_does_not_exfil(self):
        # The rev-3 BLOCKER's real teeth: a run-script job that leaves a
        # process alive can, in the window between the walk discovering an
        # intermediate directory (out_dir/sub) and the leaf (out_dir/sub/x)
        # being opened, atomically swap `sub` for a symlink pointing at a
        # directory it controls -- e.g. os.symlink("/var/lib/nebula-ca/ca",
        # "out_dir/sub") -- so a leaf named `x` resolves to a real regular
        # ca.key. A path-STRING leaf open (os.open("out_dir/sub/x",
        # O_NOFOLLOW)) only guards the FINAL component, follows the swapped
        # `sub`, and root copies the secret. An fd-PINNED open
        # (os.open("x", dir_fd=<sub's fd>)) resolves `x` within the real
        # `sub` inode the walk already opened, and cannot be redirected by
        # renaming the `sub` NAME.
        #
        # This reproduces the race deterministically by monkeypatching the
        # module's os.open to perform the swap on the first read-side leaf
        # open, then asserts the planted secret never reaches results_dir.
        # It FAILS against a path-string implementation (secret exfiltrated)
        # and PASSES against the fd-pinned os.fwalk/dir_fd one.
        secret = b"FAKE-CA-KEY-VIA-INTERMEDIATE-DIR-SYMLINK-SWAP-must-not-exfil"
        attacker_dir = os.path.join(self.tmp, "attacker")
        os.mkdir(attacker_dir)
        with open(os.path.join(attacker_dir, "x"), "wb") as f:
            f.write(secret)

        sub = os.path.join(self.out_dir, "sub")
        os.mkdir(sub)
        with open(os.path.join(sub, "x"), "wb") as f:
            f.write(b"benign original content")

        real_open = os.open
        state = {"swapped": False}

        def swapping_open(path, flags, *args, **kwargs):
            # Fire exactly once, on the first READ-side leaf open (O_NOFOLLOW
            # set; not a directory open, not a write open -- so neither the
            # walk's own dir descents nor _write_dest's opens trip it):
            # move the real `sub` dir aside and drop a symlink -> attacker
            # dir in its place, THEN delegate to the genuine os.open with
            # the caller's own (path, flags, dir_fd) unchanged.
            if (
                not state["swapped"]
                and (flags & os.O_NOFOLLOW)
                and not (flags & (os.O_WRONLY | os.O_DIRECTORY))
            ):
                state["swapped"] = True
                os.rename(sub, os.path.join(self.out_dir, "sub_moved"))
                os.symlink(attacker_dir, sub)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("causb.collect.os.open", side_effect=swapping_open):
            try:
                collect(self.out_dir, self.results_dir)
            except CollectError:
                pass  # a raised CollectError is an acceptable outcome; the
                # load-bearing guarantee is the assertion below.

        assert state["swapped"], "the race hook never fired -- test is vacuous"
        assert secret not in self._all_result_bytes()

    # --- review finding 2 [Important]: content-triggered OSError -> bad_output, not raw ---

    def test_unreadable_subdir_is_bad_output(self):
        # A nebula-job-owned chmod-000 subdirectory makes the walk hit a
        # PermissionError while descending. That content-triggered OSError
        # must be folded into CollectError("bad_output"), never left to
        # escape as a raw PermissionError (which on this LED-only box leaves
        # the error-reporting path undefined). Runs as the unprivileged test
        # user, so chmod 000 actually denies the descent; skipped under root
        # (which bypasses DAC, so the premise wouldn't hold).
        if os.geteuid() == 0:
            self.skipTest("chmod 000 does not deny root; run as an unprivileged user")
        locked = os.path.join(self.out_dir, "locked")
        os.mkdir(locked)
        with open(os.path.join(locked, "f"), "wb") as f:
            f.write(b"z")
        os.chmod(locked, 0)
        try:
            with self.assertRaises(CollectError) as cm:
                collect(self.out_dir, self.results_dir)
            assert cm.exception.reason == "bad_output"
        finally:
            os.chmod(locked, 0o700)  # let tearDown's rmtree clean up

    def test_missing_out_dir_propagates_raw_oserror(self):
        # The one genuinely environment-scoped case: out_dir itself
        # missing/not-a-directory is a caller/harness bug, not attacker-
        # influenced CONTENT, so it stays a raw OSError (mirrors
        # extract.py's dest_dir bootstrap). Only the CONTENTS of out_dir
        # fold into CollectError.
        shutil.rmtree(self.out_dir)
        with self.assertRaises(OSError):
            collect(self.out_dir, self.results_dir)

    # --- review finding 3 [Minor]: depth cap on out_dir nesting (config.CAPS["depth"] == 4) ---

    def test_output_over_depth_cap_is_rejected(self):
        # a/b/c/d/e is 5 out_dir-relative components, one over CAPS["depth"]
        # (4) -> path_traversal, mirroring causb.extract's depth handling.
        assert config.CAPS["depth"] == 4  # guards the fixture if the cap moves
        deep = os.path.join(self.out_dir, "a", "b", "c", "d")
        os.makedirs(deep)
        with open(os.path.join(deep, "e"), "wb") as f:
            f.write(b"too deep")

        with self.assertRaises(CollectError) as cm:
            collect(self.out_dir, self.results_dir)
        assert cm.exception.reason == "path_traversal"

    def test_output_at_depth_cap_is_collected(self):
        # a/b/c/d == exactly 4 components == CAPS["depth"]; AT the cap, so it
        # collects (boundary is <=, not <), matching extract.py.
        assert config.CAPS["depth"] == 4
        deep = os.path.join(self.out_dir, "a", "b", "c")
        os.makedirs(deep)
        content = b"at the depth cap"
        with open(os.path.join(deep, "d"), "wb") as f:
            f.write(content)

        outputs = collect(self.out_dir, self.results_dir)
        assert outputs == [
            {
                "path": "a/b/c/d",
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
        ]


if __name__ == "__main__":
    unittest.main()
