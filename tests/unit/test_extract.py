"""Tests for causb.extract: hardened tar extraction into trusted tmpfs
(S7.5, S11, D18, clarity M3).

Every malicious tar is built IN-TEST with a hand-constructed
`tarfile.TarInfo` (never a real symlink/device/etc. from the host
filesystem) so these tests exercise exactly the member SHAPES extract()
must reject, independent of what this test-runner's own OS can create.
None of these tests ever calls `tarfile.TarFile.extract()`/`.extractall()`
-- that is the whole point of extract.py existing.
"""

import io
import os
import shutil
import tarfile
import tempfile
import unittest

from causb import config
from causb.extract import ExtractError, extract


def _add_regular(tar, name, data=b""):
    """Add a real regular-file member with `data` as its content."""
    ti = tarfile.TarInfo(name=name)
    ti.type = tarfile.REGTYPE
    ti.size = len(data)
    tar.addfile(ti, io.BytesIO(data))


def _add_bare(tar, name, tar_type, size=0, linkname=None):
    """Add a member HEADER ONLY, with no data blocks written -- used for
    symlink/hardlink/device/fifo/dir members (which carry no data of
    their own) and for the decompression-bomb member (a header that LIES
    about its size with nothing backing it up).

    This writes the header via the same `TarInfo.tobuf()` + raw
    `fileobj.write()` sequence `TarFile.addfile()` itself uses internally
    for its fileobj=None case, rather than calling `addfile()` directly:
    Python 3.13 hardened `addfile()` to raise ValueError for a
    non-zero-size regular-file member with no fileobj (a good guardrail
    against a *well-behaved* caller of tarfile's own API) -- but a real
    hostile tar is not produced by calling tarfile's writer API at all,
    so bypassing that guard here is a more faithful stand-in for "an
    attacker hand-crafted this header," not a workaround for a test
    limitation.
    """
    ti = tarfile.TarInfo(name=name)
    ti.type = tar_type
    ti.size = size
    if linkname is not None:
        ti.linkname = linkname
    buf = ti.tobuf(tar.format, tar.encoding, tar.errors)
    tar.fileobj.write(buf)
    tar.offset += len(buf)
    tar.members.append(ti)


class TestExtract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-extract-test-")
        self.tar_path = os.path.join(self.tmp, "job.tar")
        self.dest_dir = os.path.join(self.tmp, "dest")
        os.mkdir(self.dest_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _open_tar(self):
        return tarfile.open(self.tar_path, "w")

    def _assert_rejected(self, reason):
        with self.assertRaises(ExtractError) as cm:
            extract(self.tar_path, self.dest_dir)
        assert cm.exception.reason == reason

    # --- the one accept path ---

    def test_benign_tar_extracts(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b'{"schema_version":1}')
            _add_regular(tar, "payload/x", b"payload-bytes")

        extract(self.tar_path, self.dest_dir)

        with open(os.path.join(self.dest_dir, "manifest.json"), "rb") as f:
            assert f.read() == b'{"schema_version":1}'
        with open(os.path.join(self.dest_dir, "payload", "x"), "rb") as f:
            assert f.read() == b"payload-bytes"

    # --- brief-mandated rejections ---

    def test_symlink_member_is_path_traversal(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_bare(tar, "payload/evil", tarfile.SYMTYPE, linkname="/etc/passwd")

        self._assert_rejected("path_traversal")

    def test_absolute_path_member_is_rejected(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "/etc/passwd", b"pwned")

        self._assert_rejected("path_traversal")

    def test_dotdot_member_is_rejected(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/../../etc/passwd", b"pwned")

        self._assert_rejected("path_traversal")

    def test_too_many_files_is_cap_exceeded(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            # manifest.json + tar_files (64) payload files == 65 total,
            # one over the S16 cap.
            for i in range(config.CAPS["tar_files"]):
                _add_regular(tar, f"payload/f{i}", b"x")

        self._assert_rejected("cap_exceeded")

    def test_device_node_member_is_rejected(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_bare(tar, "payload/dev0", tarfile.CHRTYPE)

        self._assert_rejected("path_traversal")

    # --- added per task constraints: decompression-bomb guard ---

    def test_decompression_bomb_member_is_cap_exceeded(self):
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            # Header claims ~1000x the tar_bytes cap; NO data blocks
            # actually back this up (fileobj=None in _add_bare) -- the tar
            # file on disk stays tiny. extract() must reject this from the
            # header's declared member.size alone, before ever calling
            # tar.extractfile()/.read() on it (which would hit the
            # archive's real EOF).
            _add_bare(
                tar, "payload/bomb", tarfile.REGTYPE,
                size=config.CAPS["tar_bytes"] * 1000,
            )

        self._assert_rejected("cap_exceeded")

    # --- review fix #2: depth cap (config.CAPS["depth"] == 4) ---

    def test_depth_at_cap_extracts(self):
        # payload/a/b/c is exactly 4 path components == CAPS["depth"]; it is
        # AT the cap, not over it, so it must extract (the boundary is <=,
        # not <), creating the two intermediate dirs a/ and b/.
        assert config.CAPS["depth"] == 4  # guards the fixture if the cap moves
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/a/b/c", b"deep-content")

        extract(self.tar_path, self.dest_dir)

        with open(os.path.join(self.dest_dir, "payload", "a", "b", "c"), "rb") as f:
            assert f.read() == b"deep-content"

    def test_depth_over_cap_is_rejected(self):
        # payload/a/b/c/d is 5 components, one over CAPS["depth"] (4).
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/a/b/c/d", b"too-deep")

        self._assert_rejected("path_traversal")

    # --- review fix #3: ".." is a per-component check, not a substring scan ---

    def test_dotdot_inside_a_filename_component_is_accepted(self):
        # "notes..v2.txt" merely CONTAINS ".." within a single component --
        # it is not a parent-dir reference. The old substring `".." in name`
        # test wrongly rejected this benign name; the per-component check
        # must accept it and extract it verbatim.
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/notes..v2.txt", b"benign")

        extract(self.tar_path, self.dest_dir)

        with open(os.path.join(self.dest_dir, "payload", "notes..v2.txt"), "rb") as f:
            assert f.read() == b"benign"

    def test_dotdot_as_a_path_component_is_still_rejected(self):
        # "payload/../x" has ".." as a whole component -- a real traversal
        # attempt that the per-component check must still reject.
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/../x", b"pwned")

        self._assert_rejected("path_traversal")

    # --- review fix #1: attacker member shapes raise ExtractError, never a raw OSError ---

    def test_file_then_directory_component_collision_is_bad_tar(self):
        # (a) "payload/subdir" is written as a regular FILE, then
        # "payload/subdir/evil" needs "subdir" to be a directory -- the
        # confined openat2(O_DIRECTORY) on the existing file fails ENOTDIR.
        # That must surface as ExtractError("bad_tar"), NOT a raw OSError.
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/subdir", b"i am a file")
            _add_regular(tar, "payload/subdir/evil", b"evil")

        self._assert_rejected("bad_tar")

    def test_directory_then_file_collision_is_bad_tar(self):
        # (b) the reverse: "payload/subdir/evil" creates "subdir" as a
        # DIRECTORY, then "payload/subdir" as a regular file collides with
        # it -- the confined openat2(O_WRONLY|O_CREAT) on the existing
        # directory fails EISDIR. Must be ExtractError("bad_tar").
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/subdir/evil", b"evil")
            _add_regular(tar, "payload/subdir", b"collides")

        self._assert_rejected("bad_tar")

    def test_trailing_slash_member_is_rejected(self):
        # (c) "payload/x/" has an empty trailing path component. Previously
        # this slipped past name validation and failed with a raw OSError
        # (ENOENT) at the write path; the per-component empty check now
        # rejects it up front as a malformed member name -> path_traversal
        # (still an ExtractError, never a raw OSError -- the point of the
        # contract fix).
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload/x/", b"data")

        self._assert_rejected("path_traversal")

    def test_doubled_slash_member_is_rejected(self):
        # (d) "payload//x" has an empty interior path component. Same story
        # as (c): once a raw-OSError (ENOENT) write-path failure, now
        # rejected up front by the empty-component check as path_traversal.
        with self._open_tar() as tar:
            _add_regular(tar, "manifest.json", b"{}")
            _add_regular(tar, "payload//x", b"data")

        self._assert_rejected("path_traversal")


if __name__ == "__main__":
    unittest.main()
