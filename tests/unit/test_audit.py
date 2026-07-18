"""Tests for causb.audit: the shared append-only forensic audit writer
(design §4/§11). Both causb.dispatch (the run-script identity record, written
fail-CLOSED before a privileged exec) and box/bin/ca-usb-run (the per-job
terminal record, written fail-SAFE at each lifecycle terminal) append through
this single writer, so the on-disk JSONL line format can never drift between
the two call sites -- the whole point of factoring it out.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from causb import audit, config


class TestAudit(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="causb-audit-test-")
        os.close(fd)
        os.unlink(self.path)  # append() must create it fresh

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_append_writes_one_canonical_sorted_json_line(self):
        audit.append({"b": 2, "a": 1}, path=self.path)
        with open(self.path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        assert lines[0].endswith("\n")
        # Canonical serialization (sorted keys) so neither caller can format a
        # line the other's reader wouldn't recognize.
        assert lines[0] == '{"a": 1, "b": 2}\n'
        assert json.loads(lines[0]) == {"a": 1, "b": 2}

    def test_append_is_append_only_two_entries_two_lines(self):
        audit.append({"n": 1}, path=self.path)
        audit.append({"n": 2}, path=self.path)
        with open(self.path) as f:
            lines = [line for line in f if line.strip()]
        assert [json.loads(line)["n"] for line in lines] == [1, 2]

    def test_append_creates_file_mode_0600(self):
        audit.append({"x": 1}, path=self.path)
        assert (os.stat(self.path).st_mode & 0o777) == 0o600

    def test_append_defaults_to_config_audit_log(self):
        with mock.patch.object(config, "AUDIT_LOG", self.path):
            audit.append({"who": "default"})
        with open(self.path) as f:
            assert json.load(f) == {"who": "default"}

    def test_append_fsyncs_the_written_line(self):
        # A lost audit line after a crash defeats the forensic trail -- the
        # line must be fsync'd. Structural spy so it can't silently regress.
        seen = []
        real_fsync = os.fsync

        def spy(fd):
            seen.append(fd)
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=spy):
            audit.append({"x": 1}, path=self.path)
        assert seen, "append() must fsync the audit line"

    def test_writer_seam_gets_encoded_bytes_and_bypasses_the_path(self):
        captured = []
        audit.append({"k": "v"}, path=self.path, writer=captured.append)
        assert captured == [b'{"k": "v"}\n']
        assert not os.path.exists(self.path)  # the DI writer bypasses the real path

    def test_append_propagates_a_writer_failure(self):
        # append() must NOT swallow -- each caller decides its posture
        # (dispatch fail-CLOSED, ca-usb-run fail-SAFE).
        def boom(_data):
            raise OSError("simulated disk full")

        with self.assertRaises(OSError):
            audit.append({"x": 1}, writer=boom)


if __name__ == "__main__":
    unittest.main()
