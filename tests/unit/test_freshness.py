import shutil
import tempfile
import unittest
import uuid
from unittest import mock

from causb import config
from causb.freshness import check


def _manifest(**overrides):
    """Build a valid single-job manifest dict (the shape causb.manifest.parse()
    returns), overridable per-test. Mirrors test_manifest.py's builder --
    freshness.check() only reads box/seq/jobs[0].job_id, so this is a minimal
    but shape-accurate stand-in for a real parsed manifest."""
    manifest = {
        "schema_version": 1,
        "bundle_id": "bundle-1",
        "box": "nebula-ca",
        "seq": 7,
        "jobs": [
            {
                "job_id": str(uuid.uuid4()),
                "operation": "sign-hosts",
                "args": {},
                "payload": [],
                "entrypoint": None,
            }
        ],
    }
    manifest.update(overrides)
    return manifest


class TestFreshnessCheck(unittest.TestCase):
    """check() against a temp STATE_DIR (config.STATE_DIR monkeypatched per-test)
    so tests write throwaway seq/consumed-jobs files instead of touching the
    real /var/lib/nebula-ca."""

    def setUp(self):
        self.state_dir = tempfile.mkdtemp(prefix="causb-freshness-test-")
        self._patcher = mock.patch.object(config, "STATE_DIR", self.state_dir)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        shutil.rmtree(self.state_dir, ignore_errors=True)

    def _write_seq(self, value):
        with open(f"{self.state_dir}/seq", "w") as f:
            f.write(str(value))

    def _write_consumed(self, *job_ids):
        with open(f"{self.state_dir}/consumed-jobs", "w") as f:
            f.write("".join(f"{job_id}\n" for job_id in job_ids))

    def test_wrong_box_is_rejected(self):
        manifest = _manifest(box="not-nebula-ca")

        result = check(manifest, now_year=2026, op="sign-hosts")

        assert result == "wrong_box"

    def test_stale_seq_is_rejected(self):
        # No seq file written -> last_seq defaults to 0, but here we pin it
        # explicitly to exercise the "seq <= last (both present)" arm, not
        # just the absent-file default.
        self._write_seq(7)
        manifest = _manifest(seq=7)  # seq <= last_seq (7 <= 7)

        result = check(manifest, now_year=2026, op="sign-hosts")

        assert result == "stale_seq"

    def test_consumed_job_id_is_replay(self):
        job_id = str(uuid.uuid4())
        self._write_consumed(job_id)
        manifest = _manifest(seq=8)
        manifest["jobs"][0]["job_id"] = job_id

        result = check(manifest, now_year=2026, op="sign-hosts")

        assert result == "replay"

    def test_fresh_job_is_accepted(self):
        self._write_seq(7)
        self._write_consumed(str(uuid.uuid4()))  # unrelated, already-consumed id
        manifest = _manifest(seq=8)  # advances seq; job_id is a fresh uuid4

        result = check(manifest, now_year=2026, op="sign-hosts")

        assert result == "fresh"

    def test_insane_clock_is_rejected_for_normal_op(self):
        manifest = _manifest()

        result = check(manifest, now_year=2025, op="sign-hosts")

        assert result == "clock_insane"

    def test_set_time_is_exempt_from_clock_gate(self):
        # R5 carve-out: set-time's whole purpose is offline clock repair, so
        # it must not be gated on the very clock it exists to fix. With an
        # implausible now_year but op="set-time", check() must fall through
        # past the clock gate to the remaining seq/replay checks rather than
        # short-circuiting on clock_insane -- asserting the stronger "fresh"
        # (not just "!= clock_insane") also proves the rest of the pipeline
        # still runs normally for this op.
        manifest = _manifest()

        result = check(manifest, now_year=2025, op="set-time")

        assert result != "clock_insane"
        assert result == "fresh"

    def test_insane_clock_still_rejects_sign_hosts(self):
        # Sanity converse of the carve-out: an op OTHER than "set-time" gets
        # no exemption at all, even with an otherwise-pristine manifest --
        # the carve-out is op-scoped, not a global relaxation of the gate.
        manifest = _manifest()

        result = check(manifest, now_year=2025, op="sign-hosts")

        assert result == "clock_insane"

    def test_set_time_lookalike_ops_are_not_clock_exempt(self):
        # The carve-out must be an EXACT string match on "set-time", never a
        # prefix/substring/case-insensitive match -- else an attacker-named op
        # like "set-time-evil" (which dispatch's exact-filename lookup would
        # anyway refuse to resolve) could slip past the clock gate. Pin the
        # exact-match scoping so a future loosening (e.g. op.startswith(
        # "set-time")) is caught here, since freshness is meant to be an
        # independent gate, not one that leans on dispatch's lookup as backstop.
        manifest = _manifest()
        for op in ("set-time-evil", "set-time ", " set-time", "SET-TIME",
                   "set-timex", "xset-time", "settime"):
            result = check(manifest, now_year=2025, op=op)
            assert result == "clock_insane", f"{op!r} was wrongly clock-exempt"

    # -- R5 carve-out precision (task-5 brief / ledger: "untested"): the
    # exemption must bypass ONLY the clock check. The three tests below each
    # pair an INSANE clock with a DIFFERENT other-gate failure for
    # op="set-time" and assert that OTHER failure still fires -- proving the
    # carve-out cannot be (mis)implemented as a blanket "op=='set-time' ->
    # skip everything" short-circuit (e.g. an early `if op == "set-time":
    # return "fresh"` ahead of the box/seq/replay checks), which would
    # silently defeat wrong_box/stale_seq/replay protection for this one
    # operation. Order per check()'s own docstring is box -> clock(skipped)
    # -> seq -> replay, so each test below holds every check UPSTREAM of the
    # one under test at a passing value and leaves everything downstream at
    # its default-passing value too, isolating exactly one failure mode.

    def test_set_time_with_insane_clock_still_rejects_wrong_box(self):
        manifest = _manifest(box="not-nebula-ca")

        result = check(manifest, now_year=2025, op="set-time")

        assert result == "wrong_box"

    def test_set_time_with_insane_clock_still_rejects_stale_seq(self):
        self._write_seq(7)
        manifest = _manifest(seq=7)  # seq <= last_seq (7 <= 7)

        result = check(manifest, now_year=2025, op="set-time")

        assert result == "stale_seq"

    def test_set_time_with_insane_clock_still_rejects_replayed_job_id(self):
        job_id = str(uuid.uuid4())
        self._write_consumed(job_id)
        manifest = _manifest(seq=8)
        manifest["jobs"][0]["job_id"] = job_id

        result = check(manifest, now_year=2025, op="set-time")

        assert result == "replay"


if __name__ == "__main__":
    unittest.main()
