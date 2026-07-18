"""Tests for causb.commitlog: crash-atomic job commit + boot reconciliation
(spec S19 R7, D22, S7.8).

The load-bearing property under test is D22's replay guarantee: certs carry
`NotBefore=now` and are NOT reproducible, so a retry of an already-committed
`job_id` must redeliver the EXACT bytes committed the first time -- never
re-run, never re-write. Two crash points are exercised directly (not just
described in prose):

- "commit() crashed BEFORE writing DONE" is simulated by writing a job's
  outputs + status.json straight into results/<job_id>/ WITHOUT ever
  creating a DONE marker (`_plant_orphan_job_dir(with_done=False)`) --
  standing in for a process that died mid-commit. S19 R7: any such dir is
  discarded (job never happened).

- "commit() crashed AFTER DONE but before the seq/consumed-jobs cache
  update" is simulated by writing a fully-formed, valid DONE marker
  directly (`_plant_orphan_job_dir(with_done=True)`), bypassing commit()
  and its cache-bump step entirely, while seq/consumed-jobs stay at their
  pre-commit values. S19 R7: any dir WITH DONE is authoritative -- the
  caches must be rebuilt from it alone.

Both scenarios are handed to reconcile_on_boot() and asserted against the
exact outcome the design specifies.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import uuid
from unittest import mock

from causb import config
from causb.commitlog import _remove_tree, cached_result, commit, reconcile_on_boot


def _job_id():
    return str(uuid.uuid4())


class TestCommitlog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-commitlog-test-")
        self.state_dir = os.path.join(self.tmp, "state")
        self.results_dir = os.path.join(self.state_dir, "results")
        os.makedirs(self.results_dir)
        self._state_patcher = mock.patch.object(config, "STATE_DIR", self.state_dir)
        self._results_patcher = mock.patch.object(
            config, "RESULTS_DIR", self.results_dir
        )
        self._state_patcher.start()
        self._results_patcher.start()

    def tearDown(self):
        self._results_patcher.stop()
        self._state_patcher.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- test-local helpers --------------------------------------------

    def _read_seq(self):
        with open(os.path.join(self.state_dir, "seq")) as f:
            return int(f.read().strip())

    def _write_seq(self, value):
        with open(os.path.join(self.state_dir, "seq"), "w") as f:
            f.write(str(value))

    def _read_consumed(self):
        """Set view -- used where dedup doesn't matter to the assertion."""
        return set(self._read_consumed_lines())

    def _read_consumed_lines(self):
        """Raw line list (NOT deduped) -- used to prove no-duplicate-append."""
        try:
            with open(os.path.join(self.state_dir, "consumed-jobs")) as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def _plant_orphan_job_dir(self, job_id, *, with_done, done_seq=None):
        """Manually construct results/<job_id>/ WITHOUT ever calling
        commit() -- standing in for a crashed process. `with_done=False`
        simulates a crash BEFORE the DONE marker (outputs + status.json on
        disk, nothing else); `with_done=True` simulates a crash AFTER DONE
        but before the seq/consumed-jobs cache update (a fully-formed DONE
        marker, with the caches never touched by this helper)."""
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "status.json"), "w") as f:
            f.write('{"status": "ok"}')
        with open(os.path.join(job_dir, "cert.crt"), "wb") as f:
            f.write(b"orphaned-cert-bytes")
        if with_done:
            with open(os.path.join(job_dir, "DONE"), "w") as f:
                json.dump({"seq": done_seq}, f)
        return job_dir

    # --- commit + cached_result: the happy path -------------------------

    def test_commit_then_cached_result_returns_dir_with_identical_bytes(self):
        job_id = _job_id()
        cert_bytes = b"-----BEGIN CERTIFICATE-----\nfake-cert-bytes\n"
        outputs = [{"path": "host.crt", "data": cert_bytes}]
        out_status = {"schema_version": 1, "status": "ok", "box": "nebula-ca"}

        commit(job_id, 5, outputs, out_status)
        result_dir = cached_result(job_id)

        assert result_dir == os.path.join(self.results_dir, job_id)
        with open(os.path.join(result_dir, "host.crt"), "rb") as f:
            assert f.read() == cert_bytes
        with open(os.path.join(result_dir, "status.json")) as f:
            status = json.load(f)
        assert status["job_id"] == job_id
        assert status["seq"] == 5
        assert status["status"] == "ok"
        assert status["outputs"] == [
            {
                "path": "host.crt",
                "sha256": hashlib.sha256(cert_bytes).hexdigest(),
                "bytes": len(cert_bytes),
            }
        ]
        with open(os.path.join(result_dir, "DONE")) as f:
            assert json.load(f) == {"seq": 5}

    def test_cached_result_is_none_for_unknown_job_id(self):
        assert cached_result(_job_id()) is None

    def test_cached_result_is_none_for_job_dir_without_done(self):
        job_id = _job_id()
        self._plant_orphan_job_dir(job_id, with_done=False)

        assert cached_result(job_id) is None

    # --- reconcile_on_boot: purge vs keep -------------------------------

    def test_reconcile_purges_dir_without_done_and_leaves_seq_unchanged(self):
        self._write_seq(5)
        job_id = _job_id()
        job_dir = self._plant_orphan_job_dir(job_id, with_done=False)
        assert os.path.isdir(job_dir)

        reconcile_on_boot()

        assert not os.path.exists(job_dir)
        assert self._read_seq() == 5

    def test_reconcile_after_commit_leaves_job_intact_and_rebuilds_consumed_jobs(
        self,
    ):
        job_id = _job_id()
        commit(job_id, 3, [{"path": "out.txt", "data": b"payload"}], {"status": "ok"})
        # Corrupt the cache with a stale id from some long-gone job, to
        # prove reconcile REBUILDS consumed-jobs from disk rather than
        # trusting/preserving whatever was already cached.
        with open(os.path.join(self.state_dir, "consumed-jobs"), "w") as f:
            f.write("some-stale-job-id-from-a-deleted-dir\n")

        reconcile_on_boot()

        assert cached_result(job_id) == os.path.join(self.results_dir, job_id)
        with open(os.path.join(self.results_dir, job_id, "out.txt"), "rb") as f:
            assert f.read() == b"payload"
        assert self._read_consumed() == {job_id}  # stale entry dropped

    def test_reconcile_computes_max_seq_across_multiple_done_jobs(self):
        low_id, high_id = _job_id(), _job_id()
        commit(low_id, 2, [], {"status": "ok"})
        commit(high_id, 9, [], {"status": "ok"})
        self._write_seq(0)  # corrupt the cache to prove reconcile re-derives it

        reconcile_on_boot()

        assert self._read_seq() == 9
        assert self._read_consumed() == {low_id, high_id}

    # --- crash simulations (the report's required scenarios) -----------

    def test_crash_before_done_is_purged_by_reconcile(self):
        job_id = _job_id()
        job_dir = self._plant_orphan_job_dir(job_id, with_done=False)

        reconcile_on_boot()

        assert not os.path.exists(job_dir)
        assert cached_result(job_id) is None
        assert job_id not in self._read_consumed()

    def test_commit_retry_wipes_a_stale_partial_dir_from_an_earlier_crash(self):
        # A prior commit() attempt for this job_id crashed before DONE,
        # leaving an orphan file behind that the retry's `outputs` no
        # longer produces (e.g. the handler's output set changed between
        # attempts). The retry must not let that stale file survive
        # un-tracked alongside the fresh, actually-committed outputs.
        job_id = _job_id()
        self._plant_orphan_job_dir(job_id, with_done=False)
        stale_path = os.path.join(self.results_dir, job_id, "cert.crt")
        assert os.path.exists(stale_path)

        commit(job_id, 1, [{"path": "new.txt", "data": b"fresh"}], {"status": "ok"})

        result_dir = cached_result(job_id)
        assert not os.path.exists(stale_path)
        with open(os.path.join(result_dir, "new.txt"), "rb") as f:
            assert f.read() == b"fresh"

    def test_crash_after_done_before_cache_update_is_rebuilt_by_reconcile(self):
        job_id = _job_id()
        job_dir = self._plant_orphan_job_dir(job_id, with_done=True, done_seq=42)
        assert not os.path.exists(os.path.join(self.state_dir, "seq"))
        assert job_id not in self._read_consumed()

        reconcile_on_boot()

        assert self._read_seq() == 42
        assert self._read_consumed() == {job_id}
        assert cached_result(job_id) == job_dir
        with open(os.path.join(job_dir, "cert.crt"), "rb") as f:
            assert f.read() == b"orphaned-cert-bytes"

    # --- seq bump semantics ----------------------------------------------

    def test_commit_bumps_seq_to_jobs_seq(self):
        commit(_job_id(), 7, [], {"status": "ok"})

        assert self._read_seq() == 7

    def test_commit_does_not_regress_seq_below_current_max(self):
        commit(_job_id(), 10, [], {"status": "ok"})

        commit(_job_id(), 4, [], {"status": "ok"})  # a lower seq than current

        assert self._read_seq() == 10

    # --- idempotency: the crux of D22 -------------------------------------

    def test_second_commit_of_same_job_id_is_idempotent(self):
        job_id = _job_id()
        first_bytes = b"first-run-cert-bytes"
        commit(
            job_id, 1, [{"path": "host.crt", "data": first_bytes}], {"status": "ok"}
        )

        # Simulate a --retry: same job_id, a NEW (higher) seq, and freshly
        # "regenerated" (deliberately DIFFERENT) bytes -- exactly what a
        # second run of a NotBefore=now handler would produce. commit()
        # must ignore all of this and leave the original commit untouched.
        second_bytes = b"second-run-would-be-DIFFERENT-cert-bytes"
        commit(
            job_id, 99, [{"path": "host.crt", "data": second_bytes}], {"status": "ok"}
        )

        result_dir = cached_result(job_id)
        with open(os.path.join(result_dir, "host.crt"), "rb") as f:
            assert f.read() == first_bytes
        assert self._read_seq() == 1
        assert self._read_consumed_lines() == [job_id]  # present exactly once

    # --- defensive validation (path-safety of caller-supplied names) ----

    def test_reserved_output_filename_collision_is_rejected(self):
        with self.assertRaises(ValueError):
            commit(_job_id(), 1, [{"path": "status.json", "data": b"x"}], {})

    def test_job_id_with_path_separator_is_rejected(self):
        with self.assertRaises(ValueError):
            commit("../escape", 1, [], {})

    # --- review fix #1 [Critical]: RESULTS_DIR (job_dir's PARENT) is
    #     fsync'd so a power-loss cannot lose the newly-created job_dir
    #     entry (which would make reconcile re-run the handler -> a new
    #     NotBefore=now cert, defeating D22's identical-bytes replay). --

    def test_commit_fsyncs_results_dir_so_job_dir_entry_is_durable(self):
        # Structural guard: spy os.fsync and, via /proc/self/fd, record the
        # PATH each fsync'd fd points at. Assert RESULTS_DIR itself (not
        # only job_dir / the tmp files) was among them -- proving the
        # parent-directory fsync that makes the job_dir entry crash-durable
        # actually happens, so this can't silently regress.
        fsynced_paths = []
        real_fsync = os.fsync

        def spy_fsync(fd):
            try:
                fsynced_paths.append(os.readlink(f"/proc/self/fd/{fd}"))
            except OSError:
                pass
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=spy_fsync):
            commit(_job_id(), 1, [{"path": "x", "data": b"y"}], {"status": "ok"})

        real_results = os.path.realpath(self.results_dir)
        assert real_results in [os.path.realpath(p) for p in fsynced_paths], (
            f"RESULTS_DIR {real_results} was never fsync'd; "
            f"fsync'd paths were {fsynced_paths}"
        )

    def test_reconcile_fsyncs_state_dir_after_rebuilding_caches(self):
        # Same structural guard for reconcile's cache rebuild: STATE_DIR
        # must be fsync'd so the rebuilt seq/consumed-jobs entries survive
        # (belt-and-braces, but asserted so it can't silently regress).
        commit(_job_id(), 1, [], {"status": "ok"})
        fsynced_paths = []
        real_fsync = os.fsync

        def spy_fsync(fd):
            try:
                fsynced_paths.append(os.readlink(f"/proc/self/fd/{fd}"))
            except OSError:
                pass
            return real_fsync(fd)

        with mock.patch("os.fsync", side_effect=spy_fsync):
            reconcile_on_boot()

        real_state = os.path.realpath(self.state_dir)
        assert real_state in [os.path.realpath(p) for p in fsynced_paths], (
            f"STATE_DIR {real_state} was never fsync'd; "
            f"fsync'd paths were {fsynced_paths}"
        )

    # --- review fix #2 [Important]: wipe/purge must never follow a symlink
    #     planted at results/<job_id> and delete the TARGET's contents. --

    def _plant_symlinked_job_dir(self, job_id):
        """Create a sensitive target dir OUTSIDE results (standing in for
        e.g. CA_DIR) holding a secret, and a symlink at results/<job_id>
        pointing to it. Returns (target_dir, secret_path)."""
        target = os.path.join(self.tmp, "sensitive-ca-dir")
        os.mkdir(target)
        secret = os.path.join(target, "ca.key")
        with open(secret, "wb") as f:
            f.write(b"super-secret-ca-key-bytes")
        os.symlink(target, os.path.join(self.results_dir, job_id))
        return target, secret

    def test_commit_refuses_symlinked_job_dir_and_spares_target(self):
        job_id = _job_id()
        target, secret = self._plant_symlinked_job_dir(job_id)

        # commit() must fail CLOSED, never following the symlink to wipe or
        # write through it.
        with self.assertRaises(ValueError):
            commit(job_id, 1, [{"path": "x", "data": b"y"}], {"status": "ok"})

        # The symlink target's contents are untouched (nothing walked
        # THROUGH the link to delete them).
        assert os.path.isdir(target)
        with open(secret, "rb") as f:
            assert f.read() == b"super-secret-ca-key-bytes"

    def test_reconcile_refuses_symlinked_entry_and_spares_target(self):
        job_id = _job_id()
        target, secret = self._plant_symlinked_job_dir(job_id)
        link_path = os.path.join(self.results_dir, job_id)

        # reconcile must not follow the symlink: the target survives, the
        # symlink is left in place (not purged-through), and the entry is
        # NOT recorded as a consumed job.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            reconcile_on_boot()

        assert os.path.isdir(target)
        with open(secret, "rb") as f:
            assert f.read() == b"super-secret-ca-key-bytes"
        assert os.path.islink(link_path)  # symlink itself left untouched
        assert job_id not in self._read_consumed()
        assert "symlink" in err.getvalue().lower()

    # --- review fix #3 [Minor]: a negative seq in DONE is malformed. ------

    def test_negative_seq_in_done_is_treated_as_malformed(self):
        job_id = _job_id()
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "DONE"), "w") as f:
            json.dump({"seq": -5}, f)

        # A negative seq is not a valid commit marker (mirrors manifest.py's
        # seq >= 0 rule) -> not a cached result, and reconcile purges it.
        # (The DONE file IS present, just corrupt, so reconcile's purge
        # legitimately emits the fix-#4 data-loss warning -- redirected here
        # to keep the test output clean.)
        assert cached_result(job_id) is None
        with contextlib.redirect_stderr(io.StringIO()):
            reconcile_on_boot()
        assert not os.path.exists(job_dir)

    # --- review fix #4 [Minor]: corrupt-DONE purge emits a DISTINCT stderr
    #     line so an operator can tell data-loss-on-corruption from a
    #     cleanly-re-runnable never-started partial. --

    def test_corrupt_done_purge_warns_about_data_loss(self):
        job_id = _job_id()
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "cert.crt"), "wb") as f:
            f.write(b"real-committed-output")
        with open(os.path.join(job_dir, "DONE"), "w") as f:
            f.write("this is not valid json at all")  # corrupt marker

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            reconcile_on_boot()

        assert not os.path.exists(job_dir)  # still purged (no valid DONE)
        message = err.getvalue().lower()
        assert "corrupt" in message
        assert job_id in err.getvalue()

    def test_never_started_partial_purge_is_silent_about_corruption(self):
        job_id = _job_id()
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)  # a partial with NO DONE file at all
        with open(os.path.join(job_dir, "cert.crt"), "wb") as f:
            f.write(b"partial-output")

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            reconcile_on_boot()

        assert not os.path.exists(job_dir)  # purged, same as corrupt case
        # ...but NOT flagged as corruption/data-loss: nothing was ever
        # committed here, so this is an expected, silent cleanup.
        assert "corrupt" not in err.getvalue().lower()

    # --- final-review T7 minor: a symlink nested INSIDE a purge-candidate
    #     job dir must be UNLINKED (os.remove), never os.rmdir'd -- os.rmdir
    #     on a symlink-to-dir raises NotADirectoryError and would abort a
    #     WIRED boot reconcile (F2's ca-usb-reconcile.service) mid-scan, since
    #     that boot unit lacks the orchestrator's catch-all backstop. --

    def test_remove_tree_unlinks_a_nested_dir_symlink_and_spares_its_target(self):
        # A job dir containing a symlink pointing at an outside directory.
        # Before the fix os.rmdir(<symlink-to-dir>) raises NotADirectoryError
        # and _remove_tree aborts; after, the symlink is os.remove'd (unlinked
        # in place, never followed) and the outside target + its contents live.
        outside = os.path.join(self.tmp, "outside-target-dir")
        os.mkdir(outside)
        secret = os.path.join(outside, "keep.txt")
        with open(secret, "wb") as f:
            f.write(b"must-survive")
        job_dir = os.path.join(self.results_dir, _job_id())
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "status.json"), "w") as f:
            f.write("{}")
        os.symlink(outside, os.path.join(job_dir, "linkdir"))

        _remove_tree(job_dir)  # must NOT raise NotADirectoryError

        assert not os.path.exists(job_dir)      # whole job dir removed
        assert os.path.isdir(outside)           # symlink target dir spared
        with open(secret, "rb") as f:
            assert f.read() == b"must-survive"  # target contents spared

    def test_remove_tree_unlinks_a_nested_file_symlink_and_spares_its_target(self):
        # Regression guard for the already-correct file-symlink case (a
        # symlink-to-FILE was always classified into os.walk's `files` and
        # os.remove'd) -- pinned so the dir-symlink fix can't accidentally
        # regress it.
        outside_file = os.path.join(self.tmp, "outside-target-file")
        with open(outside_file, "wb") as f:
            f.write(b"file-must-survive")
        job_dir = os.path.join(self.results_dir, _job_id())
        os.makedirs(os.path.join(job_dir, "sub"))
        os.symlink(outside_file, os.path.join(job_dir, "sub", "linkfile"))

        _remove_tree(job_dir)  # must NOT raise, must not follow the symlink

        assert not os.path.exists(job_dir)
        with open(outside_file, "rb") as f:
            assert f.read() == b"file-must-survive"

    def test_reconcile_purges_a_partial_job_dir_that_contains_a_symlink(self):
        # The real boot scenario: a no-DONE partial (crash pre-DONE) whose dir
        # holds a stray nested symlink. reconcile_on_boot must purge the WHOLE
        # dir without aborting the scan (T7) and never follow the symlink.
        outside = os.path.join(self.tmp, "reconcile-outside")
        os.mkdir(outside)
        with open(os.path.join(outside, "canary"), "wb") as f:
            f.write(b"spared")
        job_id = _job_id()
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)  # no DONE -> purge candidate
        os.symlink(outside, os.path.join(job_dir, "nested-link"))

        with contextlib.redirect_stderr(io.StringIO()):
            reconcile_on_boot()  # must NOT raise NotADirectoryError

        assert not os.path.exists(job_dir)          # partial purged whole
        assert cached_result(job_id) is None
        assert os.path.isdir(outside)               # symlink target spared
        with open(os.path.join(outside, "canary"), "rb") as f:
            assert f.read() == b"spared"


if __name__ == "__main__":
    unittest.main()
