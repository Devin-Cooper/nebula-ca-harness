"""Tests for box/handlers/set-time: the "set-time" vetted handler (S8, R5;
CA operation handlers plan, Task 5). This handler repairs the box's clock
OFFLINE when the RTC coin cell dies -- it is the ONE operation exempt from
causb.freshness's year>=2026 clock-sanity gate (see test_freshness.py's own
R5 carve-out tests), so this suite's load-bearing property is the
CONVERSE: set-time itself still refuses an implausible TARGET time
(config.TIME_MIN/TIME_MAX), so a malicious or fat-fingered manifest cannot
rewind the box to an arbitrary date even though the gate that would
normally catch a bad CURRENT clock doesn't apply to this operation.

box/handlers/set-time is a standalone, extensionless script (like
box/handlers/backup-ca/ca-bootstrap/sign-hosts before it) -- loaded
in-process via importlib exactly like test_handler_ca_bootstrap.py's
`_load_ca_bootstrap_module()` precedent.

`clock_run` is injected as a fake recorder standing in for the WHOLE
"set system clock + persist to RTC" operation (production: a local
`_default_clock_run` shelling out to `date -u -s ...` then `hwclock
--systohc --utc`); `now` is injected as a zero-arg clock reader standing in
for `datetime.now(timezone.utc)`, so the "old" half of time-set.json is
deterministic under test. Neither fake ever shells out or touches the real
system clock.
"""

import json
import os
import subprocess
import tempfile
import unittest
import importlib.machinery
import importlib.util
from datetime import datetime, timezone
from unittest import mock

from causb import config

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SET_TIME_HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "set-time")

FIXED_OLD = datetime(2024, 3, 1, 8, 30, 0, tzinfo=timezone.utc)


def _load_set_time_module():
    loader = importlib.machinery.SourceFileLoader("set_time_handler_under_test", SET_TIME_HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _job(time_value="2026-06-15T12:00:00+00:00"):
    return {
        "job_id": "44444444-4444-4444-8444-444444444444",
        "operation": "set-time",
        "args": {} if time_value is None else {"time": time_value},
        "payload": [],
    }


class _FakeClockRun:
    """Stands in for the handler's `clock_run` DI seam -- the WHOLE
    "set system clock + persist to RTC" operation (module docstring).
    Records every call's target datetime; never touches the real clock."""

    def __init__(self, raise_exc=None):
        self.calls = []
        self.raise_exc = raise_exc

    def __call__(self, target_utc):
        self.calls.append(target_utc)
        if self.raise_exc is not None:
            raise self.raise_exc


class _SetTimeTestBase(unittest.TestCase):
    def setUp(self):
        self.mod = _load_set_time_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-set-time-test-")
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fixed_now(self):
        return FIXED_OLD

    def _run(self, job=None, clock=None, **overrides):
        clock = clock if clock is not None else _FakeClockRun()
        kwargs = dict(clock_run=clock, now=self._fixed_now)
        kwargs.update(overrides)
        rc = self.mod.run(job if job is not None else _job(), self.payload_dir, self.out_dir, **kwargs)
        return rc, clock

    def _time_set_json(self):
        with open(os.path.join(self.out_dir, "time-set.json")) as f:
            return json.load(f)


class TestTimeMinMaxConfigConstants(unittest.TestCase):
    """The exact literal values of config.TIME_MIN/TIME_MAX this handler's
    bounds check relies on -- pinned here (rather than in
    tests/unit/test_config.py, out of this task's authorized file list)
    since set-time is the one thing in this codebase that actually reads
    them."""

    def test_time_min_and_time_max_literals(self):
        self.assertEqual(config.TIME_MIN, "2026-01-01T00:00:00+00:00")
        self.assertEqual(config.TIME_MAX, "2050-01-01T00:00:00+00:00")


class TestHappyPath(_SetTimeTestBase):
    def test_plausible_target_returns_ok_and_calls_clock_run_with_parsed_time(self):
        rc, clock = self._run(job=_job("2026-06-15T12:00:00+00:00"))

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(clock.calls), 1)
        self.assertEqual(clock.calls[0], datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc))

    def test_writes_time_set_json_with_old_and_new(self):
        rc, _ = self._run(job=_job("2026-06-15T12:00:00+00:00"))

        self.assertEqual(rc, self.mod.EXIT_OK)
        payload = self._time_set_json()
        self.assertEqual(payload["old"], "2024-03-01T08:30:00Z")
        self.assertEqual(payload["new"], "2026-06-15T12:00:00Z")

    def test_accepts_z_suffix(self):
        rc, clock = self._run(job=_job("2026-06-15T12:00:00Z"))
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(clock.calls[0], datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc))

    def test_non_utc_offset_is_converted_to_utc_before_clock_run_and_json(self):
        # 12:00 at +05:00 is 07:00 UTC -- both the clock_run call and the
        # written time-set.json must reflect the CONVERTED value, not the
        # raw local literal.
        rc, clock = self._run(job=_job("2026-06-15T12:00:00+05:00"))

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(clock.calls[0], datetime(2026, 6, 15, 7, 0, 0, tzinfo=timezone.utc))
        payload = self._time_set_json()
        self.assertEqual(payload["new"], "2026-06-15T07:00:00Z")

    def test_exact_time_min_boundary_is_accepted(self):
        rc, clock = self._run(job=_job(config.TIME_MIN))
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(clock.calls), 1)

    def test_exact_time_max_boundary_is_accepted(self):
        rc, clock = self._run(job=_job(config.TIME_MAX))
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(clock.calls), 1)


class TestImplausibleTime(_SetTimeTestBase):
    def test_year_2020_is_implausible(self):
        rc, clock = self._run(job=_job("2020-01-01T00:00:00+00:00"))
        self.assertEqual(rc, self.mod.EXIT_IMPLAUSIBLE_TIME)
        self.assertEqual(clock.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_year_2200_is_implausible(self):
        rc, clock = self._run(job=_job("2200-01-01T00:00:00+00:00"))
        self.assertEqual(rc, self.mod.EXIT_IMPLAUSIBLE_TIME)
        self.assertEqual(clock.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_just_before_time_min_is_implausible(self):
        rc, clock = self._run(job=_job("2025-12-31T23:59:59+00:00"))
        self.assertEqual(rc, self.mod.EXIT_IMPLAUSIBLE_TIME)
        self.assertEqual(clock.calls, [])

    def test_just_after_time_max_is_implausible(self):
        rc, clock = self._run(job=_job("2050-01-01T00:00:01+00:00"))
        self.assertEqual(rc, self.mod.EXIT_IMPLAUSIBLE_TIME)
        self.assertEqual(clock.calls, [])

    def test_offset_that_converts_past_time_max_in_utc_is_implausible(self):
        # A local literal that LOOKS inside-bounds but converts outside them
        # in UTC must still be caught -- proves the bounds check happens
        # AFTER UTC conversion, not against the raw literal.
        rc, clock = self._run(job=_job("2049-12-31T23:00:00-02:00"))  # == 2050-01-01T01:00:00Z
        self.assertEqual(rc, self.mod.EXIT_IMPLAUSIBLE_TIME)
        self.assertEqual(clock.calls, [])


class TestBadManifest(_SetTimeTestBase):
    def test_malformed_iso_string_returns_bad_manifest(self):
        rc, clock = self._run(job=_job("not-a-timestamp"))
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(clock.calls, [])

    def test_missing_time_key_returns_bad_manifest(self):
        rc, clock = self._run(job=_job(None))
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(clock.calls, [])

    def test_non_string_time_value_returns_bad_manifest(self):
        rc, clock = self._run(job={"job_id": "x", "operation": "set-time", "args": {"time": 12345}, "payload": []})
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(clock.calls, [])

    def test_naive_datetime_without_tzinfo_returns_bad_manifest(self):
        # No explicit offset/Z -- ambiguous which timezone was meant, so
        # this handler refuses rather than guess (module docstring).
        rc, clock = self._run(job=_job("2026-06-15T12:00:00"))
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(clock.calls, [])

    def test_control_char_in_time_value_returns_bad_manifest(self):
        rc, clock = self._run(job=_job("2026-06-15T12:00:00+00:00\x00"))
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(clock.calls, [])

    def test_non_dict_args_returns_bad_manifest_not_a_crash(self):
        job = {"job_id": "x", "operation": "set-time", "args": ["not", "a", "dict"], "payload": []}
        rc, clock = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(clock.calls, [])

    def test_bad_manifest_leaves_no_time_set_json(self):
        rc, _ = self._run(job=_job("garbage"))
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(os.listdir(self.out_dir), [])


class TestClockFailure(_SetTimeTestBase):
    def test_clock_run_raising_clock_error_returns_clock_failed(self):
        clock = _FakeClockRun(raise_exc=self.mod.ClockError("clock_failed"))
        rc, _ = self._run(clock=clock)
        self.assertEqual(rc, self.mod.EXIT_CLOCK_FAILED)

    def test_clock_failure_leaves_no_time_set_json(self):
        clock = _FakeClockRun(raise_exc=self.mod.ClockError("clock_failed"))
        rc, _ = self._run(clock=clock)
        self.assertEqual(rc, self.mod.EXIT_CLOCK_FAILED)
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_clock_failure_does_not_wedge_a_retry(self):
        failing = _FakeClockRun(raise_exc=self.mod.ClockError("clock_failed"))
        first_rc, _ = self._run(clock=failing)
        self.assertEqual(first_rc, self.mod.EXIT_CLOCK_FAILED)

        retry = _FakeClockRun()
        second_rc, _ = self._run(clock=retry)
        self.assertEqual(second_rc, self.mod.EXIT_OK)
        self.assertEqual(len(retry.calls), 1)


class TestDefaultClockRun(unittest.TestCase):
    """Direct coverage of the handler's own local `_default_clock_run`
    default: exact two-step argv (date -u -s ..., then hwclock --systohc
    --utc), control-char rejection, and error mapping -- mirrors
    test_handler_backup_ca.py's identical discipline for its own local
    `_age_encrypt` wrapper."""

    def setUp(self):
        self.mod = _load_set_time_module()

    class _RecordingRunner:
        def __init__(self, outcomes):
            self._outcomes = list(outcomes)
            self.calls = []

        def __call__(self, argv, **kwargs):
            assert kwargs.get("shell") is not True, "must never use shell=True"
            self.calls.append((list(argv), kwargs))
            idx = min(len(self.calls) - 1, len(self._outcomes) - 1)
            outcome = self._outcomes[idx]
            if isinstance(outcome, BaseException):
                raise outcome
            rc, stdout, stderr = outcome
            return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=stderr)

    def test_builds_date_then_hwclock_argv_in_order(self):
        runner = self._RecordingRunner([(0, "", ""), (0, "", "")])
        target = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        self.mod._default_clock_run(target, runner=runner)

        self.assertEqual(len(runner.calls), 2)
        argv0, _ = runner.calls[0]
        argv1, _ = runner.calls[1]
        self.assertEqual(argv0, ["date", "-u", "-s", "2026-06-15T12:00:00Z"])
        self.assertEqual(argv1, ["hwclock", "--systohc", "--utc"])

    def test_date_step_nonzero_raises_clock_failed_and_skips_hwclock(self):
        runner = self._RecordingRunner([(1, "", "sensitive diagnostic")])
        target = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        with self.assertRaises(self.mod.ClockError) as cm:
            self.mod._default_clock_run(target, runner=runner)
        self.assertEqual(cm.exception.reason, "clock_failed")
        self.assertNotIn("sensitive diagnostic", str(cm.exception))
        self.assertEqual(len(runner.calls), 1)  # hwclock never attempted

    def test_hwclock_step_nonzero_raises_clock_failed(self):
        runner = self._RecordingRunner([(0, "", ""), (1, "", "")])
        target = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        with self.assertRaises(self.mod.ClockError) as cm:
            self.mod._default_clock_run(target, runner=runner)
        self.assertEqual(cm.exception.reason, "clock_failed")
        self.assertEqual(len(runner.calls), 2)

    def test_timeout_expired_maps_to_clock_failed(self):
        runner = self._RecordingRunner([subprocess.TimeoutExpired(cmd="date", timeout=30)])
        target = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(self.mod.ClockError) as cm:
            self.mod._default_clock_run(target, runner=runner)
        self.assertEqual(cm.exception.reason, "clock_failed")

    def test_file_not_found_maps_to_clock_failed(self):
        runner = self._RecordingRunner([FileNotFoundError()])
        target = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(self.mod.ClockError) as cm:
            self.mod._default_clock_run(target, runner=runner)
        self.assertEqual(cm.exception.reason, "clock_failed")


class TestMainShim(unittest.TestCase):
    def setUp(self):
        self.mod = _load_set_time_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-set-time-main-test-")
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_job_json(self, job):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump(job, f)
        return path

    def test_main_argv_contract_reads_job_json_and_runs(self):
        # _default_clock_run's own runner=subprocess.run default binds at
        # function-DEFINITION time (mirrors test_handler_backup_ca.py's
        # identical note) -- patch subprocess.run BEFORE this test's fresh
        # module load, not after.
        job_path = self._write_job_json(_job("2026-06-15T12:00:00+00:00"))
        calls = []

        def fake_runner(argv, **kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", fake_runner):
            mod = _load_set_time_module()  # fresh exec -- binds the patched runner above
            rc = mod.main(["set-time", job_path, self.payload_dir, self.out_dir])

        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:3], ["date", "-u", "-s"])
        self.assertEqual(calls[1], ["hwclock", "--systohc", "--utc"])
        with open(os.path.join(self.out_dir, "time-set.json")) as f:
            payload = json.load(f)
        self.assertEqual(payload["new"], "2026-06-15T12:00:00Z")
        # "old" reflects whatever the real wall clock was at call time --
        # just confirm it round-trips as a parseable ISO-Z stamp.
        self.assertTrue(payload["old"].endswith("Z"))
        datetime.strptime(payload["old"], "%Y-%m-%dT%H:%M:%SZ")

    def test_main_wrong_argc_returns_fault(self):
        rc = self.mod.main(["set-time", "only-one-arg"])
        self.assertEqual(rc, self.mod.EXIT_FAULT)

    def test_main_unparseable_job_json_returns_bad_manifest(self):
        path = os.path.join(self.tmp, "bad-job.json")
        with open(path, "w") as f:
            f.write("not json{{{")
        rc = self.mod.main(["set-time", path, self.payload_dir, self.out_dir])
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)


if __name__ == "__main__":
    unittest.main()
