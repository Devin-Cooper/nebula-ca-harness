"""Tests for box/bin/ca-usb-run: the ca-usb-job@.service ExecStart/
ExecStopPost entrypoint (S4, S7, S19 R3; task 12).

ca-usb-run is a standalone, extensionless script (like mac/caj/mac/caj-recv,
see test_caj.py's docstring for the precedent) -- these tests both spawn it
via subprocess (real argv, as systemd would) for the parts that don't need
hardware, and load it in-process via importlib for white-box control-flow
tests with causb.led.set/causb.button.await_press mocked out (this file is
a STUB whose whole job -- see its own module docstring -- is to exercise the
REAL flock + led + button wiring; the real hardware calls themselves are
causb.led/causb.button's own tested responsibility (test_led.py,
test_button.py) and this project's root-integration suite
(tests/integration/hw_root.py), not re-proven here).

The single most safety-critical, least-obvious property this file pins down
is the EXIT-CODE CONTRACT documented at length in ca-usb-run's own module
docstring: every EXPECTED terminal outcome (busy / K1 timeout / success)
must return EXIT_OK, because a nonzero exit makes Type=oneshot's
ExecStopPost (LED -> IDLE) run essentially immediately regardless of
RemainAfterExit=yes -- verified against this box's real systemd 257 in the
task 12 report, not merely asserted here.
"""

import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid
from unittest import mock

from causb import audit as causb_audit
from causb import button as causb_button
from causb import collect as causb_collect  # noqa: F401 (real module, patched/used below)
from causb import commitlog as causb_commitlog
from causb import config as causb_config
from causb import dispatch as causb_dispatch
from causb import led as causb_led
from causb import mountctl as causb_mountctl
from causb import recovery as causb_recovery
from causb import registry as causb_registry

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_LIB = os.path.join(REPO_ROOT, "box", "lib")
CA_USB_RUN_PATH = os.path.join(REPO_ROOT, "box", "bin", "ca-usb-run")


def _load_ca_usb_run_module():
    """Import box/bin/ca-usb-run as an in-process module (see module
    docstring / test_caj.py's `_load_caj_module` precedent) so white-box
    tests can call its internal helpers and patch causb.led.set/
    causb.button.await_press before invoking run()/main(). ca-usb-run's own
    `sys.path.insert(0, "/usr/local/lib")` + `from causb import ...` run at
    import time exactly as they do standalone; `if __name__ == "__main__"`
    guards main() so importing has no side effects (no lock taken, no LED
    touched).
    """
    loader = importlib.machinery.SourceFileLoader("ca_usb_run_under_test", CA_USB_RUN_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _run_subprocess(argv, **kwargs):
    """Spawn ca-usb-run exactly as systemd's ExecStart=/ExecStopPost= would
    (real argv, real process) -- PYTHONPATH is set to this repo's box/lib so
    the run succeeds identically whether or not /usr/local/lib/causb (the
    real box's post-install location, task 11) happens to exist on the
    machine running this test; ca-usb-run's own hardcoded
    sys.path.insert(0, "/usr/local/lib") is simply an earlier, and on a dev
    machine empty, sys.path entry -- import falls through to PYTHONPATH's
    box/lib the same way it would fall through to nothing at all if that
    hardcoded path were removed. This does NOT weaken the check: on the
    real box /usr/local/lib/causb genuinely exists (task 11), so this same
    argv-level behavior is exercised there via the hardcoded path for real.
    """
    env = dict(os.environ, PYTHONPATH=BOX_LIB)
    return subprocess.run(
        [sys.executable, CA_USB_RUN_PATH] + argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        **kwargs,
    )


class TestArgvSubprocess(unittest.TestCase):
    """Real-process argv validation -- no hardware touched on this path."""

    def test_no_args_exits_nonzero_with_usage(self):
        result = _run_subprocess([])
        assert result.returncode != 0
        assert b"usage" in result.stderr.lower()

    def test_two_extra_args_exits_nonzero(self):
        result = _run_subprocess(["/dev/sda1", "extra"])
        assert result.returncode != 0


class TestAcquireLock(unittest.TestCase):
    """`_acquire_lock`/`_release_lock` against a REAL file + REAL flock(2)
    (fcntl.flock is POSIX, available for this test on any dev machine, not
    just the box) -- no mocking: this is the actual mechanism that has to
    serialize two concurrent ca-usb-job@ instances.
    """

    def setUp(self):
        self.mod = _load_ca_usb_run_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-lock-test-")
        self.lock_path = os.path.join(self.tmp, "lock")

    def tearDown(self):
        if os.path.exists(self.lock_path):
            os.unlink(self.lock_path)
        os.rmdir(self.tmp)

    def test_acquire_succeeds_and_is_a_real_exclusive_flock(self):
        fd = self.mod._acquire_lock(self.lock_path)
        self.assertIsNotNone(fd)
        try:
            # Prove it's a REAL flock, not just "returned a truthy fd": a
            # second, independent fd on the same path must fail LOCK_EX|NB.
            fd2 = os.open(self.lock_path, os.O_RDWR)
            try:
                with self.assertRaises(OSError):
                    fcntl.flock(fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd2)
        finally:
            self.mod._release_lock(fd)

    def test_second_acquire_while_held_returns_none_without_raising(self):
        fd1 = self.mod._acquire_lock(self.lock_path)
        self.assertIsNotNone(fd1)
        try:
            fd2 = self.mod._acquire_lock(self.lock_path)
            self.assertIsNone(fd2)
        finally:
            self.mod._release_lock(fd1)

    def test_acquire_succeeds_again_after_release(self):
        fd1 = self.mod._acquire_lock(self.lock_path)
        self.mod._release_lock(fd1)
        fd2 = self.mod._acquire_lock(self.lock_path)
        self.assertIsNotNone(fd2)
        self.mod._release_lock(fd2)

    def test_fd_is_close_on_exec(self):
        fd = self.mod._acquire_lock(self.lock_path)
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            assert flags & fcntl.FD_CLOEXEC, "lock fd must be O_CLOEXEC (S19 R3)"
        finally:
            self.mod._release_lock(fd)

    def test_non_contention_oserror_propagates(self):
        # A path whose parent directory doesn't exist is a real environment
        # fault (e.g. /run/ca-usb missing/misconfigured), not "busy" --
        # must raise, not silently return None.
        bad_path = os.path.join(self.tmp, "nonexistent-subdir", "lock")
        with self.assertRaises(OSError):
            self.mod._acquire_lock(bad_path)


class TestWipeTmpfs(unittest.TestCase):
    def setUp(self):
        self.mod = _load_ca_usb_run_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-tmpfs-test-")

    def tearDown(self):
        if os.path.isdir(self.tmp):
            for name in os.listdir(self.tmp):
                p = os.path.join(self.tmp, name)
                if os.path.isdir(p) and not os.path.islink(p):
                    os.rmdir(p)
                else:
                    os.unlink(p)
        os.rmdir(self.tmp)

    def test_clears_files_and_subdirs_but_keeps_the_directory_itself(self):
        with open(os.path.join(self.tmp, "job.tar"), "w") as f:
            f.write("x")
        os.mkdir(os.path.join(self.tmp, "payload"))
        with open(os.path.join(self.tmp, "payload", "script.sh"), "w") as f:
            f.write("x")

        self.mod._wipe_tmpfs(self.tmp)

        assert os.path.isdir(self.tmp), "the tmpfs mountpoint dir itself must survive"
        assert os.listdir(self.tmp) == []

    def test_missing_dir_does_not_raise(self):
        self.mod._wipe_tmpfs(os.path.join(self.tmp, "does-not-exist"))

    def test_does_not_follow_a_symlink_to_an_outside_target(self):
        outside = tempfile.mkdtemp(prefix="causb-tmpfs-outside-")
        victim = os.path.join(outside, "victim")
        with open(victim, "w") as f:
            f.write("do not touch")
        try:
            os.symlink(victim, os.path.join(self.tmp, "link"))
            self.mod._wipe_tmpfs(self.tmp)
            assert os.listdir(self.tmp) == [], "the symlink entry itself must be removed"
            assert os.path.exists(victim), "the symlink TARGET must be untouched"
        finally:
            os.unlink(victim)
            os.rmdir(outside)

    def test_listdir_failure_is_swallowed_not_propagated(self):
        # The dir passes the isdir() guard, but os.listdir itself raises (it
        # vanished / became inaccessible in the race window after the guard).
        # _wipe_tmpfs must swallow this exactly like a per-entry unlink
        # failure -- the try/except has to wrap os.listdir(), not just the
        # loop body -- so cleanup()/ExecStopPost never raises (see below).
        with mock.patch("os.listdir", side_effect=OSError("simulated listdir failure")):
            self.mod._wipe_tmpfs(self.tmp)  # must NOT raise


class TestRun(unittest.TestCase):
    """The one part of run()'s control flow that is NOT the full lifecycle and
    so survives task 16 unchanged: flock contention. A second concurrent
    instance must set the BUSY LED, touch no state, and exit 0 WITHOUT ever
    reaching the mount/verify/K1 pipeline.

    (The task-12 stub's other TestRun cases -- which asserted the STUB body's
    placeholder READY->button->RUNNING/ERROR->SAFE_REMOVE LED sequence with no
    mounting -- were necessarily REPLACED by task 16, because the stub's own
    docstring says task 16 "replaces run()'s body with the full mount->verify->
    K1->dispatch->commit->deliver pipeline." The real lifecycle LED sequences,
    lock-release-on-every-path, and fault handling are re-proven end to end in
    TestLifecycle below.)
    """

    def setUp(self):
        self.mod = _load_ca_usb_run_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-run-test-")
        self.lock_path = os.path.join(self.tmp, "lock")
        self.mod.LOCK_PATH = self.lock_path

    def tearDown(self):
        if os.path.exists(self.lock_path):
            os.unlink(self.lock_path)
        os.rmdir(self.tmp)

    def test_busy_path_sets_busy_led_never_touches_button_and_exits_ok(self):
        holder_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(holder_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with mock.patch.object(causb_led, "set") as led_set, \
                 mock.patch.object(causb_button, "await_press") as await_press, \
                 mock.patch.object(causb_mountctl, "mount_ro") as mount_ro:
                rc = self.mod.run("/dev/sda1")
            assert rc == self.mod.EXIT_OK
            led_set.assert_called_once_with(causb_led.BUSY)
            await_press.assert_not_called()
            mount_ro.assert_not_called()  # busy -> never even mounts
        finally:
            os.close(holder_fd)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.mod = _load_ca_usb_run_module()

    def test_cleanup_flag_resets_led_to_idle_and_wipes_configured_tmpfs_dir(self):
        tmp = tempfile.mkdtemp(prefix="causb-cleanup-test-")
        try:
            with open(os.path.join(tmp, "leftover"), "w") as f:
                f.write("x")
            self.mod.TMPFS_DIR = tmp
            with mock.patch.object(causb_led, "set") as led_set:
                rc = self.mod.main(["ca-usb-run", "--cleanup"])
            assert rc == self.mod.EXIT_OK
            led_set.assert_called_once_with(causb_led.IDLE)
            assert os.listdir(tmp) == []
        finally:
            if os.path.isdir(tmp):
                for name in os.listdir(tmp):
                    os.unlink(os.path.join(tmp, name))
                os.rmdir(tmp)

    def test_cleanup_never_raises_even_if_led_reset_fails(self):
        self.mod.TMPFS_DIR = "/nonexistent-for-test"
        with mock.patch.object(causb_led, "set", side_effect=causb_led.LedError("led_write_failed")):
            rc = self.mod.main(["ca-usb-run", "--cleanup"])
        assert rc == self.mod.EXIT_OK

    def test_cleanup_swallows_a_tmpfs_listdir_failure_end_to_end(self):
        # Full ExecStopPost path (main --cleanup -> cleanup() -> _wipe_tmpfs):
        # the tmpfs dir exists (passes isdir) but os.listdir raises. cleanup()
        # must still return EXIT_OK, not propagate the OSError -- ExecStopPost
        # must never fail for what is routine cleanup (module docstring).
        tmp = tempfile.mkdtemp(prefix="causb-cleanup-listdir-")
        try:
            self.mod.TMPFS_DIR = tmp
            with mock.patch.object(causb_led, "set"), \
                 mock.patch("os.listdir", side_effect=OSError("simulated listdir failure")):
                rc = self.mod.main(["ca-usb-run", "--cleanup"])
            assert rc == self.mod.EXIT_OK
        finally:
            os.rmdir(tmp)

    def test_wrong_argc_returns_fault_without_calling_run(self):
        with mock.patch.object(self.mod, "run") as run_mock:
            rc = self.mod.main(["ca-usb-run"])
        assert rc == self.mod.EXIT_FAULT
        run_mock.assert_not_called()

    def test_button_error_from_run_is_mapped_to_exit_fault(self):
        with mock.patch.object(self.mod, "run",
                                side_effect=causb_button.ButtonError("device_not_found")):
            rc = self.mod.main(["ca-usb-run", "/dev/sda1"])
        assert rc == self.mod.EXIT_FAULT

    def test_led_error_from_run_is_mapped_to_exit_fault(self):
        with mock.patch.object(self.mod, "run",
                                side_effect=causb_led.LedError("led_write_failed")):
            rc = self.mod.main(["ca-usb-run", "/dev/sda1"])
        assert rc == self.mod.EXIT_FAULT

    def test_bare_oserror_from_run_is_mapped_to_exit_fault(self):
        with mock.patch.object(self.mod, "run", side_effect=OSError("boom")):
            rc = self.mod.main(["ca-usb-run", "/dev/sda1"])
        assert rc == self.mod.EXIT_FAULT


class TestReconcileEntrypoint(unittest.TestCase):
    """`ca-usb-run --reconcile` -> commitlog.reconcile_on_boot() (F2 /
    R7 / D22 restart recovery; ca-usb-reconcile.service's ExecStart). Rebuilds
    the seq/consumed-jobs caches from the durable DONE markers and purges any
    pre-DONE partial job dir left by a power-cut mid-commit (§13.3), then exits
    0; EXIT_FAULT only on a genuine reconcile fault. Injected tmpdir STATE_DIR/
    RESULTS_DIR -- never the real /var/lib/nebula-ca (box-safe).
    """

    def setUp(self):
        self.mod = _load_ca_usb_run_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-reconcile-entry-")
        self.state_dir = os.path.join(self.tmp, "state")
        self.results_dir = os.path.join(self.state_dir, "results")
        self.ca_dir = os.path.join(self.state_dir, "ca")
        os.makedirs(self.results_dir)
        # CA_DIR/REGISTRY are ALSO injected (CAop-Task 8): --reconcile now
        # rebuilds registry.json too (after commitlog.reconcile_on_boot()),
        # so without this a test here would have the registry step reach
        # for the REAL config.REGISTRY default (/var/lib/nebula-ca/ca/
        # registry.json) -- it fails closed harmlessly (fail-safe, see
        # TestReconcileRegistryRebuild), but this project's own constraint is
        # to never even ATTEMPT to touch the real /var/lib/nebula-ca tree
        # from a test, so every path this entrypoint reads/writes is
        # injected here, not just the two commitlog needs.
        self._saved = {
            k: getattr(causb_config, k)
            for k in ("STATE_DIR", "RESULTS_DIR", "CA_DIR", "REGISTRY")
        }
        causb_config.STATE_DIR = self.state_dir
        causb_config.RESULTS_DIR = self.results_dir
        causb_config.CA_DIR = self.ca_dir
        causb_config.REGISTRY = os.path.join(self.ca_dir, "registry.json")

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(causb_config, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seq(self):
        with open(os.path.join(self.state_dir, "seq")) as f:
            return int(f.read().strip())

    def _plant_committed(self, job_id, seq):
        """Crash AFTER DONE but before the cache bump: a valid DONE marker
        written directly, caches untouched -- reconcile keeps it and rebuilds
        seq/consumed from it (mirrors test_commitlog's crash-after-DONE)."""
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "cert.crt"), "wb") as f:
            f.write(b"committed-bytes")
        with open(os.path.join(job_dir, "DONE"), "w") as f:
            json.dump({"seq": seq}, f)
        return job_dir

    def _plant_partial(self, job_id):
        """Crash BEFORE DONE: outputs on disk, no DONE -> purge candidate."""
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "cert.crt"), "wb") as f:
            f.write(b"partial-bytes")
        return job_dir

    def test_reconcile_on_clean_store_exits_ok_and_actually_reconciles(self):
        with mock.patch.object(causb_commitlog, "reconcile_on_boot",
                                wraps=causb_commitlog.reconcile_on_boot) as spy:
            rc = self.mod.main(["ca-usb-run", "--reconcile"])
        assert rc == self.mod.EXIT_OK
        spy.assert_called_once()
        assert self._seq() == 0  # empty store reconciles to seq 0, clean exit

    def test_reconcile_after_crash_purges_partial_keeps_committed_reconciles_seq(self):
        survivor = str(uuid.uuid4())
        partial = str(uuid.uuid4())
        survivor_dir = self._plant_committed(survivor, 9)
        partial_dir = self._plant_partial(partial)
        assert not os.path.exists(os.path.join(self.state_dir, "seq"))  # caches absent

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        assert not os.path.exists(partial_dir)          # pre-DONE partial purged
        assert os.path.isdir(survivor_dir)              # committed job survives
        with open(os.path.join(survivor_dir, "cert.crt"), "rb") as f:
            assert f.read() == b"committed-bytes"       # identical bytes, never re-run
        assert self._seq() == 9                         # seq reconciled from DONE
        assert causb_commitlog.cached_result(survivor) == survivor_dir

    def test_reconcile_dispatches_before_the_normal_run_lifecycle(self):
        # --reconcile is a DISTINCT boot entrypoint: it must never enter the
        # mount/flock/K1 lifecycle (run()).
        with mock.patch.object(self.mod, "run") as run_mock, \
             mock.patch.object(causb_commitlog, "reconcile_on_boot") as recon:
            rc = self.mod.main(["ca-usb-run", "--reconcile"])
        assert rc == self.mod.EXIT_OK
        recon.assert_called_once()
        run_mock.assert_not_called()

    def test_reconcile_failure_fails_closed_to_exit_fault(self):
        # A genuine reconcile fault (fsync/IO error) exits nonzero so the boot
        # journal surfaces a failed recovery rather than masking it.
        with mock.patch.object(causb_commitlog, "reconcile_on_boot",
                                side_effect=OSError("simulated reconcile IO fault")):
            rc = self.mod.main(["ca-usb-run", "--reconcile"])
        assert rc == self.mod.EXIT_FAULT


class TestReconcileRegistryRebuild(unittest.TestCase):
    """`ca-usb-run --reconcile`'s SECOND repair pass (CAop-Task 8, layered on
    top of `commitlog.reconcile_on_boot()` above): rebuild `registry.json`
    (R7) from every committed sign-hosts `alloc-<name>.json` allocation
    record still under `RESULTS_DIR`, so a power-loss between a sign-hosts
    commit and the box's next boot can never leave `registry.json` out of
    sync with the certs actually issued. Injected tmpdir RESULTS_DIR/
    REGISTRY/CA_DIR -- never the real /var/lib/nebula-ca (box-safe).
    """

    def setUp(self):
        self.mod = _load_ca_usb_run_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-reconcile-registry-")
        self.state_dir = os.path.join(self.tmp, "state")
        self.results_dir = os.path.join(self.state_dir, "results")
        self.ca_dir = os.path.join(self.state_dir, "ca")
        os.makedirs(self.results_dir)
        os.makedirs(self.ca_dir)
        self.registry_path = os.path.join(self.ca_dir, "registry.json")
        self._saved = {
            k: getattr(causb_config, k)
            for k in ("STATE_DIR", "RESULTS_DIR", "REGISTRY", "CA_DIR")
        }
        causb_config.STATE_DIR = self.state_dir
        causb_config.RESULTS_DIR = self.results_dir
        causb_config.REGISTRY = self.registry_path
        causb_config.CA_DIR = self.ca_dir

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(causb_config, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _plant_alloc(self, job_id, name, ip, *, seq, pubkey_sha256=None, fingerprint=None):
        # A DONE marker is REQUIRED here, not optional test decoration: this
        # test class's `reconcile()` call runs commitlog.reconcile_on_boot()
        # FIRST (see ca-usb-run's own docstring -- the registry rebuild is
        # the SECOND pass, ordered after it), and that first pass purges any
        # results/<job_id>/ directory that lacks a valid DONE marker (a
        # pre-DONE crash partial). A real sign-hosts job's alloc-<name>.json
        # never exists without DONE alongside it (both land in the same
        # commitlog.commit() batch) -- so a fixture missing DONE here isn't
        # "more minimal", it is testing a shape that cannot occur for real,
        # and commitlog would silently delete it before the registry step
        # ever got to scan it.
        job_dir = os.path.join(self.results_dir, job_id)
        os.makedirs(job_dir, exist_ok=True)
        rec = {
            "name": name,
            "ip": ip,
            "pubkey_sha256": pubkey_sha256 or f"sha-{name}",
            "fingerprint": fingerprint or f"fp-{name}",
            "not_after": "2027-01-01T00:00:00Z",
            "groups": [],
            "seq": seq,
        }
        with open(os.path.join(job_dir, f"alloc-{name}.json"), "w") as f:
            json.dump(rec, f)
        with open(os.path.join(job_dir, "DONE"), "w") as f:
            json.dump({"seq": seq}, f)
        return job_dir

    def _load_registry(self):
        with open(self.registry_path) as f:
            return json.load(f)

    def test_two_committed_alloc_records_rebuild_registry_with_both_hosts(self):
        self._plant_alloc("job-1", "host-a", "10.42.0.10", seq=1)
        self._plant_alloc("job-2", "host-b", "10.42.0.11", seq=2)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert reg["hosts"]["host-a"]["ip"] == "10.42.0.10"
        assert reg["hosts"]["host-b"]["ip"] == "10.42.0.11"
        assert reg["overlay_cidr"] == causb_config.OVERLAY_CIDR

    def test_corrupt_alloc_record_is_skipped_not_fatal(self):
        self._plant_alloc("job-good", "host-good", "10.42.0.10", seq=1)
        # A DONE marker here too -- otherwise commitlog.reconcile_on_boot's
        # OWN pre-existing pre-DONE-partial purge (which runs first) would
        # delete this whole dir before the registry scan ever saw the
        # corrupt file, and this test would pass for the wrong reason.
        bad_dir = os.path.join(self.results_dir, "job-bad")
        os.makedirs(bad_dir)
        with open(os.path.join(bad_dir, "alloc-host-bad.json"), "w") as f:
            f.write("{not valid json at all")
        with open(os.path.join(bad_dir, "DONE"), "w") as f:
            json.dump({"seq": 2}, f)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert "host-good" in reg["hosts"]
        assert "host-bad" not in reg["hosts"]

    def test_alloc_record_with_non_list_groups_is_skipped_not_fatal(self):
        # registry.reconcile() itself does `list(rec.get("groups") or [])` --
        # a TRUTHY, NON-ITERABLE "groups" (e.g. an int) makes THAT call raise
        # TypeError. Since reconcile() processes the whole batch of records
        # in one call, an unvalidated bad "groups" here would crash the
        # WHOLE rebuild (discarding every other, perfectly good record),
        # not just this one -- exactly the "single bad record must not abort
        # the whole reconcile" failure mode this handler must avoid. Proves
        # _valid_alloc_record catches this BEFORE it ever reaches
        # registry.reconcile().
        self._plant_alloc("job-good", "host-good", "10.42.0.10", seq=1)
        bad_dir = os.path.join(self.results_dir, "job-bad-groups")
        os.makedirs(bad_dir)
        rec = {
            "name": "host-bad-groups", "ip": "10.42.0.99",
            "pubkey_sha256": "sha-bad", "fingerprint": "fp-bad",
            "not_after": "2027-01-01T00:00:00Z",
            "groups": 5,  # corrupted: not a list
            "seq": 2,
        }
        with open(os.path.join(bad_dir, "alloc-host-bad-groups.json"), "w") as f:
            json.dump(rec, f)
        with open(os.path.join(bad_dir, "DONE"), "w") as f:
            json.dump({"seq": 2}, f)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert "host-good" in reg["hosts"]
        assert "host-bad-groups" not in reg["hosts"]

    def test_partial_alloc_record_missing_fields_is_skipped_not_fatal(self):
        self._plant_alloc("job-good", "host-good", "10.42.0.10", seq=1)
        # DONE marker required for the same reason as the corrupt case
        # above -- this dir must survive commitlog's own purge pass so the
        # registry scan is what's actually exercised.
        partial_dir = os.path.join(self.results_dir, "job-partial")
        os.makedirs(partial_dir)
        with open(os.path.join(partial_dir, "alloc-host-partial.json"), "w") as f:
            json.dump({"name": "host-partial"}, f)  # missing ip/seq/etc.
        with open(os.path.join(partial_dir, "DONE"), "w") as f:
            json.dump({"seq": 2}, f)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert "host-good" in reg["hosts"]
        assert "host-partial" not in reg["hosts"]

    def test_symlinked_alloc_entry_is_never_followed(self):
        # RESULTS_DIR is root:root 0700 and, in production, only ever
        # populated by commitlog.commit()'s own atomic tmp->rename writes
        # (never a symlink) -- but commitlog.reconcile_on_boot() (which
        # this scan runs immediately AFTER, over the exact same tree) still
        # treats a symlink where a real entry belongs as defense-in-depth,
        # never following/reading through it. This scan matches that same
        # posture for the alloc-*.json entries themselves: a symlink named
        # alloc-*.json pointing at some OTHER file on disk (however that
        # symlink could have gotten there) must be skipped, never opened --
        # both so a hostile/corrupted target can't get its bytes parsed as
        # a trusted allocation record, and so the "good" record alongside it
        # still survives the same batch.
        self._plant_alloc("job-good", "host-good", "10.42.0.10", seq=1)

        outside = os.path.join(self.tmp, "outside-target.json")
        with open(outside, "w") as f:
            json.dump({
                "name": "host-exfil", "ip": "10.42.0.66",
                "pubkey_sha256": "sha-exfil", "fingerprint": "fp-exfil",
                "not_after": "2027-01-01T00:00:00Z", "groups": [], "seq": 2,
            }, f)

        link_dir = os.path.join(self.results_dir, "job-symlink")
        os.makedirs(link_dir)
        os.symlink(outside, os.path.join(link_dir, "alloc-host-exfil.json"))
        with open(os.path.join(link_dir, "DONE"), "w") as f:
            json.dump({"seq": 2}, f)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert "host-good" in reg["hosts"]
        assert "host-exfil" not in reg["hosts"]

    def test_symlinked_job_dir_is_never_followed(self):
        # The exfil case the reviewer flagged: a SYMLINKED results/<job_id>
        # dir (as opposed to a symlinked alloc-*.json entry inside a real
        # job dir) pointing at an outside directory that holds a perfectly
        # well-formed alloc-*.json. os.path.isdir() FOLLOWS a symlink, so
        # without an islink-before-isdir skip on the job dir itself the scan
        # would descend into the outside target and read its alloc record as
        # trusted -- and the alloc file there is a REAL file (not a symlink),
        # so the per-FILE islink guard never fires. commitlog.reconcile_on_boot
        # (which runs first, over this same tree) lstat+S_ISLNK-skips such a
        # symlinked job entry and leaves it in place (never purged), so THIS
        # scan is what must refuse to follow it. Mutation-sensitive: delete
        # the islink-on-job-dir skip and host-exfil gets placed -> this fails.
        self._plant_alloc("job-good", "host-good", "10.42.0.10", seq=1)

        outside_dir = os.path.join(self.tmp, "outside-job")
        os.makedirs(outside_dir)
        with open(os.path.join(outside_dir, "alloc-host-exfil.json"), "w") as f:
            json.dump({
                "name": "host-exfil", "ip": "10.42.0.66",
                "pubkey_sha256": "sha-exfil", "fingerprint": "fp-exfil",
                "not_after": "2027-01-01T00:00:00Z", "groups": [], "seq": 2,
            }, f)
        with open(os.path.join(outside_dir, "DONE"), "w") as f:
            json.dump({"seq": 2}, f)

        os.symlink(outside_dir, os.path.join(self.results_dir, "job-symlink-dir"))

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert "host-good" in reg["hosts"]
        assert "host-exfil" not in reg["hosts"]

    def test_absent_alloc_file_referenced_by_nothing_is_a_non_issue(self):
        # A committed results job dir with no alloc-*.json at all (e.g. a
        # run-script job) contributes nothing and is not an error. DONE
        # marker included so this dir survives commitlog's own purge pass
        # (see _plant_alloc's comment) and genuinely reaches the registry
        # scan with zero matching files, rather than being purged first.
        job_dir = os.path.join(self.results_dir, "job-non-sign-hosts")
        os.makedirs(job_dir)
        with open(os.path.join(job_dir, "result.log"), "w") as f:
            f.write("hi\n")
        with open(os.path.join(job_dir, "DONE"), "w") as f:
            json.dump({"seq": 1}, f)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert reg["hosts"] == {}

    def test_empty_results_dir_exits_ok_and_writes_empty_registry(self):
        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert reg["hosts"] == {}

    def test_missing_results_dir_entirely_exits_ok_no_crash(self):
        shutil.rmtree(self.results_dir)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK

    def test_registry_rebuild_preserves_existing_overlay_cidr(self):
        # A registry.json already on file (e.g. from an earlier bootstrap
        # with a NON-default overlay) must have its overlay_cidr preserved
        # across a rebuild, never silently reset to config.OVERLAY_CIDR.
        with open(self.registry_path, "w") as f:
            json.dump({"overlay_cidr": "10.99.0.0/16", "hosts": {}}, f)
        self._plant_alloc("job-1", "host-a", "10.99.0.10", seq=1)

        rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        reg = self._load_registry()
        assert reg["overlay_cidr"] == "10.99.0.0/16"
        assert reg["hosts"]["host-a"]["ip"] == "10.99.0.10"

    def test_registry_reconcile_never_raises_even_if_save_fails(self):
        # Simulate an unexpected registry.save failure (e.g. a durability
        # fault): --reconcile must still exit 0 (fail-closed to a clean
        # skip) -- this NEW registry-rebuild step must never crash/fail the
        # boot unit, unlike commitlog.reconcile_on_boot's own established
        # EXIT_FAULT contract (untouched, tested above).
        self._plant_alloc("job-1", "host-a", "10.42.0.10", seq=1)
        with mock.patch.object(causb_registry, "save",
                                side_effect=OSError("simulated save fsync failure")):
            rc = self.mod.main(["ca-usb-run", "--reconcile"])
        assert rc == self.mod.EXIT_OK

    def test_reconcile_registry_runs_after_commitlog_reconcile(self):
        # Ordering: the registry rebuild must happen AFTER
        # commitlog.reconcile_on_boot(), not before/instead of it.
        call_order = []
        real_reconcile_on_boot = causb_commitlog.reconcile_on_boot
        real_registry_save = causb_registry.save

        def _tracking_reconcile_on_boot():
            call_order.append("commitlog")
            return real_reconcile_on_boot()

        def _tracking_save(reg, path):
            call_order.append("registry")
            return real_registry_save(reg, path)

        self._plant_alloc("job-1", "host-a", "10.42.0.10", seq=1)
        with mock.patch.object(causb_commitlog, "reconcile_on_boot",
                                side_effect=_tracking_reconcile_on_boot), \
             mock.patch.object(causb_registry, "save", side_effect=_tracking_save):
            rc = self.mod.main(["ca-usb-run", "--reconcile"])

        assert rc == self.mod.EXIT_OK
        assert call_order == ["commitlog", "registry"]


def _keygen(*args):
    subprocess.run(
        ["ssh-keygen", *args],
        check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


class TestLifecycle(unittest.TestCase):
    """End-to-end drive of the full S7 orchestrator with REAL
    verify/extract/manifest/freshness/collect/commitlog (ssh-keygen-signed
    crafted job.tars against injected tmpdir anchors + state), mocking only the
    genuinely un-unit-testable edges: the block-device mount/umount
    (mountctl.*), the K1 evdev button, the LED sysfs writes, `sync`, and -- for
    the run-script HAPPY path only -- `dispatch.run` (a real run-script needs
    root `setpriv`; its own real behavior is covered by test_dispatch.py). The
    cosign_failed negative uses the REAL `dispatch.run`, which raises BEFORE any
    exec, so "nothing runs as root" is proven for real.

    Requires Linux (causb.extract's openat2) + ssh-keygen -- i.e. the box.
    """

    def setUp(self):
        self.mod = _load_ca_usb_run_module()
        self.base = tempfile.mkdtemp(prefix="causb-lifecycle-")
        self.mp = os.path.join(self.base, "stick")
        os.makedirs(os.path.join(self.mp, "inbox"))
        self.state_dir = os.path.join(self.base, "state")
        os.makedirs(self.state_dir)
        self.results_dir = os.path.join(self.base, "results")
        os.makedirs(self.results_dir)
        self.tmpfs = os.path.join(self.base, "tmpfs")
        os.makedirs(self.tmpfs)

        # Point the orchestrator's path constants at the fake stick/tmpfs.
        self.mod.MNT_DIR = self.mp
        self.mod.TMPFS_DIR = self.tmpfs
        self.mod.LOCK_PATH = os.path.join(self.base, "lock")

        # Ephemeral ed25519 signer trio + anchor files (test_verify.py's shape).
        self.op_key = self._gen_key("op", "nebula-ca-operator")
        self.bg_key = self._gen_key("bg", "nebula-ca-breakglass")
        self.bad_key = self._gen_key("bad", "untrusted")
        self.allowed = os.path.join(self.base, "allowed_signers")
        self.breakglass = os.path.join(self.base, "breakglass_signers")
        self._write_signers(self.allowed, "nebula-ca-operator", self.op_key + ".pub")
        self._write_signers(self.breakglass, "nebula-ca-breakglass", self.bg_key + ".pub")

        # Inject the box paths the real modules read at call time.
        self._cfg_saved = {
            k: getattr(causb_config, k)
            for k in ("STATE_DIR", "RESULTS_DIR", "ALLOWED", "BREAKGLASS", "AUDIT_LOG")
        }
        causb_config.STATE_DIR = self.state_dir
        causb_config.RESULTS_DIR = self.results_dir
        causb_config.ALLOWED = self.allowed
        causb_config.BREAKGLASS = self.breakglass
        self.audit_log = os.path.join(self.base, "audit.log")
        causb_config.AUDIT_LOG = self.audit_log

        # LED recorder + the always-mocked hardware/IO edges.
        self.led_states = []
        self._patchers = []
        self._patch(causb_led, "set", lambda state, **kw: self.led_states.append(state))
        self.mount_ro = self._patch(causb_mountctl, "mount_ro")
        self.mount_rw = self._patch(causb_mountctl, "mount_rw")
        self.umount = self._patch(causb_mountctl, "umount")
        self._patch(self.mod, "_sync")

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        for k, v in self._cfg_saved.items():
            setattr(causb_config, k, v)
        shutil.rmtree(self.base, ignore_errors=True)

    # --- fixture helpers -------------------------------------------------

    def _patch(self, obj, name, new=None):
        p = mock.patch.object(obj, name) if new is None else mock.patch.object(obj, name, new)
        m = p.start()
        self._patchers.append(p)
        return m

    def _gen_key(self, name, comment):
        kp = os.path.join(self.base, name)
        _keygen("-t", "ed25519", "-N", "", "-C", comment, "-f", kp, "-q")
        return kp

    @staticmethod
    def _signers_line(principal, pub_path):
        with open(pub_path) as f:
            keytype, b64 = f.read().split()[:2]
        return f"{principal} {keytype} {b64} {principal}\n"

    def _write_signers(self, path, principal, pub_path):
        with open(path, "w") as f:
            f.write(self._signers_line(principal, pub_path))

    def _manifest(self, *, job_id=None, seq=1, operation="run-script",
                  payload=None, entrypoint="script.sh", args=None,
                  box="nebula-ca", bundle_id="bundle-1", jobs=None):
        if jobs is not None:  # caller supplies the full jobs[] (e.g. jobs>1)
            return {"schema_version": 1, "bundle_id": bundle_id, "box": box,
                    "seq": seq, "jobs": jobs}
        job = {
            "job_id": job_id or str(uuid.uuid4()),
            "operation": operation,
            "payload": payload if payload is not None else ["script.sh"],
        }
        if entrypoint is not None:
            job["entrypoint"] = entrypoint
        if args is not None:
            job["args"] = args
        return {"schema_version": 1, "bundle_id": bundle_id, "box": box,
                "seq": seq, "jobs": [job]}

    def _build_tar(self, tar_path, manifest_obj, payload_files):
        stage = tempfile.mkdtemp(dir=self.base)
        mpath = os.path.join(stage, "manifest.json")
        with open(mpath, "wb") as f:
            f.write(json.dumps(manifest_obj).encode())
        with tarfile.open(tar_path, "w") as tf:  # uncompressed (extract needs r:)
            tf.add(mpath, arcname="manifest.json")
            if payload_files:
                pdir = os.path.join(stage, "payload")
                os.makedirs(pdir)
                for name, data in payload_files.items():
                    fp = os.path.join(pdir, name)
                    with open(fp, "wb") as f:
                        f.write(data)
                    tf.add(fp, arcname=f"payload/{name}")

    def _sign_into(self, tar_path, key, out_sig):
        # ssh-keygen -Y sign always writes "<input>.sig", so sign a throwaway
        # COPY (identical bytes -> the detached sig is valid over tar_path) and
        # move the result to out_sig. This lets the primary job.tar.sig and the
        # break-glass job.tar.bg.sig coexist over the SAME job.tar without the
        # second signing clobbering the first's <tar>.sig (test_verify.py's
        # same "sign a per-call copy" trick, R6's two-sigs-over-one-tar shape).
        copy = out_sig + ".signing"
        shutil.copyfile(tar_path, copy)
        try:
            _keygen("-Y", "sign", "-f", key, "-n", "nebula-ca-job", copy)
            os.replace(copy + ".sig", out_sig)
        finally:
            if os.path.exists(copy):
                os.unlink(copy)

    def _place(self, manifest_obj, payload_files=None, *, sign_key=None,
               bg_key=None, omit_sig=False):
        if payload_files is None:
            payload_files = {"script.sh": b"echo hi\n"}
        inbox = os.path.join(self.mp, "inbox")
        tar = os.path.join(inbox, "job.tar")
        self._build_tar(tar, manifest_obj, payload_files)
        if not omit_sig:
            self._sign_into(tar, sign_key or self.op_key, os.path.join(inbox, "job.tar.sig"))
        if bg_key is not None:
            self._sign_into(tar, bg_key, os.path.join(inbox, "job.tar.bg.sig"))
        return manifest_obj["jobs"][0]["job_id"]

    def _fake_dispatch(self, outputs=None, rc=0):
        """A dispatch.run stand-in: records the call, writes `outputs` (name->
        bytes) into out_dir, returns `rc`. Default writes result.log. Accepts
        the F-a `bg_authorized` keyword (the real dispatch.run now takes it) and
        records it so tests can assert the orchestrator threaded a real bool."""
        outputs = {"result.log": b"hi\n"} if outputs is None else outputs
        self.dispatch_calls = []

        def _run(operation, job, payload_dir, out_dir, cosigned, bg_authorized=False):
            self.dispatch_calls.append(
                {"operation": operation, "cosigned": cosigned,
                 "bg_authorized": bg_authorized, "payload_dir": payload_dir}
            )
            for name, data in outputs.items():
                with open(os.path.join(out_dir, name), "wb") as f:
                    f.write(data)
            return rc

        return _run

    def _outbox_json(self, *parts):
        with open(os.path.join(self.mp, "outbox", *parts)) as f:
            return json.load(f)

    def _committed(self, job_id):
        return os.path.exists(os.path.join(self.results_dir, job_id, "DONE"))

    def _assert_no_delivery(self):
        outbox = os.path.join(self.mp, "outbox")
        latest = os.path.join(outbox, "LATEST.json")
        self.assertFalse(os.path.exists(latest), "nothing must be delivered to the outbox")

    def _audit_lines(self):
        """Parse the injected audit.log into a list of dicts (each line valid
        JSON), asserting every line carries the fixed field shape + a status
        drawn only from the R10a status/enum vocabulary already in use (the
        status.json.error enum plus the "ok" success sentinel) -- F1.4."""
        vocab = set(self.mod._ERROR_ENUM) | {"ok"}
        if not os.path.exists(self.audit_log):
            return []
        out = []
        with open(self.audit_log) as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)  # raises if not valid JSON
                for k in ("ts", "job_id", "operation", "principal", "status",
                          "seq", "replayed", "exit_code", "cosigned"):
                    self.assertIn(k, entry, f"audit line missing field {k!r}: {entry}")
                self.assertIn(entry["status"], vocab,
                              f"audit status not in R10a vocab: {entry['status']!r}")
                out.append(entry)
        return out

    # --- happy path ------------------------------------------------------

    def test_happy_path_run_script_echo_commits_and_delivers(self):
        m = self._manifest(seq=5, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh")
        job_id = self._place(m, {"script.sh": b"echo hi\n"})
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(
            self.led_states,
            [causb_led.VERIFYING, causb_led.READY, causb_led.RUNNING, causb_led.SAFE_REMOVE],
        )
        # dispatch saw a REAL bool cosigned=False for a non-privileged op.
        self.assertIs(self.dispatch_calls[0]["cosigned"], False)
        # committed on-box first, seq bumped.
        self.assertTrue(self._committed(job_id))
        with open(os.path.join(self.state_dir, "seq")) as f:
            self.assertEqual(f.read().strip(), "5")
        # delivered: outbox/<job_id>/{status.json,result.log} + LATEST.json.
        latest = self._outbox_json("LATEST.json")
        self.assertEqual(latest["job_id"], job_id)
        self.assertEqual(latest["status"], "ok")
        self.assertEqual(latest["seq"], 5)
        self.assertIs(latest["replayed"], False)
        st = self._outbox_json(job_id, "status.json")
        self.assertEqual(st["status"], "ok")
        self.assertIsNone(st["error"])
        self.assertIs(st["replayed"], False)
        self.assertIs(st["presence_confirmed"], True)
        self.assertEqual(st["exit_code"], 0)
        with open(os.path.join(self.mp, "outbox", job_id, "result.log"), "rb") as f:
            self.assertEqual(f.read(), b"hi\n")
        outs = {o["path"]: o for o in st["outputs"]}
        self.assertEqual(outs["result.log"]["sha256"], hashlib.sha256(b"hi\n").hexdigest())
        # DONE marker is box-internal: never delivered to the stick.
        self.assertFalse(os.path.exists(os.path.join(self.mp, "outbox", job_id, "DONE")))

    def test_orchestrator_stamps_manifest_seq_onto_job_before_dispatch(self):
        # Option A seq-threading (task 4 review): ca-usb-run must stamp the
        # manifest's top-level monotonic `seq` onto the job dict BEFORE
        # dispatch.run, so a vetted handler whose job.json dispatch serializes
        # (e.g. sign-hosts) can read it as job["seq"]. The manifest schema
        # keeps seq at the top level (NOT inside a job), so absent this stamp
        # the handler would never see it. Capture the exact job dict dispatch
        # received and assert it now carries seq == the manifest's seq.
        captured = {}

        def _capturing_dispatch(operation, job, payload_dir, out_dir, cosigned,
                                bg_authorized=False):
            captured["job"] = dict(job)  # snapshot at dispatch time
            with open(os.path.join(out_dir, "result.log"), "wb") as f:
                f.write(b"hi\n")
            return 0

        m = self._manifest(seq=11, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh")
        self._place(m, {"script.sh": b"echo hi\n"})
        self._patch(causb_dispatch, "run", _capturing_dispatch)
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertIn("job", captured)
        self.assertEqual(captured["job"]["seq"], 11)
        # The manifest's job entry itself never carried seq (it lives at the
        # manifest top level) -- so this value can only have arrived via the
        # orchestrator's stamp.
        self.assertEqual(m["seq"], 11)
        self.assertNotIn("seq", m["jobs"][0])

    # --- replay (R10e) ---------------------------------------------------

    def _seed_committed(self, job_id, seq, outputs):
        out_status = self.mod._build_out_status(
            "ok", presence_confirmed=True, exit_code=0, error=None,
            started=self.mod._utcnow(), finished=self.mod._utcnow(),
        )
        causb_commitlog.commit(
            job_id, seq, [{"path": n, "data": d} for n, d in outputs.items()], out_status
        )

    def test_replay_delivers_identical_cached_bytes_without_rerunning(self):
        job_id = str(uuid.uuid4())
        self._seed_committed(job_id, 5, {"result.log": b"hi\n"})  # first run, seq 5
        # `caj --retry`: SAME job_id, HIGHER seq.
        m = self._manifest(job_id=job_id, seq=6, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh")
        self._place(m, {"script.sh": b"echo hi\n"})
        # remove the first delivery to prove replay RE-creates it.
        shutil.rmtree(os.path.join(self.mp, "outbox"), ignore_errors=True)

        sentinel = mock.MagicMock(side_effect=AssertionError("dispatch must NOT run on replay"))
        self._patch(causb_dispatch, "run", sentinel)
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        sentinel.assert_not_called()  # the handler did NOT re-run
        self.assertEqual(
            self.led_states,
            [causb_led.VERIFYING, causb_led.READY, causb_led.RUNNING, causb_led.SAFE_REMOVE],
        )
        latest = self._outbox_json("LATEST.json")
        self.assertIs(latest["replayed"], True)
        self.assertEqual(latest["job_id"], job_id)
        self.assertEqual(latest["seq"], 5)  # the CACHED (original) seq, not 6
        st = self._outbox_json(job_id, "status.json")
        self.assertIs(st["replayed"], True)
        self.assertEqual(st["status"], "ok")
        with open(os.path.join(self.mp, "outbox", job_id, "result.log"), "rb") as f:
            self.assertEqual(f.read(), b"hi\n")  # byte-identical cached output

    def test_replay_without_k1_does_not_deliver_and_leaves_cache(self):
        job_id = str(uuid.uuid4())
        self._seed_committed(job_id, 5, {"result.log": b"hi\n"})
        m = self._manifest(job_id=job_id, seq=6)
        self._place(m, {"script.sh": b"echo hi\n"})
        shutil.rmtree(os.path.join(self.mp, "outbox"), ignore_errors=True)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("no dispatch on replay")))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=False))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states[-1], causb_led.ERROR)
        self._assert_no_delivery()
        self.assertTrue(self._committed(job_id))  # cache retained for a later retry

    # --- negatives: each fail-closed, nothing runs, nothing committed ----

    def _run_expecting_pre_freshness_fail(self, expect_dispatch_patched=True):
        if expect_dispatch_patched:
            self.dispatch = self._patch(
                causb_dispatch, "run",
                mock.MagicMock(side_effect=AssertionError("dispatch must not run")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("K1 must not be reached")))
        return self.mod.run("/dev/sda1")

    def test_unsigned_job_is_verify_failed_led_only(self):
        m = self._manifest(seq=1)
        self._place(m, omit_sig=True)
        rc = self._run_expecting_pre_freshness_fail()
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self.assertNotIn(causb_led.READY, self.led_states)  # never reached K1
        self._assert_no_delivery()
        self.assertEqual(os.listdir(self.results_dir), [])  # nothing committed

    def test_wrong_key_signature_is_verify_failed(self):
        m = self._manifest(seq=1)
        self._place(m, sign_key=self.bad_key)  # signed by an untrusted key
        rc = self._run_expecting_pre_freshness_fail()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self._assert_no_delivery()
        self.assertEqual(os.listdir(self.results_dir), [])

    def test_stale_seq_is_rejected(self):
        prior = str(uuid.uuid4())
        self._seed_committed(prior, 5, {"result.log": b"x"})  # last-seq now 5
        m = self._manifest(seq=5)  # seq <= last
        self._place(m)
        rc = self._run_expecting_pre_freshness_fail()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self._assert_no_delivery()

    def test_wrong_box_is_rejected(self):
        m = self._manifest(seq=1, box="not-nebula-ca")
        self._place(m)
        rc = self._run_expecting_pre_freshness_fail()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self._assert_no_delivery()

    def test_jobs_gt_1_is_rejected(self):
        two = [
            {"job_id": str(uuid.uuid4()), "operation": "run-script",
             "payload": ["script.sh"], "entrypoint": "script.sh"},
            {"job_id": str(uuid.uuid4()), "operation": "run-script",
             "payload": ["script.sh"], "entrypoint": "script.sh"},
        ]
        m = self._manifest(seq=1, jobs=two)
        self._place(m)
        rc = self._run_expecting_pre_freshness_fail()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self._assert_no_delivery()

    def test_malformed_manifest_is_bad_manifest(self):
        m = self._manifest(seq=1)
        m["schema_version"] = 2  # unknown schema -> bad_manifest at parse
        self._place(m)
        rc = self._run_expecting_pre_freshness_fail()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self._assert_no_delivery()

    def test_privileged_without_cosign_is_cosign_failed_nothing_runs_as_root(self):
        # REAL dispatch.run here: it raises DispatchError("cosign_failed") BEFORE
        # any exec, so "nothing runs as root" is genuine, not mocked away.
        m = self._manifest(seq=1, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh",
                           args={"privileged": True})
        job_id = self._place(m, {"script.sh": b"echo hi\n"})  # NO .bg.sig
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        # K1 was confirmed + dispatch attempted, then refused: RUNNING then ERROR.
        self.assertEqual(
            self.led_states,
            [causb_led.VERIFYING, causb_led.READY, causb_led.RUNNING, causb_led.ERROR],
        )
        self.assertFalse(self._committed(job_id))  # refused before exec -> no commit
        self._assert_no_delivery()

    def test_valid_breakglass_cosign_sets_cosigned_true(self):
        # Distinct operator + breakglass keys (R6 disjoint sets); both sign the
        # SAME job.tar. verify_cosign (the real 4-arg call) must pass -> the
        # orchestrator passes cosigned=True (a real bool) into dispatch.
        m = self._manifest(seq=1, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh",
                           args={"privileged": True})
        self._place(m, {"script.sh": b"echo hi\n"}, bg_key=self.bg_key)
        self._patch(causb_dispatch, "run", self._fake_dispatch())  # mock: real would need root
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertIs(self.dispatch_calls[0]["cosigned"], True)  # a real True, not truthy

    # --- on-stick pre-commit error breadcrumb (outbox/ERROR.json) --------
    # A failure AFTER signature verification but BEFORE commit leaves a
    # bounded, structured breadcrumb on the (authenticated) stick so it is
    # troubleshootable once the box is air-gapped and only the LED talks.
    # Unauthenticated failures (mount/verify) stay strictly LED-only.

    def _breadcrumb_path(self):
        return os.path.join(self.mp, "outbox", "ERROR.json")

    def _error_json(self):
        with open(self._breadcrumb_path()) as f:
            return json.load(f)

    def _assert_no_breadcrumb(self):
        self.assertFalse(os.path.exists(self._breadcrumb_path()),
                         "no ERROR.json breadcrumb must be written")

    def _assert_breadcrumb_shape(self, bc, *, reason, phase):
        self.assertEqual(bc["schema_version"], causb_config.SCHEMA_VERSIONS["error"])
        self.assertEqual(bc["box"], "nebula-ca")
        self.assertEqual(bc["reason"], reason)
        self.assertIn(bc["reason"], self.mod._ERROR_ENUM)  # only R10a vocabulary
        self.assertEqual(bc["phase"], phase)
        self.assertIn(bc["phase"], causb_config.ERROR_PHASES)
        self.assertRegex(bc["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_extract_failure_writes_breadcrumb_extract_phase_null_ids(self):
        # A signed but non-tar payload: verify passes, extract fails (bad_tar
        # -> bad_manifest). Pre-parse -> job_id/seq/bundle_id are null.
        inbox = os.path.join(self.mp, "inbox")
        tar = os.path.join(inbox, "job.tar")
        with open(tar, "wb") as f:
            f.write(b"this is definitely not a valid tar archive\n")
        self._sign_into(tar, self.op_key, os.path.join(inbox, "job.tar.sig"))

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states[-1], causb_led.ERROR)
        self._assert_no_delivery()  # no LATEST.json (no commit)
        bc = self._error_json()
        self._assert_breadcrumb_shape(bc, reason="bad_manifest", phase="extract")
        self.assertIsNone(bc["job_id"])
        self.assertIsNone(bc["seq"])
        self.assertIsNone(bc["bundle_id"])
        self.assertEqual(os.listdir(self.results_dir), [])  # seq NOT consumed

    def test_manifest_parse_failure_writes_breadcrumb_manifest_phase(self):
        m = self._manifest(seq=1)
        m["schema_version"] = 2  # unknown schema -> bad_manifest at parse
        self._place(m)

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        bc = self._error_json()
        self._assert_breadcrumb_shape(bc, reason="bad_manifest", phase="manifest")
        self._assert_no_delivery()

    def test_jobs_gt_1_writes_breadcrumb_manifest_phase(self):
        two = [
            {"job_id": str(uuid.uuid4()), "operation": "run-script",
             "payload": ["script.sh"], "entrypoint": "script.sh"},
            {"job_id": str(uuid.uuid4()), "operation": "run-script",
             "payload": ["script.sh"], "entrypoint": "script.sh"},
        ]
        m = self._manifest(seq=1, jobs=two)
        self._place(m)

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        bc = self._error_json()
        self._assert_breadcrumb_shape(bc, reason="jobs_gt_1", phase="manifest")

    def test_freshness_failure_writes_breadcrumb_freshness_phase_with_ids(self):
        m = self._manifest(seq=1, box="not-nebula-ca")  # wrong_box, post-parse
        job_id = m["jobs"][0]["job_id"]
        self._place(m)

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        bc = self._error_json()
        self._assert_breadcrumb_shape(bc, reason="wrong_box", phase="freshness")
        self.assertEqual(bc["job_id"], job_id)   # manifest parsed -> populated
        self.assertEqual(bc["seq"], 1)
        self.assertEqual(bc["bundle_id"], "bundle-1")
        self._assert_no_delivery()
        self.assertEqual(os.listdir(self.results_dir), [])  # seq NOT consumed

    def test_dispatch_refused_cosign_failed_writes_breadcrumb_dispatch_phase(self):
        m = self._manifest(seq=1, operation="run-script", payload=["script.sh"],
                           entrypoint="script.sh", args={"privileged": True})
        job_id = self._place(m, {"script.sh": b"echo hi\n"})  # NO .bg.sig
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        bc = self._error_json()
        self._assert_breadcrumb_shape(bc, reason="cosign_failed", phase="dispatch")
        self.assertEqual(bc["job_id"], job_id)
        self.assertEqual(bc["seq"], 1)
        self.assertFalse(self._committed(job_id))  # refused before exec
        self._assert_no_delivery()

    def test_unsigned_job_writes_no_breadcrumb_led_only(self):
        m = self._manifest(seq=1)
        self._place(m, omit_sig=True)

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        self._assert_no_breadcrumb()
        self.mount_rw.assert_not_called()  # never remount an unverified stick rw

    def test_wrong_key_writes_no_breadcrumb_led_only(self):
        m = self._manifest(seq=1)
        self._place(m, sign_key=self.bad_key)  # untrusted signer

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        self._assert_no_breadcrumb()
        self.mount_rw.assert_not_called()

    def test_breadcrumb_write_failure_is_swallowed_terminal_unchanged(self):
        # An authenticated pre-commit failure whose breadcrumb write itself
        # fails (remount rw errors) must NOT mask the terminal: still LED
        # ERROR, still EXIT_OK, nothing raised, and no breadcrumb file.
        m = self._manifest(seq=1, box="not-nebula-ca")  # wrong_box (authenticated)
        self._place(m)
        self.mount_rw.side_effect = causb_mountctl.MountError("mount_failed")

        rc = self._run_expecting_pre_freshness_fail()

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states[-1], causb_led.ERROR)
        self._assert_no_breadcrumb()

    def test_successful_delivery_unlinks_stale_breadcrumb(self):
        # A stale ERROR.json from an earlier failed attempt is removed once a
        # later job commits+delivers (LATEST.json supersedes it).
        outbox = os.path.join(self.mp, "outbox")
        os.makedirs(outbox, exist_ok=True)
        with open(os.path.join(outbox, "ERROR.json"), "w") as f:
            f.write('{"stale": true}\n')
        m = self._manifest(seq=1)
        self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self._assert_no_breadcrumb()  # stale breadcrumb unlinked
        self.assertTrue(os.path.exists(os.path.join(outbox, "LATEST.json")))

    def test_replay_does_not_unlink_a_stale_breadcrumb(self):
        # A replay re-delivers an OLDER already-committed result; it must NOT
        # clear a (possibly newer) pre-commit ERROR.json breadcrumb from another
        # insertion -- only a FRESH committed delivery supersedes one.
        job_id = str(uuid.uuid4())
        self._seed_committed(job_id, 5, {"result.log": b"hi\n"})
        m = self._manifest(job_id=job_id, seq=6, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh")
        self._place(m, {"script.sh": b"echo hi\n"})
        os.makedirs(os.path.join(self.mp, "outbox"), exist_ok=True)
        with open(self._breadcrumb_path(), "w") as f:
            f.write('{"stale": true}\n')
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("no dispatch on replay")))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertIs(self._outbox_json("LATEST.json")["replayed"], True)  # was a replay
        self.assertTrue(os.path.exists(self._breadcrumb_path()),
                        "a replay must NOT unlink a pre-existing breadcrumb")

    # --- no_confirmation (post-freshness abort that DOES commit) ----------

    def test_no_confirmation_commits_consumes_seq_and_delivers(self):
        m = self._manifest(seq=7)
        job_id = self._place(m)
        dispatch = self._patch(
            causb_dispatch, "run",
            mock.MagicMock(side_effect=AssertionError("handler must not run on K1 timeout")))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=False))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        dispatch.assert_not_called()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.READY, causb_led.ERROR])
        self.assertTrue(self._committed(job_id))  # seq consumed via commit (Task 9)
        with open(os.path.join(self.state_dir, "seq")) as f:
            self.assertEqual(f.read().strip(), "7")
        st = self._outbox_json(job_id, "status.json")
        self.assertEqual(st["status"], "no_confirmation")
        self.assertEqual(st["error"], "no_confirmation")
        self.assertIs(st["presence_confirmed"], False)
        self.assertIsNone(st["exit_code"])
        latest = self._outbox_json("LATEST.json")
        self.assertEqual(latest["status"], "no_confirmation")

    def test_handler_nonzero_rc_is_error_handler_failed_committed(self):
        m = self._manifest(seq=3)
        job_id = self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch(outputs={}, rc=1))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertTrue(self._committed(job_id))  # ran -> seq consumed
        st = self._outbox_json(job_id, "status.json")
        self.assertEqual(st["status"], "error")
        self.assertEqual(st["error"], "handler_failed")
        self.assertEqual(st["exit_code"], 1)
        self.assertEqual(self.led_states[-1], causb_led.ERROR)

    # --- recovery branch (S7A) -------------------------------------------

    def test_blank_stick_triggers_k1_gated_recovery_confirm2_false(self):
        # No inbox/job.tar at all.
        rec = self._patch(causb_recovery, "write")
        # first press => proceed; second window times out => confirm2 False.
        self._patch(causb_button, "await_press", mock.MagicMock(side_effect=[True, False]))
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("no dispatch in recovery")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        rec.assert_called_once()
        args, _ = rec.call_args
        self.assertEqual(args[0], self.mp)          # mount point
        self.assertIs(args[1], False)               # confirm2 is a REAL bool False
        self.assertEqual(
            self.led_states,
            [causb_led.VERIFYING, causb_led.RECOVERY_OFFER, causb_led.RECOVERY_CONFIRM2,
             causb_led.RECOVERY_WRITE, causb_led.SAFE_REMOVE],
        )

    def test_second_press_opts_into_registry_confirm2_true(self):
        rec = self._patch(causb_recovery, "write")
        self._patch(causb_button, "await_press", mock.MagicMock(side_effect=[True, True]))
        rc = self.mod.run("/dev/sda1")
        self.assertEqual(rc, self.mod.EXIT_OK)
        args, _ = rec.call_args
        self.assertIs(args[1], True)  # distinct 2nd confirmation -> registry opt-in

    def test_recovery_declined_when_no_k1(self):
        rec = self._patch(causb_recovery, "write")
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=False))
        rc = self.mod.run("/dev/sda1")
        self.assertEqual(rc, self.mod.EXIT_OK)
        rec.assert_not_called()  # declined -> nothing written

    def test_present_but_bad_job_fails_closed_never_recovery(self):
        # A present (but wrong-key-signed) job.tar must fail closed, NOT recover.
        m = self._manifest(seq=1)
        self._place(m, sign_key=self.bad_key)
        rec = self._patch(causb_recovery, "write")
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("no K1 on a fail-closed job")))
        rc = self.mod.run("/dev/sda1")
        self.assertEqual(rc, self.mod.EXIT_OK)
        rec.assert_not_called()
        self.assertNotIn(causb_led.RECOVERY_OFFER, self.led_states)
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])

    # --- ordering guarantee: commit ALWAYS before deliver ----------------

    def test_commit_failure_leaves_outbox_empty_nothing_delivered(self):
        m = self._manifest(seq=2)
        job_id = self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))
        # commit blows up AFTER dispatch ran -> deliver must NEVER happen.
        self._patch(causb_commitlog, "commit",
                    mock.MagicMock(side_effect=OSError("simulated commit fsync failure")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.mount_rw.assert_not_called()          # never remounted rw to deliver
        self._assert_no_delivery()                 # outbox has no LATEST.json
        self.assertEqual(self.led_states[-1], causb_led.ERROR)

    def test_deliver_failure_after_commit_retains_onbox_committed_results(self):
        m = self._manifest(seq=2)
        job_id = self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))
        # The commit SUCCEEDS (real), then the remount-rw for delivery fails.
        self.mount_rw.side_effect = causb_mountctl.MountError("mount_failed")

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertTrue(self._committed(job_id))   # committed bytes intact on-box
        self._assert_no_delivery()                 # deliver failed -> no LATEST.json
        self.assertEqual(self.led_states[-1], causb_led.ERROR)

    # --- lock is released on every lifecycle path ------------------------

    def test_lock_released_after_a_full_run(self):
        m = self._manifest(seq=1)
        self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))
        self.mod.run("/dev/sda1")
        fd = self.mod._acquire_lock(self.mod.LOCK_PATH)
        self.assertIsNotNone(fd, "run() must release the flock on the success path")
        self.mod._release_lock(fd)

    def test_button_device_fault_propagates_as_exit_fault_and_releases_lock(self):
        m = self._manifest(seq=1)
        self._place(m)
        self._patch(causb_dispatch, "run", mock.MagicMock())
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=causb_button.ButtonError("device_not_found")))
        # A ButtonError is a genuine fault (no sensible LED) -> main() maps to
        # EXIT_FAULT; run() must still have umounted + released the lock.
        rc = self.mod.main(["ca-usb-run", "/dev/sda1"])
        self.assertEqual(rc, self.mod.EXIT_FAULT)
        self.umount.assert_called()  # umounted before the fault propagated
        fd = self.mod._acquire_lock(self.mod.LOCK_PATH)
        self.assertIsNotNone(fd)
        self.mod._release_lock(fd)

    # --- F1: per-job append-only audit log (§4/§11) ----------------------
    # Every terminal appends ONE JSONL line to the injected AUDIT_LOG carrying
    # {ts, job_id, operation, principal, status, seq, replayed, exit_code,
    # cosigned}; unknown fields are null; the write is fail-safe.

    def test_audit_happy_path_writes_one_ok_line_with_principal(self):
        m = self._manifest(seq=5, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh")
        job_id = self._place(m, {"script.sh": b"echo hi\n"})
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        self.mod.run("/dev/sda1")

        lines = self._audit_lines()
        self.assertEqual(len(lines), 1)
        a = lines[0]
        self.assertEqual(a["status"], "ok")
        self.assertEqual(a["job_id"], job_id)
        self.assertEqual(a["operation"], "run-script")
        self.assertEqual(a["principal"], "nebula-ca-operator")
        self.assertEqual(a["seq"], 5)
        self.assertIs(a["replayed"], False)
        self.assertEqual(a["exit_code"], 0)
        self.assertIs(a["cosigned"], False)

    def test_audit_handler_failed_line(self):
        m = self._manifest(seq=3)
        job_id = self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch(outputs={}, rc=1))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        self.mod.run("/dev/sda1")

        a = self._audit_lines()[-1]
        self.assertEqual(a["status"], "handler_failed")
        self.assertEqual(a["exit_code"], 1)
        self.assertEqual(a["job_id"], job_id)
        self.assertEqual(a["principal"], "nebula-ca-operator")

    def test_audit_no_confirmation_line(self):
        m = self._manifest(seq=7)
        job_id = self._place(m)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("handler must not run")))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=False))

        self.mod.run("/dev/sda1")

        a = self._audit_lines()[-1]
        self.assertEqual(a["status"], "no_confirmation")
        self.assertIsNone(a["exit_code"])
        self.assertEqual(a["job_id"], job_id)
        self.assertEqual(a["seq"], 7)
        self.assertEqual(a["principal"], "nebula-ca-operator")

    def test_audit_verify_failed_line_has_null_principal_and_job(self):
        m = self._manifest(seq=1)
        self._place(m, omit_sig=True)  # unsigned -> verify_failed before any principal
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("no dispatch")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("no K1")))

        self.mod.run("/dev/sda1")

        a = self._audit_lines()[-1]
        self.assertEqual(a["status"], "verify_failed")
        self.assertIsNone(a["principal"])
        self.assertIsNone(a["job_id"])
        self.assertIsNone(a["seq"])

    def test_audit_cosign_failed_line_has_principal(self):
        # Privileged run-script with NO .bg.sig -> the REAL dispatch.run raises
        # cosign_failed before any exec; principal + operation are known
        # (verify passed).
        m = self._manifest(seq=1, operation="run-script",
                           payload=["script.sh"], entrypoint="script.sh",
                           args={"privileged": True})
        job_id = self._place(m, {"script.sh": b"echo hi\n"})  # no break-glass sig
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        self.mod.run("/dev/sda1")

        a = self._audit_lines()[-1]
        self.assertEqual(a["status"], "cosign_failed")
        self.assertEqual(a["principal"], "nebula-ca-operator")
        self.assertEqual(a["operation"], "run-script")
        self.assertEqual(a["job_id"], job_id)
        self.assertIs(a["cosigned"], False)

    def test_audit_replay_line_marks_replayed_true(self):
        job_id = str(uuid.uuid4())
        self._seed_committed(job_id, 5, {"result.log": b"hi\n"})  # does not audit
        m = self._manifest(job_id=job_id, seq=6)
        self._place(m, {"script.sh": b"echo hi\n"})
        shutil.rmtree(os.path.join(self.mp, "outbox"), ignore_errors=True)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("no dispatch on replay")))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        self.mod.run("/dev/sda1")

        a = self._audit_lines()[-1]
        self.assertIs(a["replayed"], True)
        self.assertEqual(a["status"], "ok")
        self.assertEqual(a["job_id"], job_id)
        self.assertEqual(a["seq"], 5)  # the cached (original) seq, not 6
        self.assertEqual(a["principal"], "nebula-ca-operator")

    def test_audit_is_append_only_two_jobs_two_lines_first_preserved(self):
        m1 = self._manifest(seq=5)
        job1 = self._place(m1)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))
        self.mod.run("/dev/sda1")

        m2 = self._manifest(seq=6)
        job2 = self._place(m2)
        self.mod.run("/dev/sda1")

        lines = self._audit_lines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["job_id"], job1)  # first line preserved
        self.assertEqual(lines[1]["job_id"], job2)

    def test_audit_mount_failed_line_all_null_context(self):
        # A stick that could not even be mounted is an audited terminal too,
        # with all job context null (nothing was read yet).
        m = self._manifest(seq=1)
        self._place(m)
        self.mount_ro.side_effect = causb_mountctl.MountError("mount_failed")
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("no dispatch on mount fail")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("no K1 on mount fail")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        a = self._audit_lines()[-1]
        self.assertEqual(a["status"], "mount_failed")
        self.assertIsNone(a["job_id"])
        self.assertIsNone(a["principal"])

    def test_audit_write_failure_does_not_break_the_terminal(self):
        # A raising audit writer must NOT prevent the SAFE-REMOVE LED + umount
        # (a lost audit line is bad; a stuck stick is worse -- F1 fail-safe).
        m = self._manifest(seq=5)
        self._place(m)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))
        audit_mock = self._patch(causb_audit, "append",
                    mock.MagicMock(side_effect=OSError("simulated audit write failure")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        audit_mock.assert_called()  # audit WAS attempted (and raised)...
        self.assertEqual(self.led_states[-1], causb_led.SAFE_REMOVE)  # ...terminal still set
        self.umount.assert_called()  # ...and the stick was still umounted

    # --- F-a: break-glass-ALONE recovery (bg authorizes allowed-only rotate) --
    # A job whose ONLY valid signature is a break-glass one (in the PRIMARY
    # .sig slot -- the operator LOST their primary key) is authenticated via
    # the verify_breakglass_primary fallback and authorized ONLY for
    # operation==rotate-job-signers. The SAME bg-alone sig on any OTHER
    # operation is verify_failed, nothing runs. Every other gate (box/clock/
    # seq/replay/K1/jobs==1) is unchanged for a bg-authorized rotate.

    def _clear_inbox(self):
        inbox = os.path.join(self.mp, "inbox")
        for n in os.listdir(inbox):
            os.unlink(os.path.join(inbox, n))

    def test_breakglass_alone_rotate_dispatched_bg_authorized_and_committed(self):
        # The recovery path: a rotate-job-signers signed ONLY by the break-glass
        # key -> dispatched with bg_authorized=True, cosigned=False, committed.
        m = self._manifest(seq=1, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None)
        job_id = self._place(m, {"allowed_signers": b"nebula-ca-operator ssh-ed25519 AAAA x\n"},
                             sign_key=self.bg_key)  # break-glass key in the PRIMARY slot
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(self.dispatch_calls), 1)
        self.assertEqual(self.dispatch_calls[0]["operation"], "rotate-job-signers")
        self.assertIs(self.dispatch_calls[0]["bg_authorized"], True)  # a REAL bool True
        self.assertIs(self.dispatch_calls[0]["cosigned"], False)      # never co-signed
        self.assertTrue(self._committed(job_id))
        self.assertEqual(
            self.led_states,
            [causb_led.VERIFYING, causb_led.READY, causb_led.RUNNING, causb_led.SAFE_REMOVE],
        )
        # The audit line names the break-glass signer (forensic record of who
        # authorized the CA command) and records it was not co-signed.
        a = self._audit_lines()[-1]
        self.assertEqual(a["operation"], "rotate-job-signers")
        self.assertEqual(a["principal"], "nebula-ca-breakglass")
        self.assertIs(a["cosigned"], False)

    def test_operator_signed_rotate_is_not_bg_authorized(self):
        # The common case: a rotate-job-signers signed by the OPERATOR (primary
        # verifies) dispatches with bg_authorized=False -- the fallback fires
        # ONLY when the primary verify fails, never for a normally-signed job.
        m = self._manifest(seq=1, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None)
        self._place(m, {"allowed_signers": b"nebula-ca-operator ssh-ed25519 AAAA x\n"},
                    sign_key=self.op_key)
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.dispatch_calls[0]["operation"], "rotate-job-signers")
        self.assertIs(self.dispatch_calls[0]["bg_authorized"], False)  # NOT bg-authorized

    def test_breakglass_alone_on_non_rotate_operations_is_verify_failed(self):
        # THE razor-scoping proof: the SAME break-glass-alone signature on ANY
        # operation OTHER than rotate-job-signers is verify_failed -- dispatch
        # NEVER called, K1 NEVER reached, nothing committed/delivered.
        dispatch = self._patch(causb_dispatch, "run", mock.MagicMock())
        button = self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))
        ops = [
            ("sign-hosts", [], None, {}),
            ("ca-bootstrap", [], None, {}),
            ("run-script", ["script.sh"], "script.sh", {"script.sh": b"echo hi\n"}),
            ("rotate-ca", [], None, {}),
            ("backup-ca", [], None, {}),
            ("set-time", [], None, {}),
            ("status", [], None, {}),
        ]
        for op, payload, entrypoint, payload_files in ops:
            with self.subTest(operation=op):
                self.led_states.clear()
                self._clear_inbox()
                m = self._manifest(seq=1, operation=op, payload=payload,
                                   entrypoint=entrypoint)
                self._place(m, payload_files, sign_key=self.bg_key)  # bg in PRIMARY slot

                rc = self.mod.run("/dev/sda1")

                self.assertEqual(rc, self.mod.EXIT_OK)
                # verify_failed is LED-only (never reaches READY/K1).
                self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR],
                                 f"op={op!r} must be verify_failed (LED-only)")
                self._assert_no_delivery()
                self.assertEqual(os.listdir(self.results_dir), [],
                                 f"op={op!r} must commit nothing")
                # Prove it failed at the F-a operation gate (verify_failed),
                # not incidentally at parse (bad_manifest): the audit status is
                # exactly verify_failed and names the break-glass signer.
                a = self._audit_lines()[-1]
                self.assertEqual(a["status"], "verify_failed",
                                 f"op={op!r} must refuse with verify_failed")
                self.assertEqual(a["operation"], op)
                self.assertEqual(a["principal"], "nebula-ca-breakglass")
        dispatch.assert_not_called()  # NOTHING ran for ANY non-rotate op
        button.assert_not_called()    # K1 never reached for ANY of them

    def test_breakglass_alone_neither_anchor_is_verify_failed(self):
        # A rotate-job-signers signed by a key in NEITHER anchor (untrusted):
        # verify() fails AND verify_breakglass_primary() fails -> verify_failed,
        # nothing extracted-to-dispatch. Proves the fallback is not a bypass.
        m = self._manifest(seq=1, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None)
        self._place(m, {"allowed_signers": b"x\n"}, sign_key=self.bad_key)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("dispatch must not run")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("K1 must not be reached")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self._assert_no_delivery()
        self.assertEqual(self._audit_lines()[-1]["status"], "verify_failed")

    def test_breakglass_alone_rotate_stale_seq_still_gated(self):
        # Every non-verify gate is UNCHANGED for a bg-authorized rotate: a stale
        # seq is still stale_seq (dispatch never runs).
        prior = str(uuid.uuid4())
        self._seed_committed(prior, 5, {"result.log": b"x"})  # last-seq now 5
        m = self._manifest(seq=5, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None)  # seq <= last
        self._place(m, {"allowed_signers": b"x\n"}, sign_key=self.bg_key)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("dispatch must not run")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("K1 must not be reached")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        a = self._audit_lines()[-1]
        self.assertEqual(a["status"], "stale_seq")
        self.assertEqual(a["principal"], "nebula-ca-breakglass")

    def test_breakglass_alone_rotate_wrong_box_still_gated(self):
        m = self._manifest(seq=1, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None,
                           box="not-nebula-ca")
        self._place(m, {"allowed_signers": b"x\n"}, sign_key=self.bg_key)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("dispatch must not run")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("K1 must not be reached")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self.assertEqual(self._audit_lines()[-1]["status"], "wrong_box")

    def test_breakglass_alone_rotate_k1_timeout_still_no_confirmation(self):
        # K1 still gates a bg-authorized rotate: a timeout is no_confirmation
        # (which DOES commit + consume the seq, per Task 9), never a silent run.
        m = self._manifest(seq=8, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None)
        job_id = self._place(m, {"allowed_signers": b"x\n"}, sign_key=self.bg_key)
        dispatch = self._patch(
            causb_dispatch, "run",
            mock.MagicMock(side_effect=AssertionError("handler must not run on K1 timeout")))
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=False))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        dispatch.assert_not_called()
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.READY, causb_led.ERROR])
        self.assertTrue(self._committed(job_id))  # seq consumed via commit
        st = self._outbox_json(job_id, "status.json")
        self.assertEqual(st["status"], "no_confirmation")

    def test_breakglass_alone_rotate_jobs_gt_1_still_rejected(self):
        # jobs==1 still enforced for a bg-authenticated bundle: a 2-job manifest
        # is jobs_gt_1 at parse (before the operation gate), nothing runs.
        two = [
            {"job_id": str(uuid.uuid4()), "operation": "rotate-job-signers", "payload": []},
            {"job_id": str(uuid.uuid4()), "operation": "rotate-job-signers", "payload": []},
        ]
        m = self._manifest(seq=1, jobs=two)
        self._place(m, {}, sign_key=self.bg_key)
        self._patch(causb_dispatch, "run",
                    mock.MagicMock(side_effect=AssertionError("dispatch must not run")))
        self._patch(causb_button, "await_press",
                    mock.MagicMock(side_effect=AssertionError("K1 must not be reached")))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(self.led_states, [causb_led.VERIFYING, causb_led.ERROR])
        self.assertEqual(self._audit_lines()[-1]["status"], "jobs_gt_1")

    def test_breakglass_alone_rotate_ignores_bg_sig_and_stays_not_cosigned(self):
        # A bg-authorized rotate never runs verify_cosign: even if an
        # (irrelevant) job.tar.bg.sig is ALSO attached, cosigned stays False.
        # The primary-slot sig is the break-glass one; the fallback authorizes,
        # and co-sign is neither computed nor passed to dispatch.
        m = self._manifest(seq=1, operation="rotate-job-signers",
                           payload=["allowed_signers"], entrypoint=None)
        self._place(m, {"allowed_signers": b"x\n"},
                    sign_key=self.bg_key, bg_key=self.bg_key)  # bg in BOTH slots
        self._patch(causb_dispatch, "run", self._fake_dispatch())
        self._patch(causb_button, "await_press", mock.MagicMock(return_value=True))

        rc = self.mod.run("/dev/sda1")

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertIs(self.dispatch_calls[0]["bg_authorized"], True)
        self.assertIs(self.dispatch_calls[0]["cosigned"], False)


if __name__ == "__main__":
    unittest.main()
