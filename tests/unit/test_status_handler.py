"""Tests for box/handlers/status: the "status" vetted handler (S6/S8; task
14). Not part of the enumerated brief test list (that list is scoped to
causb.dispatch's run-script/privileged logic) -- written anyway per this
project's TDD-for-the-whole-task convention, and because build_box_info/
build_health both read real system state (RTC sysfs, nebula-cert, disk
usage, STATE_DIR/seq) that is cheap and worthwhile to pin down.

box/handlers/status is a standalone, extensionless script (like
box/bin/ca-usb-run) -- loaded in-process via importlib exactly like
test_ca_usb_run.py's `_load_ca_usb_run_module()` precedent, so its
`sys.path.insert(0, "/usr/local/lib")` + `from causb import ...` at module
scope behave identically to a real standalone invocation.

Every real-system read (`nebula-cert` binary, RTC sysfs path, disk-usage
target, seq-state directory) is exercised via `build_box_info`/
`build_health`'s explicit keyword params -- never against the box's REAL
`/var/lib/nebula-ca` (confirmed empirically, non-root: `shutil.disk_usage`
on it happens to succeed, but a plain `open(.../seq)` raises a raw, UNCAUGHT
`PermissionError`, and `os.path.isfile(.../ca/ca.crt)` silently swallows a
permission error into a same-shaped `False` as "genuinely absent" -- none of
which this task should rely on, since `status` always runs as ROOT in
production, R2). The one `run()`-level smoke test below therefore carefully
monkeypatches the loaded module's `config.STATE_DIR`/`config.CA_DIR`/
`RTC_SINCE_EPOCH_PATH` to temp, world-accessible paths, and restores them in
`finally` -- `causb.config` is a real, process-wide SHARED module object
(unlike `ca_usb_run_under_test`'s own top-level constants, which are
distinct per fresh `importlib` load), so an unrestored mutation here would
leak into every other test file's `from causb import config`.
"""

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_LIB = os.path.join(REPO_ROOT, "box", "lib")
STATUS_HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "status")


def _load_status_module():
    loader = importlib.machinery.SourceFileLoader("status_handler_under_test", STATUS_HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _fake_runner(stdout_text=None, raise_exc=None):
    def _runner(argv, **kwargs):
        if raise_exc is not None:
            raise raise_exc
        return subprocess.CompletedProcess(list(argv), 0, stdout=(stdout_text or "").encode())
    return _runner


def _write_rtc_epoch(path, epoch):
    with open(path, "w") as f:
        f.write(str(epoch))


def _make_stub_nebula_cert_bin(tmpdir):
    """A directory holding a dummy, executable `nebula-cert` file -- just
    enough for `shutil.which()` (`causb.recovery._ca_fingerprint`'s
    binary-presence pre-check, reused verbatim by `build_box_info`'s
    post-bootstrap fingerprint field) to resolve to SOMETHING, without
    depending on whether a real `nebula-cert` happens to be on this test
    runner's PATH. Every caller ALSO overrides `nebula_cert_runner`, so the
    stub's own content is never actually executed -- mirrors
    tests/unit/test_recovery.py's own `_make_stub_bin` recipe for the exact
    same seam."""
    bindir = os.path.join(tmpdir, "fakebin")
    os.makedirs(bindir, exist_ok=True)
    stub = os.path.join(bindir, "nebula-cert")
    with open(stub, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(stub, 0o755)
    return bindir


def _fake_nebula_cert_runner(version_text="Version: 1.10.3\n", print_json_text=None, raise_exc=None):
    """Like `_fake_runner`, but distinguishes the plain `-version` argv
    `_nebula_cert_version` invokes from the `print -json ...` argv
    `causb.recovery._ca_fingerprint` invokes (reused verbatim by
    `build_box_info` for the post-bootstrap `ca_fingerprint` field) -- so
    ONE runner can realistically serve both call shapes in the same
    bootstrapped-box test."""
    def _runner(argv, **kwargs):
        if raise_exc is not None:
            raise raise_exc
        if "print" in argv:
            return subprocess.CompletedProcess(list(argv), 0, stdout=(print_json_text or "").encode())
        return subprocess.CompletedProcess(list(argv), 0, stdout=(version_text or "").encode())
    return _runner


class TestBuildBoxInfo(unittest.TestCase):
    def setUp(self):
        self.mod = _load_status_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-status-test-")
        self.state_dir = os.path.join(self.tmp, "state")
        self.ca_dir = os.path.join(self.tmp, "state", "ca")
        os.makedirs(self.ca_dir)
        self.rtc_path = os.path.join(self.tmp, "since_epoch")

    def tearDown(self):
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.tmp)

    def _kwargs(self, **overrides):
        kwargs = dict(
            box_name="nebula-ca",
            state_dir=self.state_dir,
            ca_dir=self.ca_dir,
            rtc_path=self.rtc_path,
            nebula_cert_runner=_fake_runner("Version: 1.10.3\n"),
        )
        kwargs.update(overrides)
        return kwargs

    def test_pre_bootstrap_shape_matches_s6_exactly(self):
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        info = self.mod.build_box_info(**self._kwargs())

        assert set(info.keys()) == {
            "box", "bootstrapped", "ca_fingerprint", "nebula_cert_version",
            "curve", "overlay_cidr", "seq", "schema_versions", "rtc_ok",
        }
        assert info["box"] == "nebula-ca"
        assert info["bootstrapped"] is False
        assert info["ca_fingerprint"] is None
        assert info["curve"] is None
        assert info["overlay_cidr"] is None
        assert info["seq"] == 0  # no seq file yet
        assert info["nebula_cert_version"] == "1.10.3"
        assert info["schema_versions"] == {"manifest": 1, "status": 1, "error": 1}
        assert info["rtc_ok"] is True

    def test_bootstrapped_true_when_ca_crt_present(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "w") as f:
            f.write("dummy cert content")
        _write_rtc_epoch(self.rtc_path, int(time.time()))

        info = self.mod.build_box_info(**self._kwargs())
        assert info["bootstrapped"] is True
        # Post-review fix (final-review-caops-fixes): curve is now populated
        # unconditionally whenever bootstrapped -- see the dedicated
        # overlay_cidr/ca_fingerprint tests below for the registry/nebula-cert
        # -dependent fields, which need the stub-bin seam to be hermetic.
        assert info["curve"] == "25519"

    def test_bootstrapped_populates_overlay_cidr_from_registry(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "w") as f:
            f.write("dummy cert content")
        with open(os.path.join(self.ca_dir, "registry.json"), "w") as f:
            json.dump({"overlay_cidr": "10.99.0.0/16", "hosts": {}}, f)
        _write_rtc_epoch(self.rtc_path, int(time.time()))

        info = self.mod.build_box_info(**self._kwargs())
        assert info["overlay_cidr"] == "10.99.0.0/16"

    def test_bootstrapped_overlay_cidr_defaults_when_registry_absent(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "w") as f:
            f.write("dummy cert content")
        _write_rtc_epoch(self.rtc_path, int(time.time()))

        info = self.mod.build_box_info(**self._kwargs())
        assert info["overlay_cidr"] == self.mod.config.OVERLAY_CIDR

    def test_bootstrapped_populates_fingerprint_via_recovery_reuse(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "w") as f:
            f.write("dummy cert content")
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        bindir = _make_stub_nebula_cert_bin(self.tmp)
        fingerprint_json = json.dumps([{"fingerprint": "deadbeefcafe0123"}])

        info = self.mod.build_box_info(**self._kwargs(
            nebula_cert_runner=_fake_nebula_cert_runner(print_json_text=fingerprint_json),
            nebula_cert_path=bindir,
        ))
        assert info["ca_fingerprint"] == "deadbeefcafe0123"

    def test_bootstrapped_fingerprint_none_on_print_json_failure(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "w") as f:
            f.write("dummy cert content")
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        bindir = _make_stub_nebula_cert_bin(self.tmp)

        info = self.mod.build_box_info(**self._kwargs(
            nebula_cert_runner=_fake_nebula_cert_runner(print_json_text="not json at all"),
            nebula_cert_path=bindir,
        ))
        # Graceful degrade, never a crash -- curve is still populated (it
        # needs no external tool), only the fingerprint itself is None.
        assert info["curve"] == "25519"
        assert info["ca_fingerprint"] is None

    def test_seq_reads_real_value(self):
        with open(os.path.join(self.state_dir, "seq"), "w") as f:
            f.write("42\n")
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        info = self.mod.build_box_info(**self._kwargs())
        assert info["seq"] == 42

    def test_rtc_ok_false_when_year_implausible(self):
        _write_rtc_epoch(self.rtc_path, 946684800)  # 2000-01-01
        info = self.mod.build_box_info(**self._kwargs())
        assert info["rtc_ok"] is False

    def test_rtc_ok_false_when_rtc_file_missing(self):
        info = self.mod.build_box_info(**self._kwargs())  # rtc_path never written
        assert info["rtc_ok"] is False

    def test_nebula_cert_version_none_when_binary_missing(self):
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        info = self.mod.build_box_info(
            **self._kwargs(nebula_cert_runner=_fake_runner(raise_exc=FileNotFoundError()))
        )
        assert info["nebula_cert_version"] is None

    def test_nebula_cert_version_none_on_unparseable_output(self):
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        info = self.mod.build_box_info(
            **self._kwargs(nebula_cert_runner=_fake_runner("garbage output\n"))
        )
        assert info["nebula_cert_version"] is None


class TestBuildHealth(unittest.TestCase):
    def setUp(self):
        self.mod = _load_status_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-status-health-test-")
        self.rtc_path = os.path.join(self.tmp, "since_epoch")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_disk_fields_are_positive_ints_for_a_real_path(self):
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        health = self.mod.build_health(
            state_dir=self.tmp, rtc_path=self.rtc_path,
            nebula_cert_runner=_fake_runner("Version: 1.10.3\n"),
        )
        assert isinstance(health["disk_total_bytes"], int) and health["disk_total_bytes"] > 0
        assert isinstance(health["disk_free_bytes"], int) and health["disk_free_bytes"] >= 0
        assert health["rtc_ok"] is True
        assert health["nebula_cert_reachable"] is True

    def test_disk_fields_none_when_path_does_not_exist(self):
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        health = self.mod.build_health(
            state_dir=os.path.join(self.tmp, "does-not-exist"), rtc_path=self.rtc_path,
            nebula_cert_runner=_fake_runner("Version: 1.10.3\n"),
        )
        assert health["disk_total_bytes"] is None
        assert health["disk_free_bytes"] is None

    def test_nebula_cert_reachable_false_when_binary_missing(self):
        _write_rtc_epoch(self.rtc_path, int(time.time()))
        health = self.mod.build_health(
            state_dir=self.tmp, rtc_path=self.rtc_path,
            nebula_cert_runner=_fake_runner(raise_exc=FileNotFoundError()),
        )
        assert health["nebula_cert_reachable"] is False


class TestAtomicWriteJson(unittest.TestCase):
    def setUp(self):
        self.mod = _load_status_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-status-atomic-test-")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_writes_valid_json_and_leaves_no_tmp_file(self):
        self.mod._atomic_write_json(self.tmp, "thing.json", {"a": 1})
        with open(os.path.join(self.tmp, "thing.json")) as f:
            assert json.load(f) == {"a": 1}
        assert not os.path.exists(os.path.join(self.tmp, "thing.json.tmp"))


class TestRun(unittest.TestCase):
    """Full run(manifest_path, payload_dir, out_dir): writes all three
    files to out_dir. Monkeypatches the loaded module's config.STATE_DIR/
    config.CA_DIR/RTC_SINCE_EPOCH_PATH (save/restore -- see module
    docstring) so this is fully non-root."""

    def setUp(self):
        self.mod = _load_status_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-status-run-test-")
        self.state_dir = os.path.join(self.tmp, "state")
        self.ca_dir = os.path.join(self.tmp, "state", "ca")
        os.makedirs(self.ca_dir)
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)
        self.rtc_path = os.path.join(self.tmp, "since_epoch")
        _write_rtc_epoch(self.rtc_path, int(time.time()))

        self._orig_state_dir = self.mod.config.STATE_DIR
        self._orig_ca_dir = self.mod.config.CA_DIR
        self._orig_rtc_path = self.mod.RTC_SINCE_EPOCH_PATH
        self.mod.config.STATE_DIR = self.state_dir
        self.mod.config.CA_DIR = self.ca_dir
        self.mod.RTC_SINCE_EPOCH_PATH = self.rtc_path

    def tearDown(self):
        self.mod.config.STATE_DIR = self._orig_state_dir
        self.mod.config.CA_DIR = self._orig_ca_dir
        self.mod.RTC_SINCE_EPOCH_PATH = self._orig_rtc_path
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for name in files:
                os.unlink(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.tmp)

    def test_writes_all_three_files_and_ignores_manifest_and_payload_args(self):
        manifest_path = os.path.join(self.tmp, "does-not-need-to-exist.json")
        rc = self.mod.run(manifest_path, self.payload_dir, self.out_dir)
        assert rc == self.mod.EXIT_OK

        with open(os.path.join(self.out_dir, "box-info.json")) as f:
            box_info = json.load(f)
        assert box_info["bootstrapped"] is False
        assert box_info["box"] == "nebula-ca"

        # Post-review fix (final-review-caops-fixes): registry.json is now
        # the OBJECT shape ca-bootstrap/sign-hosts actually write on disk,
        # never the stale S6 `[]` literal (which used to clobber a populated
        # registry mirror on the operator's stick after a sign-hosts run).
        with open(os.path.join(self.out_dir, "registry.json")) as f:
            registry_out = json.load(f)
        assert registry_out == {"overlay_cidr": self.mod.config.OVERLAY_CIDR, "hosts": {}}

        with open(os.path.join(self.out_dir, "health.json")) as f:
            health = json.load(f)
        assert "disk_free_bytes" in health

    def test_registry_json_echoes_populated_registry(self):
        populated = {
            "overlay_cidr": "10.42.0.0/16",
            "hosts": {"alice": {"ip": "10.42.0.10", "pubkey_sha256": "abc123"}},
        }
        with open(os.path.join(self.ca_dir, "registry.json"), "w") as f:
            json.dump(populated, f)
        manifest_path = os.path.join(self.tmp, "does-not-need-to-exist.json")

        rc = self.mod.run(manifest_path, self.payload_dir, self.out_dir)
        assert rc == self.mod.EXIT_OK
        with open(os.path.join(self.out_dir, "registry.json")) as f:
            registry_out = json.load(f)
        assert registry_out == populated

    def test_registry_json_degrades_gracefully_on_corrupt_file(self):
        with open(os.path.join(self.ca_dir, "registry.json"), "w") as f:
            f.write("{not valid json")
        manifest_path = os.path.join(self.tmp, "does-not-need-to-exist.json")

        rc = self.mod.run(manifest_path, self.payload_dir, self.out_dir)
        assert rc == self.mod.EXIT_OK  # never crashes -- status is read-only
        with open(os.path.join(self.out_dir, "registry.json")) as f:
            registry_out = json.load(f)
        assert registry_out == {"overlay_cidr": self.mod.config.OVERLAY_CIDR, "hosts": {}}

    def test_main_argv_contract(self):
        rc = self.mod.main(["status", "manifest.json", self.payload_dir, self.out_dir])
        assert rc == self.mod.EXIT_OK

    def test_main_wrong_argc_returns_fault(self):
        rc = self.mod.main(["status", "only-one-arg"])
        assert rc == self.mod.EXIT_FAULT


if __name__ == "__main__":
    unittest.main()
