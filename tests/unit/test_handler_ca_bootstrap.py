"""Tests for box/handlers/ca-bootstrap: the "ca-bootstrap" vetted handler
(S8; CA operation handlers plan, Task 3). This is the FIRST post-air-gap job
the operator ever runs -- it mints the CA's ca.key/ca.crt ON THE BOX (the
key is born here and must NEVER leave), so this suite's two load-bearing
properties are: (1) the CA is genuinely v1 (D16 -- nebula-cert `ca` DEFAULTS
to -version 2 if omitted, which would silently break the mixed/Android
fleet), and (2) ca.key can never reach out_dir under any code path,
including a "copy the whole ca_dir" mutation.

box/handlers/ca-bootstrap is a standalone, extensionless script (like
box/handlers/status before it) -- loaded in-process via importlib exactly
like test_status_handler.py's `_load_status_module()` precedent, so its
`sys.path.append("/usr/local/lib")` + `from causb import ...` at module
scope behave identically to a real standalone invocation.

`nebula_ca` is injected as a fake recorder (mirrors test_nebulacli.py's
_RecordingRunner and this project's established `runner=`/`popen=`
DI-seam convention): it never shells out to the real nebula-cert binary,
just records every call's arguments and writes recognizable fake bytes to
the out_crt/out_key paths it's given -- exactly the brief's own fixture
description. Every test uses fresh tempfile.mkdtemp() dirs for ca_dir/
out_dir, never the real /var/lib/nebula-ca.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
import importlib.machinery
import importlib.util

from causb import config, registry

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CA_BOOTSTRAP_HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "ca-bootstrap")

FAKE_KEY_BYTES = b"FAKE-CA-PRIVATE-KEY-SECRET-MATERIAL-DO-NOT-LEAK-4f8c"
FAKE_CRT_BYTES = b"FAKE-CA-PUBLIC-CERT-PEM-BYTES"


def _load_ca_bootstrap_module():
    loader = importlib.machinery.SourceFileLoader("ca_bootstrap_handler_under_test", CA_BOOTSTRAP_HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _rmtree(path):
    """Manual recursive removal (mirrors test_status_handler.py's tearDown
    precedent) -- works even though ca-bootstrap deliberately leaves ca.key
    at 0400/ca.crt at 0444: unlink only needs the PARENT directory to be
    writable, not the file itself."""
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            os.unlink(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(path)


def _job(args=None):
    job = {
        "job_id": "11111111-1111-4111-8111-111111111111",
        "operation": "ca-bootstrap",
        "args": {} if args is None else args,
        "payload": [],
    }
    return job


class _FakeNebulaCa:
    """Stands in for causb.nebulacli.ca(). Records every call's bound
    arguments (name/curve/version/duration positional, out_crt/out_key
    keyword -- matching the brief's own documented call shape) and writes
    recognizable fake bytes to the paths it's given. Binding through a real
    Python parameter list (rather than raw *args/**kwargs) means a call
    asserted against `self.calls[i]["version"]` is correct regardless of
    whether the production code happened to pass `version` positionally or
    by keyword -- Python's own argument binding normalizes it either way."""

    def __init__(self, key_bytes=FAKE_KEY_BYTES, crt_bytes=FAKE_CRT_BYTES, raise_exc=None):
        self.calls = []
        self.key_bytes = key_bytes
        self.crt_bytes = crt_bytes
        self.raise_exc = raise_exc

    def __call__(self, name, curve, version, duration, *, out_crt, out_key):
        self.calls.append({
            "name": name, "curve": curve, "version": version,
            "duration": duration, "out_crt": out_crt, "out_key": out_key,
        })
        if self.raise_exc is not None:
            raise self.raise_exc
        with open(out_crt, "wb") as f:
            f.write(self.crt_bytes)
        with open(out_key, "wb") as f:
            f.write(self.key_bytes)


class _CaBootstrapTestBase(unittest.TestCase):
    def setUp(self):
        self.mod = _load_ca_bootstrap_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-ca-bootstrap-test-")
        self.ca_dir = os.path.join(self.tmp, "ca")
        self.registry_path = os.path.join(self.ca_dir, "registry.json")
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)

    def tearDown(self):
        _rmtree(self.tmp)

    def _mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def _run(self, job=None, fake=None, out_dir=None, **overrides):
        fake = fake or _FakeNebulaCa()
        kwargs = dict(ca_dir=self.ca_dir, registry_path=self.registry_path, nebula_ca=fake)
        kwargs.update(overrides)
        rc = self.mod.run(job or _job(), self.payload_dir, out_dir or self.out_dir, **kwargs)
        return rc, fake


class TestHappyPath(_CaBootstrapTestBase):
    def test_happy_path_creates_ca_dir_artifacts_with_correct_modes(self):
        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_OK)

        ca_key_path = os.path.join(self.ca_dir, "ca.key")
        ca_crt_path = os.path.join(self.ca_dir, "ca.crt")
        self.assertTrue(os.path.isfile(ca_key_path))
        self.assertTrue(os.path.isfile(ca_crt_path))

        with open(ca_key_path, "rb") as f:
            self.assertEqual(f.read(), FAKE_KEY_BYTES)
        with open(ca_crt_path, "rb") as f:
            self.assertEqual(f.read(), FAKE_CRT_BYTES)

        self.assertEqual(self._mode(ca_key_path), 0o400)
        self.assertEqual(self._mode(ca_crt_path), 0o444)
        self.assertEqual(self._mode(self.ca_dir), 0o700)

    def test_happy_path_writes_initial_registry_with_default_overlay(self):
        self._run()
        reg = registry.load(self.registry_path)
        self.assertEqual(reg, {"overlay_cidr": config.OVERLAY_CIDR, "hosts": {}})

    def test_happy_path_writes_public_artifacts_to_out_dir(self):
        self._run()
        out_crt = os.path.join(self.out_dir, "ca.crt")
        out_registry = os.path.join(self.out_dir, "registry.json")
        self.assertTrue(os.path.isfile(out_crt))
        self.assertTrue(os.path.isfile(out_registry))
        with open(out_crt, "rb") as f:
            self.assertEqual(f.read(), FAKE_CRT_BYTES)
        with open(out_registry) as f:
            self.assertEqual(json.load(f), {"overlay_cidr": config.OVERLAY_CIDR, "hosts": {}})

    def test_nebula_ca_called_with_explicit_version_1(self):
        # D16 / CAop-Task 1's review carry-forward: nebula-cert `ca` DEFAULTS
        # to -version 2 if omitted; ca-bootstrap MUST pass version="1"
        # explicitly. This is the single most important call-shape
        # assertion in this whole file.
        _, fake = self._run()
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["version"], "1")
        self.assertEqual(fake.calls[0]["curve"], "25519")

    def test_nebula_ca_called_with_default_name_and_duration(self):
        _, fake = self._run(job=_job())
        self.assertEqual(fake.calls[0]["name"], "nebula-ca")
        self.assertEqual(fake.calls[0]["duration"], config.CA_DURATION)


class TestKeyNeverReachesOutDir(_CaBootstrapTestBase):
    def test_ca_key_bytes_never_appear_anywhere_under_out_dir(self):
        """Mutation-proof: a `shutil.copytree(ca_dir, out_dir)`-style bug
        (copy everything instead of an explicit allowlist) would plant
        ca.key -- and its bytes -- somewhere under out_dir. This test walks
        the ENTIRE out_dir tree and checks both the filename and the byte
        content, so it fails under that exact mutation."""
        rc, _ = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)

        found_files = []
        for root, _dirs, files in os.walk(self.out_dir):
            for name in files:
                found_files.append(os.path.join(root, name))

        self.assertTrue(found_files, "expected out_dir to contain the public artifacts")

        for path in found_files:
            self.assertNotEqual(os.path.basename(path), "ca.key")
            with open(path, "rb") as f:
                content = f.read()
            self.assertNotIn(FAKE_KEY_BYTES, content)


class TestIdempotency(_CaBootstrapTestBase):
    def test_second_run_returns_already_bootstrapped_and_leaves_key_untouched(self):
        first_rc, first_fake = self._run()
        self.assertEqual(first_rc, self.mod.EXIT_OK)

        ca_key_path = os.path.join(self.ca_dir, "ca.key")
        with open(ca_key_path, "rb") as f:
            original_key_bytes = f.read()
        self.assertEqual(original_key_bytes, FAKE_KEY_BYTES)

        # Wipe out_dir so we can prove the second run writes NOTHING to it.
        for name in os.listdir(self.out_dir):
            os.unlink(os.path.join(self.out_dir, name))

        second_fake = _FakeNebulaCa(key_bytes=b"DIFFERENT-KEY-IF-THIS-EVER-RUNS")
        second_rc, _ = self._run(fake=second_fake)

        self.assertEqual(second_rc, self.mod.EXIT_ALREADY_BOOTSTRAPPED)
        self.assertEqual(second_rc, 3)  # brief pins this exact exit code
        self.assertEqual(second_fake.calls, [])  # nebula_ca never invoked

        with open(ca_key_path, "rb") as f:
            self.assertEqual(f.read(), original_key_bytes)

        self.assertEqual(os.listdir(self.out_dir), [])

    def test_fresh_bootstrap_on_empty_ca_dir_is_not_already_bootstrapped(self):
        # Sanity check on the guard's precision: a ca_dir that exists but
        # has no ca.key yet (e.g. a stray registry.json from nowhere) is
        # NOT considered already-bootstrapped.
        os.makedirs(self.ca_dir, exist_ok=True)
        rc, _ = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)


class TestManifestOverrides(_CaBootstrapTestBase):
    def test_overlay_override_lands_in_registry_json(self):
        job = _job(args={"overlay": "10.99.0.0/16"})
        self._run(job=job)
        reg = registry.load(self.registry_path)
        self.assertEqual(reg["overlay_cidr"], "10.99.0.0/16")

    def test_duration_and_name_overrides_passed_to_nebula_ca(self):
        job = _job(args={"duration": "8760h", "name": "custom-ca"})
        _, fake = self._run(job=job)
        self.assertEqual(fake.calls[0]["duration"], "8760h")
        self.assertEqual(fake.calls[0]["name"], "custom-ca")

    def test_missing_args_key_entirely_uses_all_defaults(self):
        job = {"job_id": "22222222-2222-4222-8222-222222222222", "operation": "ca-bootstrap", "payload": []}
        rc, fake = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(fake.calls[0]["name"], "nebula-ca")
        self.assertEqual(fake.calls[0]["duration"], config.CA_DURATION)
        reg = registry.load(self.registry_path)
        self.assertEqual(reg["overlay_cidr"], config.OVERLAY_CIDR)

    def test_non_dict_args_falls_back_to_defaults_rather_than_crashing(self):
        job = _job(args=["not", "a", "dict"])
        rc, fake = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(fake.calls[0]["name"], "nebula-ca")


class TestBadManifestArgs(_CaBootstrapTestBase):
    def test_non_string_overlay_returns_bad_manifest(self):
        job = _job(args={"overlay": 12345})
        rc, fake = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(fake.calls, [])

    def test_control_char_in_name_returns_bad_manifest_not_a_raw_valueerror(self):
        # Without this guard, nebulacli.ca()'s own _check_clean() raises a
        # bare ValueError (not NebulaError) on an embedded control char,
        # which would otherwise escape run()'s bounded reason contract.
        job = _job(args={"name": "evil\x00name"})
        rc, fake = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(fake.calls, [])

    def test_bad_manifest_leaves_no_ca_dir_artifacts(self):
        job = _job(args={"duration": None})
        rc, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt")))


class TestNebulaFailure(_CaBootstrapTestBase):
    def test_nebula_error_returns_nonzero_and_leaves_no_partial_ca(self):
        from causb.nebulacli import NebulaError
        fake = _FakeNebulaCa(raise_exc=NebulaError("nebula_failed"))

        rc, _ = self._run(fake=fake)

        self.assertNotEqual(rc, 0)
        self.assertEqual(rc, self.mod.EXIT_NEBULA_FAILED)
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key.tmp")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt.tmp")))
        # Nothing was ever published either.
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_nebula_error_does_not_wedge_a_retry(self):
        from causb.nebulacli import NebulaError
        failing_fake = _FakeNebulaCa(raise_exc=NebulaError("nebula_failed"))
        first_rc, _ = self._run(fake=failing_fake)
        self.assertEqual(first_rc, self.mod.EXIT_NEBULA_FAILED)

        retry_fake = _FakeNebulaCa()
        second_rc, _ = self._run(fake=retry_fake)
        self.assertEqual(second_rc, self.mod.EXIT_OK)
        self.assertEqual(len(retry_fake.calls), 1)


class TestWriteFailureLeavesNoWedge(_CaBootstrapTestBase):
    def test_out_dir_missing_causes_write_failed_and_a_clean_retry_succeeds(self):
        # out_dir does not exist -> the out_dir copy step fails with OSError
        # AFTER nebula_ca already produced tmp cert/key bytes. This must not
        # leave ca.key sitting in ca_dir (which would permanently wedge a
        # retry behind the already_bootstrapped guard with no registry ever
        # written).
        missing_out_dir = os.path.join(self.tmp, "does-not-exist")
        first_fake = _FakeNebulaCa()
        rc = self.mod.run(
            _job(), self.payload_dir, missing_out_dir,
            ca_dir=self.ca_dir, registry_path=self.registry_path, nebula_ca=first_fake,
        )
        self.assertEqual(rc, self.mod.EXIT_WRITE_FAILED)
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt")))

        os.makedirs(missing_out_dir)
        retry_fake = _FakeNebulaCa()
        rc2, _ = self._run(fake=retry_fake, out_dir=missing_out_dir)
        self.assertEqual(rc2, self.mod.EXIT_OK)


class TestMainShim(_CaBootstrapTestBase):
    def _write_job_json(self, job):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump(job, f)
        return path

    def test_main_argv_contract_reads_job_json_and_runs(self):
        # run()'s ca_dir=config.CA_DIR / registry_path=config.REGISTRY /
        # nebula_ca=nebulacli.ca defaults are bound at function-DEFINITION
        # time (an ordinary Python default-argument, evaluated once when the
        # module execs) -- NOT re-read at call time. So config/nebulacli
        # must be patched BEFORE this test's own fresh module load, not
        # after (a plain post-hoc `self.mod.config.CA_DIR = ...` would be a
        # no-op on run()'s already-bound default, exactly as it would be for
        # causb.registry.save's identical `path=config.REGISTRY` pattern).
        job_path = self._write_job_json(_job())
        orig_ca_dir = config.CA_DIR
        orig_registry = config.REGISTRY
        from causb import nebulacli as shared_nebulacli
        orig_nebula_ca = shared_nebulacli.ca
        fake = _FakeNebulaCa()
        config.CA_DIR = self.ca_dir
        config.REGISTRY = self.registry_path
        shared_nebulacli.ca = fake
        try:
            mod = _load_ca_bootstrap_module()  # fresh exec -- binds the patched values above
            rc = mod.main(["ca-bootstrap", job_path, self.payload_dir, self.out_dir])
        finally:
            config.CA_DIR = orig_ca_dir
            config.REGISTRY = orig_registry
            shared_nebulacli.ca = orig_nebula_ca
        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(os.path.isfile(os.path.join(self.ca_dir, "ca.key")))

    def test_main_wrong_argc_returns_fault(self):
        rc = self.mod.main(["ca-bootstrap", "only-one-arg"])
        self.assertEqual(rc, self.mod.EXIT_FAULT)

    def test_main_unparseable_job_json_returns_bad_manifest(self):
        path = os.path.join(self.tmp, "bad-job.json")
        with open(path, "w") as f:
            f.write("not json{{{")
        rc = self.mod.main(["ca-bootstrap", path, self.payload_dir, self.out_dir])
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)


if __name__ == "__main__":
    unittest.main()
