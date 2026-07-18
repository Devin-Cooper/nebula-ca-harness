"""Tests for box/handlers/backup-ca: the "backup-ca" vetted handler (S8; CA
operation handlers plan, Task 5). This handler produces an age-encrypted
`ca.key.age` the operator can carry OFF the box for disaster recovery (see
recovery-kit/RECOVERY-CEREMONY.md) -- so this suite's two load-bearing
properties are: (1) the PLAINTEXT `ca.key` can never reach `out_dir` under
any code path (only the encrypted `ca.key.age` may), and (2) the recipient
`age` encrypts against is ALWAYS the box-pinned `config.BACKUP_RECIPIENT`
file, NEVER anything a job manifest might supply -- a job cannot redirect
the backup to an attacker's key.

box/handlers/backup-ca is a standalone, extensionless script (like
box/handlers/ca-bootstrap/sign-hosts before it) -- loaded in-process via
importlib exactly like test_handler_ca_bootstrap.py's
`_load_ca_bootstrap_module()` precedent, so its `sys.path.append(
"/usr/local/lib")` + `from causb import ...` at module scope behave
identically to a real standalone invocation.

`age_run` is injected as a fake recorder (mirrors test_handler_ca_bootstrap
.py's `_FakeNebulaCa` / this project's established `runner=`/DI-seam
convention): it never shells out to the real `age` binary, just records
every call's bound arguments and writes recognizable fake ciphertext bytes
to the `out_path` it's given -- exactly the way age itself would populate
`-o <out_path>`. Every test uses fresh tempfile.mkdtemp() dirs for ca_dir/
out_dir, never the real /var/lib/nebula-ca or /etc/nebula-ca.

The real `age`/`age-keygen` round trip (a throwaway keypair genuinely
encrypting then decrypting a fake key) is NOT exercised here -- neither
binary is installed on this dev machine -- and was instead verified live
against the box in a throwaway /tmp directory; see
tests/integration/backup-ca.md.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
import importlib.machinery
import importlib.util
from unittest import mock

from causb import config

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BACKUP_CA_HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "backup-ca")

FAKE_KEY_BYTES = b"FAKE-CA-PRIVATE-KEY-SECRET-MATERIAL-DO-NOT-LEAK-9a2e"
FAKE_AGE_CIPHERTEXT_BYTES = b"age-encryption.org/v1\nFAKE-CIPHERTEXT-BYTES-NOT-THE-KEY-b71c"
FAKE_RECIPIENT_CONTENT = b"age1qzxg8jl9v9c9jkeqzq0d8dnml7yh6t3fpv73eqcnpqp8hqxjfxjqas7dqez\n"


def _load_backup_ca_module():
    loader = importlib.machinery.SourceFileLoader("backup_ca_handler_under_test", BACKUP_CA_HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _job(args=None):
    return {
        "job_id": "33333333-3333-4333-8333-333333333333",
        "operation": "backup-ca",
        "args": {} if args is None else args,
        "payload": [],
    }


class _FakeAgeRun:
    """Stands in for the handler's `age_run` DI seam (production: a local
    `_age_encrypt` wrapper shelling out to the real `age` binary). Records
    every call's bound arguments (recipient_path, in_path, out_path -- a
    real parameter list, like test_handler_ca_bootstrap.py's
    `_FakeNebulaCa`, so an assertion against `self.calls[0]["recipient_path"]`
    is correct regardless of positional/keyword call style) and writes
    recognizable fake ciphertext bytes to `out_path`, exactly like the real
    `age -o out_path ...` would populate it."""

    def __init__(self, ciphertext=FAKE_AGE_CIPHERTEXT_BYTES, raise_exc=None, write_before_raise=False):
        self.calls = []
        self.ciphertext = ciphertext
        self.raise_exc = raise_exc
        self.write_before_raise = write_before_raise

    def __call__(self, recipient_path, in_path, out_path):
        self.calls.append({
            "recipient_path": recipient_path, "in_path": in_path, "out_path": out_path,
        })
        if self.raise_exc is not None:
            if self.write_before_raise:
                # Simulates a real `age` invocation that partially wrote its
                # output before failing/timing out -- proves the handler
                # cleans up rather than leaving a partial ciphertext behind.
                with open(out_path, "wb") as f:
                    f.write(b"PARTIAL-GARBAGE-NOT-VALID-CIPHERTEXT")
            raise self.raise_exc
        with open(out_path, "wb") as f:
            f.write(self.ciphertext)


class _BackupCaTestBase(unittest.TestCase):
    def setUp(self):
        self.mod = _load_backup_ca_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-backup-ca-test-")
        self.ca_dir = os.path.join(self.tmp, "ca")
        os.makedirs(self.ca_dir)
        self.ca_key_path = os.path.join(self.ca_dir, "ca.key")
        with open(self.ca_key_path, "wb") as f:
            f.write(FAKE_KEY_BYTES)
        self.recipient_path = os.path.join(self.tmp, "backup-recipient.age")
        with open(self.recipient_path, "wb") as f:
            f.write(FAKE_RECIPIENT_CONTENT)
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, job=None, fake=None, **overrides):
        fake = fake if fake is not None else _FakeAgeRun()
        kwargs = dict(ca_dir=self.ca_dir, recipient_path=self.recipient_path, age_run=fake)
        kwargs.update(overrides)
        rc = self.mod.run(job or _job(), self.payload_dir, self.out_dir, **kwargs)
        return rc, fake


class TestHappyPath(_BackupCaTestBase):
    def test_happy_path_writes_ca_key_age_and_returns_ok(self):
        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_OK)
        out_path = os.path.join(self.out_dir, "ca.key.age")
        self.assertTrue(os.path.isfile(out_path))
        with open(out_path, "rb") as f:
            self.assertEqual(f.read(), FAKE_AGE_CIPHERTEXT_BYTES)

    def test_age_run_called_once_with_box_recipient_ca_key_and_out_path(self):
        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(fake.calls), 1)
        call = fake.calls[0]
        self.assertEqual(call["recipient_path"], self.recipient_path)
        self.assertEqual(call["in_path"], self.ca_key_path)
        self.assertEqual(call["out_path"], os.path.join(self.out_dir, "ca.key.age"))


class TestManifestRecipientIgnored(_BackupCaTestBase):
    def test_manifest_recipient_field_is_ignored_box_recipient_used(self):
        # A job manifest attempting to redirect the backup to an
        # attacker-controlled recipient must have ZERO effect: the box-
        # pinned recipient_path (a DI seam, production config.
        # BACKUP_RECIPIENT) is what age_run is always called with.
        attacker_recipient = os.path.join(self.tmp, "attacker-recipient.age")
        with open(attacker_recipient, "wb") as f:
            f.write(b"age1attackerscontrolledrecipientkeyxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
        job = _job(args={"recipient": attacker_recipient})

        rc, fake = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["recipient_path"], self.recipient_path)
        self.assertNotEqual(fake.calls[0]["recipient_path"], attacker_recipient)

    def test_manifest_with_arbitrary_junk_args_has_no_effect(self):
        job = _job(args={"recipient": "ignored", "anything": ["also", "ignored"], "num": 7})
        rc, fake = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(fake.calls[0]["recipient_path"], self.recipient_path)

    def test_non_dict_job_args_does_not_crash(self):
        job = _job(args=["not", "a", "dict"])
        rc, fake = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)


class TestPlaintextNeverInOutDir(_BackupCaTestBase):
    def test_ca_key_bytes_never_appear_anywhere_under_out_dir(self):
        """Mutation-proof: a bug that copied ca_dir wholesale (or wrote the
        plaintext key alongside the ciphertext) would plant ca.key -- or its
        BYTES -- somewhere under out_dir. This walks the ENTIRE out_dir tree
        and checks both the filename and the byte content, so it fails
        under that exact mutation, mirroring
        test_handler_ca_bootstrap.py's TestKeyNeverReachesOutDir."""
        rc, _ = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)

        found_files = []
        for root, _dirs, files in os.walk(self.out_dir):
            for name in files:
                found_files.append(os.path.join(root, name))

        self.assertTrue(found_files, "expected out_dir to contain ca.key.age")

        for path in found_files:
            self.assertNotEqual(os.path.basename(path), "ca.key")
            with open(path, "rb") as f:
                content = f.read()
            self.assertNotIn(FAKE_KEY_BYTES, content)

    def test_out_dir_contains_only_the_encrypted_blob(self):
        rc, _ = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(os.listdir(self.out_dir), ["ca.key.age"])


class TestNotBootstrapped(_BackupCaTestBase):
    def test_missing_ca_key_returns_not_bootstrapped(self):
        os.remove(self.ca_key_path)

        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)
        self.assertEqual(fake.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])


class TestNoRecipient(_BackupCaTestBase):
    def test_missing_recipient_file_returns_no_recipient(self):
        os.remove(self.recipient_path)

        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_NO_RECIPIENT)
        self.assertEqual(fake.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_empty_recipient_file_returns_no_recipient(self):
        with open(self.recipient_path, "wb") as f:
            pass  # truncate to 0 bytes

        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_NO_RECIPIENT)
        self.assertEqual(fake.calls, [])

    def test_recipient_path_pointing_at_a_directory_returns_no_recipient(self):
        os.remove(self.recipient_path)
        os.makedirs(self.recipient_path)

        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_NO_RECIPIENT)
        self.assertEqual(fake.calls, [])

    def test_not_bootstrapped_checked_before_no_recipient(self):
        # Both missing -> not_bootstrapped wins (brief's own check order:
        # ca.key existence first, then recipient).
        os.remove(self.ca_key_path)
        os.remove(self.recipient_path)

        rc, fake = self._run()

        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)


class TestAgeErrorMapping(_BackupCaTestBase):
    def test_age_failed_reason_maps_to_age_failed_exit(self):
        fake = _FakeAgeRun(raise_exc=self.mod.AgeError("age_failed"))
        rc, _ = self._run(fake=fake)
        self.assertEqual(rc, self.mod.EXIT_AGE_FAILED)
        self.assertNotEqual(rc, 0)

    def test_timeout_reason_maps_to_timeout_exit(self):
        fake = _FakeAgeRun(raise_exc=self.mod.AgeError("timeout"))
        rc, _ = self._run(fake=fake)
        self.assertEqual(rc, self.mod.EXIT_TIMEOUT)

    def test_tool_missing_reason_maps_to_tool_missing_exit(self):
        fake = _FakeAgeRun(raise_exc=self.mod.AgeError("tool_missing"))
        rc, _ = self._run(fake=fake)
        self.assertEqual(rc, self.mod.EXIT_TOOL_MISSING)

    def test_failed_age_run_leaves_no_partial_ciphertext_in_out_dir(self):
        # Mutation-proof cleanup check: age_run wrote partial garbage to
        # out_path THEN raised -- the handler must not leave that partial
        # file sitting in out_dir looking like a usable backup.
        fake = _FakeAgeRun(raise_exc=self.mod.AgeError("age_failed"), write_before_raise=True)
        rc, _ = self._run(fake=fake)
        self.assertEqual(rc, self.mod.EXIT_AGE_FAILED)
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_age_error_does_not_wedge_a_retry(self):
        failing_fake = _FakeAgeRun(raise_exc=self.mod.AgeError("timeout"))
        first_rc, _ = self._run(fake=failing_fake)
        self.assertEqual(first_rc, self.mod.EXIT_TIMEOUT)

        retry_fake = _FakeAgeRun()
        second_rc, _ = self._run(fake=retry_fake)
        self.assertEqual(second_rc, self.mod.EXIT_OK)
        self.assertEqual(len(retry_fake.calls), 1)


class TestAgeEncryptWrapper(unittest.TestCase):
    """Direct coverage of the handler's own local `_age_encrypt` DI-seam
    default: list-argv shape, control-char rejection, and the nonzero/
    timeout/missing-binary error mapping -- mirrors test_nebulacli.py's
    identical discipline for causb.nebulacli's own wrapper (module
    docstring: "keep the same discipline as nebulacli")."""

    def setUp(self):
        self.mod = _load_backup_ca_module()

    class _RecordingRunner:
        def __init__(self, outcome):
            self.outcome = outcome
            self.calls = []

        def __call__(self, argv, **kwargs):
            assert kwargs.get("shell") is not True, "must never use shell=True"
            self.calls.append((list(argv), kwargs))
            if isinstance(self.outcome, BaseException):
                raise self.outcome
            rc, stdout, stderr = self.outcome
            return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=stderr)

    def test_builds_exact_argv(self):
        runner = self._RecordingRunner((0, "", ""))
        self.mod._age_encrypt("recipients.age", "ca.key", "ca.key.age", runner=runner)
        argv, kwargs = runner.calls[0]
        self.assertEqual(argv, ["age", "-R", "recipients.age", "-o", "ca.key.age", "ca.key"])
        self.assertIsNot(kwargs.get("shell"), True)

    def test_nonzero_returncode_maps_to_age_failed_and_hides_stderr(self):
        runner = self._RecordingRunner((1, "", "some sensitive diagnostic"))
        with self.assertRaises(self.mod.AgeError) as cm:
            self.mod._age_encrypt("recipients.age", "ca.key", "ca.key.age", runner=runner)
        self.assertEqual(cm.exception.reason, "age_failed")
        self.assertNotIn("sensitive diagnostic", str(cm.exception))

    def test_timeout_expired_maps_to_timeout(self):
        runner = self._RecordingRunner(subprocess.TimeoutExpired(cmd="age", timeout=30))
        with self.assertRaises(self.mod.AgeError) as cm:
            self.mod._age_encrypt("recipients.age", "ca.key", "ca.key.age", runner=runner)
        self.assertEqual(cm.exception.reason, "timeout")

    def test_file_not_found_maps_to_tool_missing(self):
        runner = self._RecordingRunner(FileNotFoundError())
        with self.assertRaises(self.mod.AgeError) as cm:
            self.mod._age_encrypt("recipients.age", "ca.key", "ca.key.age", runner=runner)
        self.assertEqual(cm.exception.reason, "tool_missing")

    def test_control_char_in_recipient_path_rejected_before_exec(self):
        runner = self._RecordingRunner((0, "", ""))
        with self.assertRaises(ValueError):
            self.mod._age_encrypt("recipients\x00.age", "ca.key", "ca.key.age", runner=runner)
        self.assertEqual(runner.calls, [])

    def test_control_char_in_out_path_rejected_before_exec(self):
        runner = self._RecordingRunner((0, "", ""))
        with self.assertRaises(ValueError):
            self.mod._age_encrypt("recipients.age", "ca.key", "ca.key\x7f.age", runner=runner)
        self.assertEqual(runner.calls, [])


class TestMainShim(_BackupCaTestBase):
    def _write_job_json(self, job):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump(job, f)
        return path

    def test_main_argv_contract_reads_job_json_and_runs(self):
        # run()'s ca_dir=config.CA_DIR / recipient_path=config.BACKUP_RECIPIENT
        # / age_run=_age_encrypt defaults are bound at function-DEFINITION
        # time (mirrors test_handler_ca_bootstrap.py's identical note) -- so
        # config must be patched, and subprocess.run patched (the innermost
        # default _age_encrypt's own runner= binds to), BEFORE this test's
        # fresh module load, not after.
        job_path = self._write_job_json(_job())
        orig_ca_dir = config.CA_DIR
        orig_recipient = config.BACKUP_RECIPIENT
        config.CA_DIR = self.ca_dir
        config.BACKUP_RECIPIENT = self.recipient_path

        calls = []

        def fake_runner(argv, **kwargs):
            calls.append(list(argv))
            out_path = argv[argv.index("-o") + 1]
            with open(out_path, "wb") as f:
                f.write(FAKE_AGE_CIPHERTEXT_BYTES)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        try:
            with mock.patch("subprocess.run", fake_runner):
                mod = _load_backup_ca_module()  # fresh exec -- binds the patched values above
                rc = mod.main(["backup-ca", job_path, self.payload_dir, self.out_dir])
        finally:
            config.CA_DIR = orig_ca_dir
            config.BACKUP_RECIPIENT = orig_recipient

        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ["age", "-R"])
        out_path = os.path.join(self.out_dir, "ca.key.age")
        with open(out_path, "rb") as f:
            self.assertEqual(f.read(), FAKE_AGE_CIPHERTEXT_BYTES)

    def test_main_wrong_argc_returns_fault(self):
        rc = self.mod.main(["backup-ca", "only-one-arg"])
        self.assertEqual(rc, self.mod.EXIT_FAULT)

    def test_main_unparseable_job_json_returns_bad_manifest(self):
        path = os.path.join(self.tmp, "bad-job.json")
        with open(path, "w") as f:
            f.write("not json{{{")
        rc = self.mod.main(["backup-ca", path, self.payload_dir, self.out_dir])
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)


if __name__ == "__main__":
    unittest.main()
