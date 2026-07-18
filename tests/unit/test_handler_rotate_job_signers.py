"""Tests for box/handlers/rotate-job-signers: the co-sign-aware trust-anchor
rotation handler (S8, R6, D9, D20; CA operation handlers plan, Task 6).

This is the MOST security-sensitive handler in the harness -- it edits the
files that decide WHO may command the CA (allowed_signers) and WHO may
co-authorize a break-glass change (breakglass_signers). The load-bearing
properties this suite pins:

  1. Changing ONLY allowed_signers is authorized by the operator's primary
     signature alone (cosigned need not be True).
  2. ANY change to the breakglass_signers key-SET requires `cosigned is
     True` -- a truthy non-bool ("True", 1, ...) is REFUSED (fail closed),
     and the on-disk anchors are BYTE-UNCHANGED when it is refused.
  3. allowed_signers and breakglass_signers key-sets stay disjoint (R6) --
     an install that would put one key blob in both is rejected `overlap`,
     changing nothing. Disjointness is checked against the UNION of the old
     and new breakglass sets so the allowed-first write order can never
     leave an unsafe (overlapping) intermediate on a partial write.
  4. allowed_signers can never become empty (D9 self-lockout prevention).
  5. Every non-comment/non-blank proposed anchor line must parse to a key
     blob (via verify._key_blobs's own rule) -- an unparseable line fails
     closed `bad_signers`, never silently skipped.
  6. On ANY validation failure the on-disk anchors are BYTE-UNCHANGED
     (everything is validated before EITHER file is touched).

Keys are real ephemeral ed25519 keypairs generated with ssh-keygen (the same
fixture strategy as test_verify.py) so the installed anchors are genuinely
well-formed -- test 8 proves a real `ssh-keygen -Y verify` accepts a
signature from a freshly-installed operator key. No test touches the box's
real /etc/nebula-ca; allowed_path/breakglass_path are injected temp paths.
"""

import base64
import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from causb import verify

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "rotate-job-signers")


def _load_module():
    loader = importlib.machinery.SourceFileLoader("rotate_job_signers_under_test", HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _sh(argv):
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _gen_key(keydir, name, comment):
    key_path = os.path.join(keydir, name)
    _sh(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", key_path, "-q"])
    return key_path


def _line(principal, key_path):
    """One allowed-signers line in this harness's S4 format:
    "<principal> <keytype> <base64> <comment>\\n"."""
    with open(key_path + ".pub") as f:
        keytype, b64 = f.read().split()[:2]
    return f"{principal} {keytype} {b64} {principal}\n"


def _blob(key_path):
    with open(key_path + ".pub") as f:
        keytype, b64 = f.read().split()[:2]
    return (keytype, b64)


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class _RotateBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()
        cls.keydir = tempfile.mkdtemp(prefix="causb-rotate-keys-")
        # A stable stable of distinct ephemeral keypairs reused across tests.
        cls.op1 = _gen_key(cls.keydir, "op1", "nebula-ca-operator")
        cls.op2 = _gen_key(cls.keydir, "op2", "nebula-ca-operator")
        cls.op3 = _gen_key(cls.keydir, "op3", "nebula-ca-operator")
        cls.bg1 = _gen_key(cls.keydir, "bg1", "nebula-ca-breakglass")
        cls.bg2 = _gen_key(cls.keydir, "bg2", "nebula-ca-breakglass")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keydir, ignore_errors=True)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-rotate-test-")
        self.etc = os.path.join(self.tmp, "etc")
        os.makedirs(self.etc)
        self.allowed_path = os.path.join(self.etc, "allowed_signers")
        self.breakglass_path = os.path.join(self.etc, "breakglass_signers")
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)

        # Initial installed anchors: allowed={op1}, breakglass={bg1}.
        self._install_anchor(self.allowed_path, [("nebula-ca-operator", self.op1)], 0o644)
        self._install_anchor(self.breakglass_path, [("nebula-ca-breakglass", self.bg1)], 0o444)
        self.orig_allowed = _read_bytes(self.allowed_path)
        self.orig_breakglass = _read_bytes(self.breakglass_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- fixture helpers --

    def _install_anchor(self, path, entries, mode):
        with open(path, "w") as f:
            for principal, key in entries:
                f.write(_line(principal, key))
        os.chmod(path, mode)

    def _write_payload_allowed(self, entries=None, raw=None):
        self._write_payload("allowed_signers", entries, raw)

    def _write_payload_breakglass(self, entries=None, raw=None):
        self._write_payload("breakglass_signers", entries, raw)

    def _write_payload(self, name, entries=None, raw=None):
        path = os.path.join(self.payload_dir, name)
        with open(path, "w") as f:
            if raw is not None:
                f.write(raw)
            else:
                for principal, key in entries:
                    f.write(_line(principal, key))
        return path

    def _run(self, cosigned=None, job=None, bg_authorized=None):
        return self.mod.run(
            job if job is not None else {"job_id": "job-rotate-1"},
            self.payload_dir,
            self.out_dir,
            allowed_path=self.allowed_path,
            breakglass_path=self.breakglass_path,
            cosigned=cosigned,
            bg_authorized=bg_authorized,
        )

    def _mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def _receipt(self):
        with open(os.path.join(self.out_dir, "rotate-receipt.json")) as f:
            return json.load(f)

    def _assert_anchors_unchanged(self):
        self.assertEqual(_read_bytes(self.allowed_path), self.orig_allowed)
        self.assertEqual(_read_bytes(self.breakglass_path), self.orig_breakglass)
        # No receipt is produced on any failure path.
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "rotate-receipt.json")))


# 1. allowed-only change, cosigned=False -> APPLIED.
class TestAllowedOnlyChange(_RotateBase):
    def test_allowed_only_rotate_applied_without_cosign(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_OK)
        # New allowed installed (op2), breakglass byte-for-byte untouched.
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})
        self.assertEqual(_read_bytes(self.breakglass_path), self.orig_breakglass)

    def test_allowed_written_with_exact_payload_bytes_and_mode_0644(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self._run(cosigned=False)
        payload_bytes = _read_bytes(os.path.join(self.payload_dir, "allowed_signers"))
        self.assertEqual(_read_bytes(self.allowed_path), payload_bytes)
        self.assertEqual(self._mode(self.allowed_path), 0o644)

    def test_receipt_reports_allowed_changed_and_principal_count(self):
        self._write_payload_allowed([
            ("nebula-ca-operator", self.op2),
            ("nebula-ca-operator", self.op3),
        ])
        self._run(cosigned=False)
        r = self._receipt()
        self.assertTrue(r["allowed_changed"])
        self.assertFalse(r["breakglass_changed"])
        self.assertEqual(r["allowed_principals"], 2)
        self.assertFalse(r["cosigned"])

    def test_adding_a_key_keeps_existing_and_new(self):
        # allowed = op1 (existing) + op2 (added). Still disjoint from bg1.
        self._write_payload_allowed([
            ("nebula-ca-operator", self.op1),
            ("nebula-ca-operator", self.op2),
        ])
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(
            verify._key_blobs(self.allowed_path),
            {_blob(self.op1), _blob(self.op2)},
        )


# 2. breakglass change, non-True cosigned -> cosign_required, byte-unchanged.
class TestBreakglassChangeRequiresCosign(_RotateBase):
    def test_all_non_true_cosigned_values_are_refused(self):
        for bad in (False, None, "True", "true", "1", 1, 2, [1], {"x": 1}, object()):
            with self.subTest(cosigned=bad):
                # Fresh payload each iteration (payload dir persists across
                # the loop, which is fine -- it's overwritten every time).
                self._write_payload_allowed([("nebula-ca-operator", self.op1)])
                self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
                rc = self._run(cosigned=bad)
                self.assertEqual(
                    rc, self.mod.EXIT_COSIGN_REQUIRED,
                    f"cosigned={bad!r} must NOT authorize a break-glass change",
                )
                self._assert_anchors_unchanged()

    def test_removing_breakglass_entirely_also_requires_cosign(self):
        # Proposing an empty (comment-only) breakglass set is still a change
        # to the breakglass key-set -> needs a co-signature.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass(raw="# no break-glass keys\n")
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_COSIGN_REQUIRED)
        self._assert_anchors_unchanged()


# 3. breakglass change, cosigned is True (literal) -> APPLIED.
class TestBreakglassChangeCosigned(_RotateBase):
    def test_breakglass_rotate_applied_when_cosigned_true(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        rc = self._run(cosigned=True)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.breakglass_path), {_blob(self.bg2)})
        self.assertEqual(self._mode(self.breakglass_path), 0o444)

    def test_receipt_reports_breakglass_changed(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        self._run(cosigned=True)
        r = self._receipt()
        self.assertTrue(r["breakglass_changed"])
        self.assertTrue(r["cosigned"])
        self.assertEqual(r["breakglass_principals"], 1)

    def test_comment_only_breakglass_diff_is_not_a_change(self):
        # Same key-set as installed (bg1), only an added comment line -> NOT
        # a break-glass change, so cosigned=False is fine and breakglass is
        # left byte-untouched (compare by PARSED key-set, not raw bytes).
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self._write_payload_breakglass(
            raw="# rotated comment only\n" + _line("nebula-ca-breakglass", self.bg1)
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_OK)
        # breakglass NOT rewritten (byte-identical to the original install).
        self.assertEqual(_read_bytes(self.breakglass_path), self.orig_breakglass)
        r = self._receipt()
        self.assertFalse(r["breakglass_changed"])


# 4. overlap -> overlap, both anchors unchanged.
class TestOverlapRejected(_RotateBase):
    def test_proposed_breakglass_overlaps_proposed_allowed(self):
        # allowed gains op2; breakglass proposed as op2 too -> op2 in both.
        self._write_payload_allowed([
            ("nebula-ca-operator", self.op1),
            ("nebula-ca-operator", self.op2),
        ])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.op2)])
        rc = self._run(cosigned=True)  # cosigned, so only overlap can reject
        self.assertEqual(rc, self.mod.EXIT_OVERLAP)
        self._assert_anchors_unchanged()

    def test_allowed_only_change_overlapping_current_breakglass(self):
        # No breakglass payload (breakglass unchanged), but the new allowed
        # set includes bg1 -- which is the CURRENT break-glass key. Installing
        # it would create a self-cosign vector, so it must be rejected even
        # though breakglass itself is untouched.
        self._write_payload_allowed([
            ("nebula-ca-operator", self.op1),
            ("nebula-ca-breakglass", self.bg1),
        ])
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_OVERLAP)
        self._assert_anchors_unchanged()


# 5. empty / only-comments allowed -> would_lockout, unchanged.
class TestWouldLockout(_RotateBase):
    def test_comment_only_allowed_is_would_lockout(self):
        self._write_payload_allowed(raw="# operator retired, no keys\n\n")
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_WOULD_LOCKOUT)
        self._assert_anchors_unchanged()

    def test_empty_allowed_file_is_would_lockout(self):
        self._write_payload_allowed(raw="")
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_WOULD_LOCKOUT)
        self._assert_anchors_unchanged()


# 6. unparseable line -> bad_signers, unchanged.
class TestBadSigners(_RotateBase):
    def test_garbage_line_in_allowed_is_bad_signers(self):
        self._write_payload_allowed(
            raw=_line("nebula-ca-operator", self.op1) + "this is not a key line\n"
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_garbage_line_in_breakglass_is_bad_signers_even_before_cosign(self):
        # Validation precedes the cosign gate: a garbage breakglass line is
        # bad_signers, NOT cosign_required, even with cosigned=False.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass(
            raw=_line("nebula-ca-breakglass", self.bg2) + "@@@ garbage @@@\n"
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_control_char_in_allowed_line_is_bad_signers(self):
        good = _line("nebula-ca-operator", self.op1).rstrip("\n")
        self._write_payload_allowed(raw=good + "\x00\n")  # embedded NUL
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()


# 7. payload/allowed_signers absent -> bad_manifest.
class TestBadManifest(_RotateBase):
    def test_missing_allowed_payload_is_bad_manifest(self):
        # No payload/allowed_signers written at all.
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self._assert_anchors_unchanged()

    def test_missing_allowed_but_present_breakglass_is_still_bad_manifest(self):
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        rc = self._run(cosigned=True)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self._assert_anchors_unchanged()


# 8. Installed anchor round-trips through verify (a real signature is accepted).
class TestInstalledAnchorRoundTrips(_RotateBase):
    def test_new_operator_key_can_sign_a_job_that_verify_accepts(self):
        # Rotate the sole operator key from op1 -> op2, then prove a job
        # signed by op2 is accepted by verify.verify() against the freshly
        # installed allowed_signers -- i.e. the install is genuinely
        # authenticating, not just syntactically plausible.
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_OK)

        tar_path = os.path.join(self.tmp, "job.tar")
        with open(os.path.join(self.tmp, "payload.txt"), "w") as f:
            f.write("sample\n")
        _sh(["tar", "-cf", tar_path, "-C", self.tmp, "payload.txt"])
        sig_copy = os.path.join(self.tmp, "job-signed.tar")
        shutil.copyfile(tar_path, sig_copy)
        _sh(["ssh-keygen", "-Y", "sign", "-f", self.op2, "-n", "nebula-ca-job", sig_copy])

        principal = verify.verify(tar_path, sig_copy + ".sig", self.allowed_path)
        self.assertEqual(principal, "nebula-ca-operator")

    def test_old_operator_key_is_rejected_after_rotation(self):
        # The converse: after rotating op1 -> op2, a job signed by the OLD
        # op1 key must no longer verify against the installed allowed_signers.
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self.assertEqual(self._run(cosigned=False), self.mod.EXIT_OK)

        tar_path = os.path.join(self.tmp, "job.tar")
        with open(os.path.join(self.tmp, "payload.txt"), "w") as f:
            f.write("sample\n")
        _sh(["tar", "-cf", tar_path, "-C", self.tmp, "payload.txt"])
        sig_copy = os.path.join(self.tmp, "job-oldsigned.tar")
        shutil.copyfile(tar_path, sig_copy)
        _sh(["ssh-keygen", "-Y", "sign", "-f", self.op1, "-n", "nebula-ca-job", sig_copy])

        with self.assertRaises(verify.VerifyError):
            verify.verify(tar_path, sig_copy + ".sig", self.allowed_path)


# Simultaneous operator + break-glass rotation (the realistic §13.2 shape).
class TestSimultaneousRotation(_RotateBase):
    def test_rotate_both_operator_and_breakglass_cosigned(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        rc = self._run(cosigned=True)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})
        self.assertEqual(verify._key_blobs(self.breakglass_path), {_blob(self.bg2)})
        r = self._receipt()
        self.assertTrue(r["allowed_changed"])
        self.assertTrue(r["breakglass_changed"])


# Reason vocabulary is exactly the brief's set.
class TestReasonVocabulary(_RotateBase):
    def test_reason_strings_match_brief(self):
        reasons = set(self.mod._REASON_BY_EXIT.values())
        for expected in ("cosign_required", "overlap", "would_lockout",
                         "bad_signers", "bad_manifest", "write_failed"):
            self.assertIn(expected, reasons)


# __main__ shim reads cosigned from CA_USB_COSIGNED (the dispatch bridge).
class TestMainCosignedEnv(_RotateBase):
    def _write_job_json(self):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump({"job_id": "job-main", "operation": "rotate-job-signers"}, f)
        return path

    def test_env_1_authorizes_breakglass_change(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        job_path = self._write_job_json()
        # Point the module's config defaults at our temp anchors for the
        # __main__ path (run() binds allowed_path/breakglass_path defaults at
        # definition time, so patch config BEFORE a fresh module load).
        mod = self._module_with_anchor_config()
        prev = os.environ.get("CA_USB_COSIGNED")
        os.environ["CA_USB_COSIGNED"] = "1"
        try:
            rc = mod.main(["rotate-job-signers", job_path, self.payload_dir, self.out_dir])
        finally:
            if prev is None:
                os.environ.pop("CA_USB_COSIGNED", None)
            else:
                os.environ["CA_USB_COSIGNED"] = prev
        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.breakglass_path), {_blob(self.bg2)})

    def test_env_absent_refuses_breakglass_change(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        job_path = self._write_job_json()
        mod = self._module_with_anchor_config()
        prev = os.environ.pop("CA_USB_COSIGNED", None)
        try:
            rc = mod.main(["rotate-job-signers", job_path, self.payload_dir, self.out_dir])
        finally:
            if prev is not None:
                os.environ["CA_USB_COSIGNED"] = prev
        self.assertEqual(rc, mod.EXIT_COSIGN_REQUIRED)
        self._assert_anchors_unchanged()

    def _module_with_anchor_config(self):
        from causb import config
        orig_allowed, orig_bg = config.ALLOWED, config.BREAKGLASS
        config.ALLOWED = self.allowed_path
        config.BREAKGLASS = self.breakglass_path
        try:
            return _load_module()  # binds patched config defaults
        finally:
            config.ALLOWED = orig_allowed
            config.BREAKGLASS = orig_bg


# [Critical fix] Invalid key MATERIAL must fail closed (D9 silent-lockout hole).
# A known keytype token followed by unloadable material (bad base64, type
# mismatch, truncated wire blob) previously yielded a "blob", passed the
# non-empty D9 check, and INSTALLED with rc=0 + a success receipt -- but
# ssh-keygen cannot load it, so an all-invalid file would permanently brick
# the box's authentication. These tests are mutation-sensitive: reverting the
# material validation makes each install (rc=0) instead of bad_signers.
class TestInvalidKeyMaterialRejected(_RotateBase):
    def test_keytype_with_invalid_base64_is_bad_signers(self):
        self._write_payload_allowed(
            raw="nebula-ca-operator ssh-ed25519 NOTVALIDBASE64!!! op\n"
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_type_mismatch_token_vs_blob_is_bad_signers(self):
        # ssh-rsa token in front of a real ed25519 blob: the embedded wire
        # type ("ssh-ed25519") does not match the declared token ("ssh-rsa").
        keytype, b64 = _blob(self.op2)
        self.assertEqual(keytype, "ssh-ed25519")
        self._write_payload_allowed(raw=f"nebula-ca-operator ssh-rsa {b64} op\n")
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_all_lines_invalid_single_line_brick_case_is_bad_signers(self):
        # THE brick case: the ONLY proposed operator line is unloadable. Must
        # NOT install (would leave the box permanently unauthenticable).
        self._write_payload_allowed(
            raw="nebula-ca-operator ssh-ed25519 NOTVALIDBASE64!!! op\n"
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_valid_line_plus_garbage_line_mixed_is_bad_signers(self):
        # No silent skip: one valid + one keytype+garbage line -> bad_signers,
        # not "install the valid one and drop the garbage".
        good = _line("nebula-ca-operator", self.op1).rstrip("\n")
        self._write_payload_allowed(
            raw=good + "\nnebula-ca-operator ssh-ed25519 NOTVALIDBASE64!!! op2\n"
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_truncated_ed25519_wire_blob_is_bad_signers(self):
        # Valid base64, but the decoded SSH wire blob is truncated (declared
        # key length overruns the bytes present).
        _keytype, b64 = _blob(self.op2)
        truncated = base64.b64encode(base64.b64decode(b64)[:20]).decode()
        self._write_payload_allowed(
            raw=f"nebula-ca-operator ssh-ed25519 {truncated} op\n"
        )
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_wrong_length_ed25519_key_material_is_bad_signers(self):
        # A structurally-well-formed wire blob whose ed25519 key field is 16
        # bytes (not 32): [str "ssh-ed25519"][str 16-bytes]. The generic
        # field-walk consumes it exactly, so ONLY the ed25519-specific
        # 32-byte assertion (or the ssh-keygen backstop) rejects it.
        body = (len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519"
                + (16).to_bytes(4, "big") + b"\x00" * 16)
        b64 = base64.b64encode(body).decode()
        self._write_payload_allowed(raw=f"nebula-ca-operator ssh-ed25519 {b64} op\n")
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_invalid_material_in_breakglass_is_bad_signers(self):
        # Material validation applies to the proposed breakglass too. cosigned
        # so only the material check (not the cosign gate) can reject.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass(
            raw="nebula-ca-breakglass ssh-ed25519 NOTVALIDBASE64!!! bg\n"
        )
        rc = self._run(cosigned=True)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_genuinely_valid_new_allowed_still_installs_no_false_positive(self):
        # The no-false-positive control: a real ssh-keygen-generated key still
        # installs rc=0 and is loadable by ssh-keygen (round-trip proven by
        # TestInstalledAnchorRoundTrips.test_new_operator_key_can_sign_...).
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        rc = self._run(cosigned=False)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})


# F-a: break-glass-ALONE authorization restricts a rotate to allowed_signers.
# When bg_authorized is True (the recovery/lockout path: the operator lost their
# PRIMARY key and a break-glass-ALONE signature authorized this job), the
# handler PERMITS an allowed_signers-only change (install a fresh primary) but
# REFUSES any breakglass_signers change (bg_cannot_change_breakglass) -- changing
# the break-glass set still needs the new primary + a co-signature. Every other
# guard (disjointness, would_lockout, bad_signers key-material) still applies.
class TestBgAuthorized(_RotateBase):
    def test_allowed_only_change_is_applied(self):
        # The recovery path: allowed-only change installs a fresh primary, no
        # cosign needed, break-glass byte-untouched.
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})
        self.assertEqual(_read_bytes(self.breakglass_path), self.orig_breakglass)

    def test_breakglass_change_is_refused_bg_cannot_change_breakglass(self):
        # A bg-authorized job may NOT change the break-glass set. Refused with
        # the dedicated bg_cannot_change_breakglass reason, both anchors
        # byte-unchanged.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_BG_CANNOT_CHANGE_BREAKGLASS)
        self._assert_anchors_unchanged()

    def test_breakglass_change_refused_even_if_cosigned_true(self):
        # Defense-in-depth: even if cosigned is somehow True, a bg-authorized
        # job STILL cannot change break-glass (the bg check precedes the cosign
        # gate). A break-glass rotation is only ever authorized by a genuine
        # PRIMARY + co-sign, never a break-glass-alone signature.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        rc = self._run(cosigned=True, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_BG_CANNOT_CHANGE_BREAKGLASS)
        self._assert_anchors_unchanged()

    def test_removing_breakglass_is_also_refused(self):
        # Proposing an empty (comment-only) breakglass set is still a key-set
        # change -> bg_cannot_change_breakglass.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass(raw="# emptied\n")
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_BG_CANNOT_CHANGE_BREAKGLASS)
        self._assert_anchors_unchanged()

    def test_comment_only_breakglass_diff_is_not_a_change_and_is_allowed(self):
        # A comment-only breakglass edit is NOT a key-set change (same parser as
        # the cosign gate), so a bg-authorized job with an allowed change + a
        # comment-only breakglass payload is still applied; break-glass is left
        # byte-untouched.
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self._write_payload_breakglass(
            raw="# rotated comment only\n" + _line("nebula-ca-breakglass", self.bg1)
        )
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})
        self.assertEqual(_read_bytes(self.breakglass_path), self.orig_breakglass)

    def test_receipt_reports_bg_authorized_true(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self._run(cosigned=False, bg_authorized=True)
        r = self._receipt()
        self.assertTrue(r["bg_authorized"])
        self.assertTrue(r["allowed_changed"])
        self.assertFalse(r["breakglass_changed"])

    def test_non_true_bg_authorized_falls_through_to_normal_behavior(self):
        # STRICT `is True`: a truthy non-bool must NOT trigger the bg path. It
        # falls through to normal handling -- where a break-glass change with
        # cosigned=False is refused by the ordinary cosign gate (cosign_required),
        # still fail-closed, NEVER applied. (Belt-and-suspenders: production
        # always passes a real bool from the CA_USB_BG_AUTHORIZED == "1"
        # comparison; this pins the direct-caller contract.)
        for bad in ("True", "true", "1", 1, 2, [1], {"x": 1}):
            with self.subTest(bg_authorized=bad):
                self._write_payload_allowed([("nebula-ca-operator", self.op1)])
                self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
                rc = self._run(cosigned=False, bg_authorized=bad)
                self.assertEqual(rc, self.mod.EXIT_COSIGN_REQUIRED,
                                 f"bg_authorized={bad!r} must not take the bg path")
                self._assert_anchors_unchanged()

    def test_bg_authorized_false_path_is_unchanged(self):
        # bg_authorized=False is the ordinary path: allowed-only change applies
        # without cosign, exactly as before F-a.
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        rc = self._run(cosigned=False, bg_authorized=False)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})

    def test_bg_authorized_none_default_path_is_unchanged(self):
        # The fail-closed run() default (bg_authorized=None) behaves as
        # not-bg-authorized: a break-glass change still needs cosign.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        rc = self.mod.run(
            {"job_id": "job-rotate-1"}, self.payload_dir, self.out_dir,
            allowed_path=self.allowed_path, breakglass_path=self.breakglass_path,
            cosigned=False,  # bg_authorized omitted -> None default
        )
        self.assertEqual(rc, self.mod.EXIT_COSIGN_REQUIRED)
        self._assert_anchors_unchanged()

    def test_still_enforces_would_lockout(self):
        self._write_payload_allowed(raw="# no keys left\n")
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_WOULD_LOCKOUT)
        self._assert_anchors_unchanged()

    def test_still_enforces_overlap(self):
        # A bg-authorized allowed change overlapping the CURRENT break-glass set
        # is still overlap (the self-cosign vector stays blocked).
        self._write_payload_allowed([
            ("nebula-ca-operator", self.op1),
            ("nebula-ca-breakglass", self.bg1),
        ])
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_OVERLAP)
        self._assert_anchors_unchanged()

    def test_still_enforces_bad_signers_key_material(self):
        self._write_payload_allowed(
            raw="nebula-ca-operator ssh-ed25519 NOTVALIDBASE64!!! op\n"
        )
        rc = self._run(cosigned=False, bg_authorized=True)
        self.assertEqual(rc, self.mod.EXIT_BAD_SIGNERS)
        self._assert_anchors_unchanged()

    def test_still_enforces_bad_manifest_missing_allowed(self):
        rc = self._run(cosigned=False, bg_authorized=True)  # no payload written
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self._assert_anchors_unchanged()

    def test_installed_new_primary_authenticates_after_bg_recovery(self):
        # End-to-end recovery proof: after a bg-authorized allowed-only rotate
        # op1 -> op2, a real ssh-keygen -Y verify (through verify.verify())
        # accepts a job signed by the NEW primary op2 -- the box now trusts the
        # freshly installed operator key, which is the whole point of the
        # break-glass-alone lockout recovery.
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        self.assertEqual(self._run(cosigned=False, bg_authorized=True), self.mod.EXIT_OK)

        tar_path = os.path.join(self.tmp, "job.tar")
        with open(os.path.join(self.tmp, "payload.txt"), "w") as f:
            f.write("sample\n")
        _sh(["tar", "-cf", tar_path, "-C", self.tmp, "payload.txt"])
        sig_copy = os.path.join(self.tmp, "job-signed.tar")
        shutil.copyfile(tar_path, sig_copy)
        _sh(["ssh-keygen", "-Y", "sign", "-f", self.op2, "-n", "nebula-ca-job", sig_copy])

        principal = verify.verify(tar_path, sig_copy + ".sig", self.allowed_path)
        self.assertEqual(principal, "nebula-ca-operator")


# __main__ shim reads bg_authorized from CA_USB_BG_AUTHORIZED (the dispatch
# bridge), strictly `== "1"`, independent of CA_USB_COSIGNED.
class TestMainBgAuthorizedEnv(_RotateBase):
    def _write_job_json(self):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump({"job_id": "job-main-bg", "operation": "rotate-job-signers"}, f)
        return path

    def _module_with_anchor_config(self):
        from causb import config
        orig_allowed, orig_bg = config.ALLOWED, config.BREAKGLASS
        config.ALLOWED = self.allowed_path
        config.BREAKGLASS = self.breakglass_path
        try:
            return _load_module()  # binds patched config defaults into run()
        finally:
            config.ALLOWED = orig_allowed
            config.BREAKGLASS = orig_bg

    def _main_with_env(self, mod, job_path, *, bg, cosigned):
        """Run main() with CA_USB_BG_AUTHORIZED/CA_USB_COSIGNED pinned to `bg`/
        `cosigned` (each a value string or None to unset), restoring both."""
        saved = {k: os.environ.get(k) for k in ("CA_USB_BG_AUTHORIZED", "CA_USB_COSIGNED")}
        for k, v in (("CA_USB_BG_AUTHORIZED", bg), ("CA_USB_COSIGNED", cosigned)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        try:
            return mod.main(["rotate-job-signers", job_path, self.payload_dir, self.out_dir])
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_bg_env_1_authorizes_allowed_only_change(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op2)])
        mod = self._module_with_anchor_config()
        rc = self._main_with_env(mod, self._write_job_json(), bg="1", cosigned=None)
        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(verify._key_blobs(self.allowed_path), {_blob(self.op2)})

    def test_bg_env_1_refuses_breakglass_change(self):
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        mod = self._module_with_anchor_config()
        rc = self._main_with_env(mod, self._write_job_json(), bg="1", cosigned=None)
        self.assertEqual(rc, mod.EXIT_BG_CANNOT_CHANGE_BREAKGLASS)
        self._assert_anchors_unchanged()

    def test_bg_env_absent_is_not_bg_authorized(self):
        # No CA_USB_BG_AUTHORIZED -> bg_authorized False -> a break-glass change
        # (cosign absent) is the ordinary cosign_required, not bg-path.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        mod = self._module_with_anchor_config()
        rc = self._main_with_env(mod, self._write_job_json(), bg=None, cosigned=None)
        self.assertEqual(rc, mod.EXIT_COSIGN_REQUIRED)
        self._assert_anchors_unchanged()

    def test_bg_env_non_1_value_is_not_bg_authorized(self):
        # Only the exact string "1" authorizes; "0"/"true"/anything else is not.
        self._write_payload_allowed([("nebula-ca-operator", self.op1)])
        self._write_payload_breakglass([("nebula-ca-breakglass", self.bg2)])
        mod = self._module_with_anchor_config()
        for val in ("0", "true", "True", "2", ""):
            with self.subTest(env=val):
                rc = self._main_with_env(mod, self._write_job_json(), bg=val, cosigned=None)
                self.assertEqual(rc, mod.EXIT_COSIGN_REQUIRED)
                self._assert_anchors_unchanged()


if __name__ == "__main__":
    unittest.main()
