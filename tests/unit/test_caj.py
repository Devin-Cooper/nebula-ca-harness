"""Tests for mac/caj: the online (Mac-side) job builder + signer (S5, S6, D19).

caj is a standalone CLI script, not an importable causb submodule, so these
tests exercise it exactly as an operator would: spawn it via subprocess with
real argv, then inspect the job.tar/job.tar.sig it drops in <stick>/inbox/.

Every key used here is a fully ephemeral ed25519 keypair generated fresh in
setUp() inside a per-test tempdir (never committed, never touching a real
signing key) -- same fixture style as test_verify.py's TestVerify. The
produced signature is checked against causb.verify.verify() (Task 4) using a
box-style allowed_signers file, and the produced manifest is checked against
causb.manifest.parse() (Task 2) -- both real production code, not
reimplemented assertions -- proving the wire contract round-trips for real.

PYTHONPATH is deliberately SCRUBBED from the subprocess environment (not just
left as inherited from the test runner's own `PYTHONPATH=box/lib`): caj runs
standalone on the operator's Mac in production with no PYTHONPATH set up at
all, so a test that happened to only pass because it inherited the test
harness's own PYTHONPATH would be testing the wrong thing. caj must find
`causb` itself via its own sys.path insertion relative to `__file__`.
"""

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
from unittest import mock

from causb.dispatch import DispatchError, _is_privileged, _run_script
from causb.manifest import parse as manifest_parse
from causb.verify import VerifyError, verify

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAJ_PATH = os.path.join(REPO_ROOT, "mac", "caj")


def _load_caj_module():
    """Import mac/caj (an extensionless script, not a normal .py module) as an
    in-process module, so a white-box test can call its internal helpers (e.g.
    _deliver_atomic) directly. caj's own module-level `sys.path.insert(...box/
    lib)` + `from causb import ...` run at import time and succeed the same way
    they do when caj runs standalone; `if __name__ == "__main__"` guards main()
    so importing has no CLI side effects."""
    loader = importlib.machinery.SourceFileLoader("caj_under_test", CAJ_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _run(argv, **kwargs):
    """Run a fixture-setup command, raising loudly if it fails -- a broken
    fixture must not silently produce a vacuously-passing (or -failing) test."""
    subprocess.run(
        argv,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


class TestCaj(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-caj-test-")

        # Ephemeral operator keypair + a box-style allowed_signers anchor,
        # exactly mirroring test_verify.py's TestVerify.setUp fixture style.
        self.operator_key = os.path.join(self.tmp, "operator_key")
        _run(
            [
                "ssh-keygen", "-t", "ed25519", "-N", "", "-C", "nebula-ca-operator",
                "-f", self.operator_key, "-q",
            ]
        )
        self.allowed_signers = os.path.join(self.tmp, "allowed_signers")
        with open(self.operator_key + ".pub") as f:
            keytype, b64 = f.read().split()[:2]
        with open(self.allowed_signers, "w") as f:
            f.write(f"nebula-ca-operator {keytype} {b64} nebula-ca-operator\n")

        # A DISTINCT ephemeral break-glass keypair + its own anchor file
        # (causb.verify.verify_cosign's "breakglass_signers"), for
        # --breakglass co-sign tests (R6/D20). Deliberately a different key
        # from operator_key -- R6 requires the two sets to be disjoint.
        self.breakglass_key = os.path.join(self.tmp, "breakglass_key")
        _run(
            [
                "ssh-keygen", "-t", "ed25519", "-N", "", "-C", "nebula-ca-breakglass",
                "-f", self.breakglass_key, "-q",
            ]
        )
        self.breakglass_signers = os.path.join(self.tmp, "breakglass_signers")
        with open(self.breakglass_key + ".pub") as f:
            bg_keytype, bg_b64 = f.read().split()[:2]
        with open(self.breakglass_signers, "w") as f:
            f.write(f"nebula-ca-breakglass {bg_keytype} {bg_b64} nebula-ca-breakglass\n")

        # A fresh, isolated seq-bookkeeping directory per test -- caj must
        # never touch this repo checkout's own real ca-state/.
        self.state_dir = os.path.join(self.tmp, "ca-state")

        # Spec dir doubles as the "staging area": caj resolves payload
        # entries relative to the spec file's own directory.
        self.spec_dir = os.path.join(self.tmp, "stage")
        os.makedirs(self.spec_dir)
        self._stage("alice.pub", b"dummy-ed25519-pubkey-bytes-for-alice\n")
        self._stage("bob.pub", b"dummy-ed25519-pubkey-bytes-for-bob\n")

        self.stick = os.path.join(self.tmp, "stick")
        os.makedirs(self.stick)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _stage(self, name, data):
        with open(os.path.join(self.spec_dir, name), "wb") as f:
            f.write(data)

    def _write_spec(self, filename="job.spec", **lines):
        spec_path = os.path.join(self.spec_dir, filename)
        with open(spec_path, "w") as f:
            for key, value in lines.items():
                f.write(f"{key}: {value}\n")
        return spec_path

    def _caj_build(self, spec_path, stick, extra_args=(), env_extra=None):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["CAJ_STATE_DIR"] = self.state_dir
        if env_extra:
            env.update(env_extra)
        argv = [
            sys.executable, CAJ_PATH, "build",
            "--spec", spec_path,
            "--stick", stick,
            "--key", self.operator_key,
        ]
        argv.extend(extra_args)
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def _read_manifest_and_payload_names(self, stick):
        """Read <stick>/inbox/job.tar's manifest.json bytes + the set of
        basenames actually present under payload/, using plain tarfile
        access (this is a test reading its OWN trusted output, not
        adversarial input -- causb.extract's hardening is for the box's
        opposite-direction, hostile-input case)."""
        tar_path = os.path.join(stick, "inbox", "job.tar")
        with tarfile.open(tar_path, "r:") as tar:
            names = tar.getnames()
            raw = tar.extractfile("manifest.json").read()
            payload_names = {
                n[len("payload/"):] for n in names if n.startswith("payload/")
            }
        return raw, payload_names, names

    # --- (a) produced signature verifies via causb.verify.verify() ---

    def test_build_produces_signature_that_verifies_via_causb_verify(self):
        spec_path = self._write_spec(
            name="sign-alice-and-bob",
            operation="sign-hosts",
            box="nebula-ca",
            payload="alice.pub,bob.pub",
            **{"args.groups": "admins", "args.duration": "8760h"},
        )

        result = self._caj_build(spec_path, self.stick)

        assert result.returncode == 0, result.stderr.decode()
        tar_path = os.path.join(self.stick, "inbox", "job.tar")
        sig_path = os.path.join(self.stick, "inbox", "job.tar.sig")
        assert os.path.isfile(tar_path)
        assert os.path.isfile(sig_path)

        principal = verify(tar_path, sig_path, self.allowed_signers)
        assert principal == "nebula-ca-operator"

    # --- "Also assert" the tar members are exactly manifest.json + payload/<name> ---

    def test_build_tar_members_are_exactly_manifest_and_payload_no_traversal(self):
        spec_path = self._write_spec(
            operation="sign-hosts",
            payload="alice.pub,bob.pub",
        )

        result = self._caj_build(spec_path, self.stick)
        assert result.returncode == 0, result.stderr.decode()

        tar_path = os.path.join(self.stick, "inbox", "job.tar")
        with tarfile.open(tar_path, "r:") as tar:
            names = tar.getnames()

        assert set(names) == {"manifest.json", "payload/alice.pub", "payload/bob.pub"}
        for name in names:
            assert not name.startswith("./"), name
            assert not os.path.isabs(name), name
            assert ".." not in name.split("/"), name
            assert len(name.split("/")) <= 4  # causb.config.CAPS["depth"]

    # --- (c) causb.manifest.parse() accepts the emitted manifest ---

    def test_build_manifest_round_trips_through_manifest_parse(self):
        spec_path = self._write_spec(
            name="sign-alice-and-bob",
            operation="sign-hosts",
            box="nebula-ca",
            payload="alice.pub,bob.pub",
            **{"args.groups": "admins", "args.duration": "8760h"},
        )

        result = self._caj_build(spec_path, self.stick)
        assert result.returncode == 0, result.stderr.decode()

        raw, payload_names, _ = self._read_manifest_and_payload_names(self.stick)
        assert payload_names == {"alice.pub", "bob.pub"}

        parsed = manifest_parse(raw, payload_names=payload_names)

        assert parsed["schema_version"] == 1
        assert parsed["box"] == "nebula-ca"
        assert len(parsed["jobs"]) == 1
        job = parsed["jobs"][0]
        assert job["operation"] == "sign-hosts"
        assert set(job["payload"]) == {"alice.pub", "bob.pub"}
        assert job["args"]["groups"] == "admins"
        assert job["args"]["duration"] == "8760h"

    # --- (b) --retry <job_id> reuses job_id but increments seq ---

    def test_retry_reuses_job_id_and_increments_seq(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")
        first_stick = self.stick
        second_stick = os.path.join(self.tmp, "stick2")
        os.makedirs(second_stick)

        first = self._caj_build(spec_path, first_stick)
        assert first.returncode == 0, first.stderr.decode()
        raw1, _, _ = self._read_manifest_and_payload_names(first_stick)
        manifest1 = json.loads(raw1)
        job_id1 = manifest1["jobs"][0]["job_id"]
        seq1 = manifest1["seq"]

        second = self._caj_build(
            spec_path, second_stick, extra_args=["--retry", job_id1]
        )
        assert second.returncode == 0, second.stderr.decode()
        raw2, _, _ = self._read_manifest_and_payload_names(second_stick)
        manifest2 = json.loads(raw2)
        job_id2 = manifest2["jobs"][0]["job_id"]
        seq2 = manifest2["seq"]

        assert job_id2 == job_id1
        assert seq2 == seq1 + 1

    # --- review fix #1: seq is RESERVED before delivery (no reuse on failure) ---

    def test_seq_reserved_before_delivery_so_a_failed_build_never_reuses_it(self):
        # Reproduces the review's "crash after delivery, before recording seq"
        # concern as a deterministic, observable POST-RESERVATION failure: a
        # --key that EXISTS (so caj's up-front isfile check passes) but is not a
        # loadable ssh key makes `ssh-keygen -Y sign` fail -- which caj reaches
        # only AFTER it has already reserved (persisted last-built-seq) the seq.
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")
        bogus_key = os.path.join(self.tmp, "bogus_key")
        with open(bogus_key, "w") as f:
            f.write("not a valid ssh private key\n")

        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["CAJ_STATE_DIR"] = self.state_dir
        failed = subprocess.run(
            [
                sys.executable, CAJ_PATH, "build",
                "--spec", spec_path, "--stick", self.stick, "--key", bogus_key,
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )
        assert failed.returncode == 1, failed.stderr.decode()
        # Nothing was delivered (signing failed before the deliver step) ...
        assert not os.path.exists(os.path.join(self.stick, "inbox", "job.tar"))
        assert not os.path.exists(os.path.join(self.stick, "inbox", "job.tar.sig"))
        # ... but the seq WAS reserved (last-built-seq advanced to 1) despite it.
        last_built_path = os.path.join(self.state_dir, "last-built-seq")
        with open(last_built_path) as f:
            assert int(f.read().strip()) == 1

        # A subsequent SUCCESSFUL build gets a STRICTLY HIGHER seq (2) -- it
        # never reuses the reserved-but-undelivered seq 1, so no two delivered
        # jobs can ever share a seq (the box's monotonic gate stays satisfiable).
        ok = self._caj_build(spec_path, self.stick)
        assert ok.returncode == 0, ok.stderr.decode()
        raw, _, _ = self._read_manifest_and_payload_names(self.stick)
        assert json.loads(raw)["seq"] == 2

    def test_two_sequential_builds_get_strictly_increasing_seqs(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")
        stick2 = os.path.join(self.tmp, "stick_seq2")
        os.makedirs(stick2)

        first = self._caj_build(spec_path, self.stick)
        assert first.returncode == 0, first.stderr.decode()
        raw1, _, _ = self._read_manifest_and_payload_names(self.stick)
        manifest1 = json.loads(raw1)

        second = self._caj_build(spec_path, stick2)
        assert second.returncode == 0, second.stderr.decode()
        raw2, _, _ = self._read_manifest_and_payload_names(stick2)
        manifest2 = json.loads(raw2)

        assert manifest1["seq"] == 1
        assert manifest2["seq"] == 2  # strictly increasing across sequential builds
        # Two independent builds (no --retry) mint distinct fresh uuid4 job_ids.
        assert manifest2["jobs"][0]["job_id"] != manifest1["jobs"][0]["job_id"]

    # --- review fix #2: duplicate payload basename is rejected ---

    def test_duplicate_payload_basename_is_rejected(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,alice.pub")

        result = self._caj_build(spec_path, self.stick)

        assert result.returncode == 1
        assert b"duplicate payload basename" in result.stderr, result.stderr.decode()
        # No malformed artifact was produced ...
        assert not os.path.exists(os.path.join(self.stick, "inbox", "job.tar"))
        # ... and no seq was reserved (duplicate rejection happens during spec
        # parse, before the flock/seq-reservation is ever reached).
        assert not os.path.exists(os.path.join(self.state_dir, "last-built-seq"))

    # --- review fix #3: delivery is atomic (tmp -> rename), signature last ---

    def test_delivery_uses_tmp_then_rename_with_sig_last(self):
        caj_mod = _load_caj_module()

        inbox = os.path.join(self.tmp, "wb_inbox")
        os.makedirs(inbox)
        src_tar = os.path.join(self.tmp, "wb_src.tar")
        src_sig = os.path.join(self.tmp, "wb_src.tar.sig")
        with open(src_tar, "wb") as f:
            f.write(b"TAR-BYTES")
        with open(src_sig, "wb") as f:
            f.write(b"SIG-BYTES")

        real_replace = os.replace
        calls = []

        def spy_replace(src, dst):
            # At the instant of each rename: the temp source exists and the
            # FINAL destination does not yet exist -- i.e. the final name is
            # only ever created by renaming a fully-written temp, never written
            # to directly. Record basenames to check ordering + tmp usage.
            calls.append((os.path.basename(src), os.path.basename(dst)))
            assert os.path.exists(src), src
            assert not os.path.exists(dst), dst
            return real_replace(src, dst)

        with mock.patch("os.replace", spy_replace):
            caj_mod._deliver_atomic(src_tar, src_sig, inbox)

        # Exactly two tmp->rename moves, in order, .sig LAST, both from .tmp names.
        assert calls == [
            ("job.tar.tmp", "job.tar"),
            ("job.tar.sig.tmp", "job.tar.sig"),
        ]
        with open(os.path.join(inbox, "job.tar"), "rb") as f:
            assert f.read() == b"TAR-BYTES"
        with open(os.path.join(inbox, "job.tar.sig"), "rb") as f:
            assert f.read() == b"SIG-BYTES"
        # No .tmp litter survives a completed delivery.
        assert [n for n in os.listdir(inbox) if n.endswith(".tmp")] == []

    # --- Task 7: `--breakglass <key>` emits inbox/job.tar.bg.sig (R6 co-sign) ---

    def test_breakglass_flag_produces_bg_sig_alongside_tar_and_primary_sig(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")

        result = self._caj_build(
            spec_path, self.stick, extra_args=["--breakglass", self.breakglass_key]
        )

        assert result.returncode == 0, result.stderr.decode()
        inbox = os.path.join(self.stick, "inbox")
        assert os.path.isfile(os.path.join(inbox, "job.tar"))
        assert os.path.isfile(os.path.join(inbox, "job.tar.sig"))
        assert os.path.isfile(os.path.join(inbox, "job.tar.bg.sig"))

    def test_without_breakglass_flag_no_bg_sig_is_produced(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")

        result = self._caj_build(spec_path, self.stick)

        assert result.returncode == 0, result.stderr.decode()
        inbox = os.path.join(self.stick, "inbox")
        assert os.path.isfile(os.path.join(inbox, "job.tar"))
        assert os.path.isfile(os.path.join(inbox, "job.tar.sig"))
        # Unchanged behavior: a job built with no --breakglass never produces
        # a job.tar.bg.sig -- it will correctly fail the box's cosign_required
        # gate for any operation that needs one, rather than silently getting
        # (or forging) a co-signature it was never asked to carry.
        assert not os.path.exists(os.path.join(inbox, "job.tar.bg.sig"))

    def test_breakglass_sig_verifies_against_breakglass_signers_but_not_a_different_key(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")

        result = self._caj_build(
            spec_path, self.stick, extra_args=["--breakglass", self.breakglass_key]
        )
        assert result.returncode == 0, result.stderr.decode()

        tar_path = os.path.join(self.stick, "inbox", "job.tar")
        bg_sig_path = os.path.join(self.stick, "inbox", "job.tar.bg.sig")

        # This is exactly what the box's causb.verify.verify_cosign does:
        # verify the bg signature against the (box-local) breakglass_signers
        # anchor, in the same nebula-ca-job namespace.
        bg_principal = verify(tar_path, bg_sig_path, self.breakglass_signers)
        assert bg_principal == "nebula-ca-breakglass"

        # A DIFFERENT key (the primary operator key, via its own anchor file)
        # must NOT verify the break-glass signature.
        with self.assertRaises(VerifyError):
            verify(tar_path, bg_sig_path, self.allowed_signers)

    def test_breakglass_sig_covers_the_same_tar_bytes_as_the_primary_sig(self):
        spec_path = self._write_spec(operation="sign-hosts", payload="alice.pub,bob.pub")

        result = self._caj_build(
            spec_path, self.stick, extra_args=["--breakglass", self.breakglass_key]
        )
        assert result.returncode == 0, result.stderr.decode()

        inbox = os.path.join(self.stick, "inbox")
        tar_path = os.path.join(inbox, "job.tar")
        sig_path = os.path.join(inbox, "job.tar.sig")
        bg_sig_path = os.path.join(inbox, "job.tar.bg.sig")

        # Both the primary and break-glass signatures verify against the
        # exact same on-disk job.tar -- the whole point of a co-signature
        # (D20/R6) is that it authorizes THIS job, not some other bytes.
        assert verify(tar_path, sig_path, self.allowed_signers) == "nebula-ca-operator"
        assert verify(tar_path, bg_sig_path, self.breakglass_signers) == "nebula-ca-breakglass"

        # Prove the bg.sig is bound to THESE bytes, not merely produced
        # alongside a same-named file by coincidence: a copy of job.tar with
        # a single byte flipped must FAIL break-glass verification against
        # this same job.tar.bg.sig.
        tampered_path = tar_path + ".tampered"
        with open(tar_path, "rb") as f:
            data = bytearray(f.read())
        data[0] ^= 0xFF
        with open(tampered_path, "wb") as f:
            f.write(bytes(data))

        with self.assertRaises(VerifyError):
            verify(tampered_path, bg_sig_path, self.breakglass_signers)

    def test_breakglass_delivery_places_bg_sig_before_the_primary_sig_which_is_last(self):
        caj_mod = _load_caj_module()

        inbox = os.path.join(self.tmp, "wb_inbox_bg")
        os.makedirs(inbox)
        src_tar = os.path.join(self.tmp, "wb_src2.tar")
        src_sig = os.path.join(self.tmp, "wb_src2.tar.sig")
        src_bg_sig = os.path.join(self.tmp, "wb_src2.tar.bg.sig")
        with open(src_tar, "wb") as f:
            f.write(b"TAR-BYTES")
        with open(src_sig, "wb") as f:
            f.write(b"PRIMARY-SIG-BYTES")
        with open(src_bg_sig, "wb") as f:
            f.write(b"BG-SIG-BYTES")

        real_replace = os.replace
        calls = []

        def spy_replace(src, dst):
            calls.append((os.path.basename(src), os.path.basename(dst)))
            assert os.path.exists(src), src
            assert not os.path.exists(dst), dst
            return real_replace(src, dst)

        with mock.patch("os.replace", spy_replace):
            caj_mod._deliver_atomic(src_tar, src_sig, inbox, bg_sig_path=src_bg_sig)

        # job.tar, THEN job.tar.bg.sig, THEN job.tar.sig (primary) LAST -- the
        # primary sig is the box's completeness signal regardless of whether a
        # break-glass co-signature also rides along, so it must remain the
        # final file written: a crash between the bg.sig and primary-sig
        # renames leaves, at worst, a job.tar (+ maybe a bg.sig) with no
        # primary job.tar.sig -- which the box rejects fail-closed, same as
        # the no-breakglass case.
        assert calls == [
            ("job.tar.tmp", "job.tar"),
            ("job.tar.bg.sig.tmp", "job.tar.bg.sig"),
            ("job.tar.sig.tmp", "job.tar.sig"),
        ]
        with open(os.path.join(inbox, "job.tar.sig"), "rb") as f:
            assert f.read() == b"PRIMARY-SIG-BYTES"
        with open(os.path.join(inbox, "job.tar.bg.sig"), "rb") as f:
            assert f.read() == b"BG-SIG-BYTES"
        # No .tmp litter survives a completed delivery.
        assert [n for n in os.listdir(inbox) if n.endswith(".tmp")] == []

    # --- F-b: args.<name> boolean coercion (bare true/false -> JSON bool) ---
    #
    # Follow-on close: _parse_spec used to store EVERY args.<name> value as a
    # plain string, so `args.privileged: true` reached the box as the STRING
    # "true" -- dispatch._is_privileged's strict `is True` check (and
    # rotate-ca's `isinstance(..., bool)` check) correctly refused that shape,
    # which meant a caj-built privileged run-script silently ran UNPRIVILEGED
    # and a caj-built `rotate-ca --compromise` was rejected as bad_manifest --
    # fail-safe, but two real features were unreachable via caj. These tests
    # pin the fix: ONLY the two exact literals `true`/`false` are coerced to
    # real JSON booleans; everything else (including any other casing or
    # truthy-looking string) stays a plain string, unchanged from before.

    def test_parse_spec_coerces_bare_true_false_args_to_json_booleans(self):
        caj_mod = _load_caj_module()
        spec_path = self._write_spec(
            operation="sign-hosts",
            payload="alice.pub",
            **{"args.privileged": "true", "args.compromise": "false"},
        )

        fields = caj_mod._parse_spec(spec_path)

        self.assertIs(fields["args"]["privileged"], True)
        self.assertIs(fields["args"]["compromise"], False)

    def test_parse_spec_leaves_non_boolean_args_as_plain_strings(self):
        caj_mod = _load_caj_module()
        spec_path = self._write_spec(
            operation="sign-hosts",
            payload="alice.pub",
            **{
                "args.duration": "8760h",
                "args.name": "nebula-ca",
                "args.overlay": "10.42.0.0/16",
                # Non-coercion cases: none of these are the exact literal
                # "true"/"false" (case-sensitive, exact-match only), so all
                # must stay plain strings, never bools.
                "args.x": "True",
                "args.y": "yes",
                "args.z": "1",
                "args.w": "truthy",
            },
        )

        fields = caj_mod._parse_spec(spec_path)
        args = fields["args"]

        self.assertEqual(args["duration"], "8760h")
        self.assertEqual(args["name"], "nebula-ca")
        self.assertEqual(args["overlay"], "10.42.0.0/16")
        for name, expected in (
            ("x", "True"), ("y", "yes"), ("z", "1"), ("w", "truthy"),
        ):
            self.assertEqual(args[name], expected)
            self.assertNotIsInstance(args[name], bool)

    def test_privileged_run_script_end_to_end_manifest_bool_and_dispatch_gate(self):
        self._stage("run.sh", b"#!/bin/sh\necho hi\n")
        spec_path = self._write_spec(
            operation="run-script",
            payload="run.sh",
            entrypoint="run.sh",
            **{"args.privileged": "true"},
        )

        result = self._caj_build(spec_path, self.stick)
        assert result.returncode == 0, result.stderr.decode()

        raw, payload_names, _ = self._read_manifest_and_payload_names(self.stick)
        parsed = manifest_parse(raw, payload_names=payload_names)
        job = parsed["jobs"][0]

        # caj emitted a REAL JSON boolean, not the string "true" ...
        self.assertIs(job["args"]["privileged"], True)
        # ... which is exactly the shape dispatch._is_privileged requires.
        self.assertIs(_is_privileged(job), True)

        # SECURITY INVARIANT (unchanged, and NOT relaxed by this fix):
        # `_is_privileged` being True does not itself run anything as root --
        # dispatch._run_script's strict `cosigned is True` gate still applies
        # and still fires BEFORE any child is ever spawned. Prove it with a
        # popen stub that blows up if dispatch ever attempts to invoke it.
        def _must_not_spawn(*_args, **_kwargs):
            raise AssertionError("dispatch must not spawn anything without cosign")

        with self.assertRaises(DispatchError) as ctx:
            _run_script(
                job, payload_dir=self.spec_dir, out_dir=self.tmp,
                cosigned=False, popen=_must_not_spawn, timeout_s=5,
                audit_log_path=os.path.join(self.tmp, "unused-audit.log"),
            )
        self.assertEqual(ctx.exception.reason, "cosign_failed")

    def test_compromise_true_end_to_end_manifest_round_trip(self):
        # The rotate-ca side of the same bug: args.compromise must also
        # reach the box as a real JSON boolean (box/handlers/rotate-ca
        # requires isinstance(args["compromise"], bool)). No payload/
        # dispatch involved here -- purely the caj -> manifest.parse() wire
        # round trip, mirroring test_build_manifest_round_trips_through_
        # manifest_parse's existing style.
        spec_path = self._write_spec(
            operation="rotate-ca",
            **{"args.compromise": "true"},
        )

        result = self._caj_build(spec_path, self.stick)
        assert result.returncode == 0, result.stderr.decode()

        raw, payload_names, _ = self._read_manifest_and_payload_names(self.stick)
        parsed = manifest_parse(raw, payload_names=payload_names)
        job = parsed["jobs"][0]

        self.assertIs(job["args"]["compromise"], True)

    def test_hand_built_string_true_privileged_is_still_rejected_by_dispatch(self):
        # The box's OWN defense is unchanged: a manifest that somehow still
        # carries the old, buggy shape ({"privileged": "true"}, a string --
        # e.g. hand-built, or from some other, non-caj tool) must still be
        # treated as NOT privileged. caj no longer produces this shape; this
        # pins that dispatch's strict check is what actually guarantees that,
        # not caj's good behavior.
        job = {"args": {"privileged": "true"}}
        self.assertIs(_is_privileged(job), False)


if __name__ == "__main__":
    unittest.main()
