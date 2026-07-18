"""Tests for causb.verify: ssh-sig verify + break-glass co-sign (S7.4, R6, D20).

Exercises the real `ssh-keygen -Y {find-principals,sign,verify}` binary via
subprocess -- verify.py's whole job is to get that flow exactly right, so
mocking ssh-keygen itself would test nothing. Every key used here is a fully
ephemeral ed25519 keypair generated fresh in setUp() inside a per-test
tempdir (never committed, never touching the box's real /etc/nebula-ca
anchors) and destroyed in tearDown().
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from causb.verify import VerifyError, verify, verify_breakglass_primary, verify_cosign


def _run(argv):
    """Run a fixture-setup command, raising loudly if it fails -- a broken
    fixture must not silently produce a vacuously-passing (or vacuously
    -failing) test."""
    subprocess.run(
        argv,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class TestVerify(unittest.TestCase):
    """Builds, per test, a fresh ephemeral operator/breakglass/untrusted
    ed25519 keypair trio, allowed_signers/breakglass_signers anchor files
    (S4 format: "<principal> <keytype> <base64> [comment]"), and a sample
    job.tar -- then exercises verify()/verify_cosign() against them."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-verify-test-")

        self.operator_key = self._gen_key("operator_key", "nebula-ca-operator")
        self.breakglass_key = self._gen_key("breakglass_key", "nebula-ca-breakglass")
        self.untrusted_key = self._gen_key("untrusted_key", "untrusted")

        self.allowed_path = os.path.join(self.tmp, "allowed_signers")
        self.breakglass_path = os.path.join(self.tmp, "breakglass_signers")
        self._write_signers_file(
            self.allowed_path, "nebula-ca-operator", self.operator_key + ".pub"
        )
        self._write_signers_file(
            self.breakglass_path, "nebula-ca-breakglass", self.breakglass_key + ".pub"
        )

        self.tar_path = os.path.join(self.tmp, "job.tar")
        with open(os.path.join(self.tmp, "payload.txt"), "w") as f:
            f.write("sample payload\n")
        _run(["tar", "-cf", self.tar_path, "-C", self.tmp, "payload.txt"])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _gen_key(self, name, comment):
        key_path = os.path.join(self.tmp, name)
        _run(
            [
                "ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment,
                "-f", key_path, "-q",
            ]
        )
        return key_path

    @staticmethod
    def _signers_line(principal, pubkey_path):
        """One allowed-signers line in this harness's S4 format:
        "<principal> <keytype> <base64> <comment>\\n"."""
        with open(pubkey_path) as f:
            keytype, b64 = f.read().split()[:2]
        return f"{principal} {keytype} {b64} {principal}\n"

    def _write_signers_file(self, path, principal, pubkey_path):
        with open(path, "w") as f:
            f.write(self._signers_line(principal, pubkey_path))

    def _sign(self, key_path, label):
        """Sign a fresh copy of self.tar_path's bytes (under a throwaway
        `label`) with `key_path`'s private half, namespace nebula-ca-job.
        Returns the produced .sig path. Using a per-call throwaway copy
        (rather than re-signing self.tar_path in place) lets a test hold
        two independent detached signatures over the same underlying bytes
        at once -- exactly the R6 wire shape (job.tar.sig + job.tar.bg.sig
        both cover the same job.tar).
        """
        copy_path = os.path.join(self.tmp, f"{label}.tar")
        shutil.copyfile(self.tar_path, copy_path)
        _run(["ssh-keygen", "-Y", "sign", "-f", key_path, "-n", "nebula-ca-job", copy_path])
        return copy_path + ".sig"

    # --- verify() ---

    def test_valid_signature_returns_operator_principal(self):
        sig_path = self._sign(self.operator_key, "primary")

        principal = verify(self.tar_path, sig_path, self.allowed_path)

        assert principal == "nebula-ca-operator"

    def test_tampered_tar_is_rejected(self):
        sig_path = self._sign(self.operator_key, "primary")
        with open(self.tar_path, "ab") as f:
            f.write(b"tampered")

        with self.assertRaises(VerifyError) as cm:
            verify(self.tar_path, sig_path, self.allowed_path)
        assert cm.exception.reason == "verify_failed"

    def test_untrusted_signer_is_rejected(self):
        sig_path = self._sign(self.untrusted_key, "untrusted")

        with self.assertRaises(VerifyError) as cm:
            verify(self.tar_path, sig_path, self.allowed_path)
        assert cm.exception.reason == "verify_failed"

    # --- verify_cosign() ---

    def test_cosign_with_distinct_breakglass_key_succeeds(self):
        # Positive path: allowed_signers (operator key) and breakglass_signers
        # (a genuinely different break-glass key) are disjoint key sets, and
        # the break-glass sig is made by that distinct key -> OK, no raise.
        bg_sig_path = self._sign(self.breakglass_key, "bg")

        result = verify_cosign(
            self.tar_path, bg_sig_path, self.breakglass_path, self.allowed_path
        )

        assert result is None  # no raise == OK

    def test_cosign_with_same_key_as_primary_is_rejected(self):
        # Single-line rejection: a compromised/misconfigured breakglass_signers
        # registers the PRIMARY's own key under the breakglass principal name.
        # The bg signature below verifies fine against this file in isolation --
        # the distinct-key rule (D20/R6) must still catch it because the two
        # key SETS intersect (both contain the operator key).
        same_key_breakglass_path = os.path.join(self.tmp, "breakglass_signers_samekey")
        self._write_signers_file(
            same_key_breakglass_path, "nebula-ca-breakglass", self.operator_key + ".pub"
        )
        bg_sig_path = self._sign(self.operator_key, "bg-samekey")

        with self.assertRaises(VerifyError) as cm:
            verify_cosign(
                self.tar_path, bg_sig_path, same_key_breakglass_path, self.allowed_path
            )
        assert cm.exception.reason == "cosign_failed"

    def test_cosign_multiline_operator_shared_key_bypass_is_caught(self):
        # Regression for the CRITICAL self-cosign bypass. The realistic D19
        # FIDO2-migration shape: the operator principal spans TWO key lines
        # (old + new). The attacker's key X is the NON-FIRST (line 2) operator
        # line AND the only key in breakglass_signers. Holding only X, the
        # attacker can sign both the primary job and the break-glass sig.
        #
        # The old by-name comparison looked up the operator's FIRST line (a
        # decoy key != X) and wrongly ACCEPTED. Key-set disjointness must now
        # catch it: X is a member of BOTH sets, so they intersect.
        decoy_key = self._gen_key("decoy_key", "nebula-ca-operator")  # line 1 (old)
        attacker_key = self._gen_key("attacker_key", "nebula-ca-operator")  # X, line 2

        multi_allowed = os.path.join(self.tmp, "allowed_signers_multi")
        with open(multi_allowed, "w") as f:
            f.write(self._signers_line("nebula-ca-operator", decoy_key + ".pub"))
            f.write(self._signers_line("nebula-ca-operator", attacker_key + ".pub"))
        shared_breakglass = os.path.join(self.tmp, "breakglass_signers_shared")
        with open(shared_breakglass, "w") as f:
            f.write(self._signers_line("nebula-ca-breakglass", attacker_key + ".pub"))

        # X is a genuinely valid operator signer here (line 2), so verify()
        # accepts the attacker's PRIMARY sig -- proving the only thing standing
        # between the attacker and a successful self-cosign is the disjointness
        # check inside verify_cosign() below (the caller verifies the primary
        # sig separately; verify_cosign is not given it).
        primary_sig = self._sign(attacker_key, "attacker-primary")
        assert verify(self.tar_path, primary_sig, multi_allowed) == "nebula-ca-operator"

        # The attacker's break-glass sig, also made with X, verifies against
        # breakglass_signers in isolation (X is legitimately listed there).
        bg_sig_path = self._sign(attacker_key, "attacker-bg")

        with self.assertRaises(VerifyError) as cm:
            verify_cosign(
                self.tar_path, bg_sig_path, shared_breakglass, multi_allowed
            )
        assert cm.exception.reason == "cosign_failed"

    # --- verify_breakglass_primary() (F-a break-glass-ALONE recovery) ---
    #
    # verify_breakglass_primary is verify() pointed at the break-glass anchor:
    # it authenticates the SAME primary-slot signature (job.tar.sig) against
    # breakglass_signers instead of allowed_signers, for the lockout-recovery
    # case where the operator has LOST their primary key and signs the job.tar
    # with a break-glass key. Same flow/rigor as verify(): find-principals
    # (exactly one) -> -Y verify -n nebula-ca-job -> exit 0; any failure is
    # verify_failed. The ca-usb-run fallback additionally gates on
    # operation=="rotate-job-signers"; that scoping is tested in
    # test_ca_usb_run.py -- here we pin the verifier itself.

    def test_breakglass_signed_job_verifies_against_breakglass_anchor(self):
        # A job signed by the break-glass key verifies against breakglass_signers
        # and returns the break-glass principal.
        sig_path = self._sign(self.breakglass_key, "bg-primary")

        principal = verify_breakglass_primary(
            self.tar_path, sig_path, self.breakglass_path
        )

        assert principal == "nebula-ca-breakglass"

    def test_primary_signed_job_does_not_verify_against_breakglass_anchor(self):
        # THE core scoping proof at the verifier level: an OPERATOR (primary)
        # signature must NOT authenticate against the break-glass anchor. R6
        # disjointness guarantees the operator key is not in breakglass_signers,
        # so find-principals returns no match -> verify_failed.
        sig_path = self._sign(self.operator_key, "op-primary")

        with self.assertRaises(VerifyError) as cm:
            verify_breakglass_primary(self.tar_path, sig_path, self.breakglass_path)
        assert cm.exception.reason == "verify_failed"

    def test_breakglass_signed_job_does_not_verify_as_operator_primary(self):
        # The converse symmetry: a break-glass signature must NOT pass verify()
        # against allowed_signers. This is what makes the ca-usb-run fallback
        # strictly ADDITIVE -- verify() is unweakened, a break-glass sig only
        # ever authenticates via verify_breakglass_primary against the
        # break-glass anchor, never widens who may run an ordinary job.
        sig_path = self._sign(self.breakglass_key, "bg-as-op")

        with self.assertRaises(VerifyError) as cm:
            verify(self.tar_path, sig_path, self.allowed_path)
        assert cm.exception.reason == "verify_failed"

    def test_breakglass_primary_tampered_tar_is_rejected(self):
        sig_path = self._sign(self.breakglass_key, "bg-primary")
        with open(self.tar_path, "ab") as f:
            f.write(b"tampered")

        with self.assertRaises(VerifyError) as cm:
            verify_breakglass_primary(self.tar_path, sig_path, self.breakglass_path)
        assert cm.exception.reason == "verify_failed"

    def test_breakglass_primary_untrusted_key_is_rejected(self):
        # A signature from a key in NEITHER anchor fails against breakglass too.
        sig_path = self._sign(self.untrusted_key, "untrusted")

        with self.assertRaises(VerifyError) as cm:
            verify_breakglass_primary(self.tar_path, sig_path, self.breakglass_path)
        assert cm.exception.reason == "verify_failed"

    def test_breakglass_primary_wrong_namespace_is_rejected(self):
        # The nebula-ca-job namespace binding is preserved for the bg path: a
        # signature made under a different namespace must not verify.
        copy_path = os.path.join(self.tmp, "wrongns.tar")
        shutil.copyfile(self.tar_path, copy_path)
        _run(["ssh-keygen", "-Y", "sign", "-f", self.breakglass_key,
              "-n", "not-nebula-ca-job", copy_path])

        with self.assertRaises(VerifyError) as cm:
            verify_breakglass_primary(
                self.tar_path, copy_path + ".sig", self.breakglass_path
            )
        assert cm.exception.reason == "verify_failed"

    def test_breakglass_primary_relative_anchor_path_raises_valueerror(self):
        # Same S7.4 absolute-anchor guard as verify(): a relative anchor path
        # is a caller/config bug (ValueError), not a signature failure.
        sig_path = self._sign(self.breakglass_key, "bg-primary")
        with self.assertRaises(ValueError):
            verify_breakglass_primary(
                self.tar_path, sig_path, "relative/breakglass_signers"
            )

    def test_breakglass_primary_missing_anchor_is_verify_failed(self):
        # A missing anchor file is an infrastructure failure that folds into
        # the fixed verify_failed enum (fail closed), exactly like verify().
        sig_path = self._sign(self.breakglass_key, "bg-primary")
        with self.assertRaises(VerifyError) as cm:
            verify_breakglass_primary(
                self.tar_path, sig_path, os.path.join(self.tmp, "no-such-anchor")
            )
        assert cm.exception.reason == "verify_failed"


if __name__ == "__main__":
    unittest.main()
