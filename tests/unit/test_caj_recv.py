"""Tests for mac/caj-recv: the online (Mac-side) result verifier + seq
reconciler (S5, S6, clarity M1).

caj-recv is a standalone CLI script (like mac/caj), not an importable causb
submodule, so these tests exercise it exactly as an operator would: spawn it
via subprocess with real argv against a hand-built mock `outbox/` tree that
matches the S6 wire schema, then inspect what landed in the (test-isolated)
repo layout -- `hosts/<name>/<name>.crt`, `ca-state/last-seq`, etc.

PYTHONPATH is deliberately SCRUBBED from the subprocess environment (not just
inherited from the test runner's own `PYTHONPATH=box/lib`) -- caj-recv runs
standalone on the operator's Mac in production with no PYTHONPATH set up at
all, matching test_caj.py's own established rationale. `CAJ_STATE_DIR` and
`CAJ_HOSTS_DIR` (mirroring caj's own `CAJ_STATE_DIR` convention) point both
`ca-state/` and `hosts/` at a per-test tempdir, so no test run ever touches
this checkout's real repo layout.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAJ_RECV_PATH = os.path.join(REPO_ROOT, "mac", "caj-recv")


def _write_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _write_json_file(path, obj):
    _write_file(path, json.dumps(obj, indent=2, sort_keys=True).encode())


def _bytes_present_under(root, needle):
    """True if `needle` appears verbatim in ANY file anywhere under `root`.
    Used to prove an exfil attempt (a symlink/traversal output pointing at an
    off-stick secret) did NOT land the secret's bytes anywhere in the repo
    layout, no matter what name it might have been placed under."""
    if not os.path.isdir(root):
        return False
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                with open(os.path.join(dirpath, name), "rb") as f:
                    if needle in f.read():
                        return True
            except OSError:
                continue
    return False


class TestCajRecv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-caj-recv-test-")
        self.stick = os.path.join(self.tmp, "stick")
        os.makedirs(self.stick)
        # A fresh, isolated repo layout per test -- caj-recv must never touch
        # this checkout's own real ca-state/ or hosts/.
        self.state_dir = os.path.join(self.tmp, "ca-state")
        self.hosts_dir = os.path.join(self.tmp, "hosts")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- fixture helpers -------------------------------------------------

    def _build_outbox(self, job_id, seq, status_value, outputs, error=None,
                       corrupt=None, extra_status_fields=None):
        """Write a well-formed outbox/<job_id>/status.json + outbox/LATEST.json
        (S6 schema) plus the given output files, ALL under self.stick.

        `outputs` is a list of (path, data) tuples: `data` is written for
        real to outbox/<job_id>/<path>, and its REAL sha256/len is what gets
        declared in status.json UNLESS `corrupt` overrides that path's
        declared metadata (simulating tampering/corruption between box-write
        and Mac-read: the on-disk bytes are exactly `data`, but status.json
        LIES about their hash/length).
        """
        job_dir = os.path.join(self.stick, "outbox", job_id)
        outputs_meta = []
        for path, data in outputs:
            _write_file(os.path.join(job_dir, path), data)
            entry = {
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
            if corrupt and path in corrupt:
                entry.update(corrupt[path])
            outputs_meta.append(entry)

        status = {
            "schema_version": 1,
            "status": status_value,
            "job_id": job_id,
            "box": "nebula-ca",
            "seq": seq,
            "started_at": "2026-07-12T00:00:00Z",
            "finished_at": "2026-07-12T00:00:05Z",
            "presence_confirmed": True,
            "exit_code": 0 if status_value == "ok" else 1,
            "outputs": outputs_meta,
            "error": error,
            "replayed": False,
        }
        if extra_status_fields:
            status.update(extra_status_fields)
        _write_json_file(os.path.join(job_dir, "status.json"), status)

        latest = {
            "bundle_id": job_id,
            "box": "nebula-ca",
            "seq": seq,
            "job_id": job_id,
            "status": status_value,
            "replayed": False,
        }
        _write_json_file(os.path.join(self.stick, "outbox", "LATEST.json"), latest)
        return job_dir

    def _run_caj_recv(self, extra_args=()):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["CAJ_STATE_DIR"] = self.state_dir
        env["CAJ_HOSTS_DIR"] = self.hosts_dir
        argv = [sys.executable, CAJ_RECV_PATH, "--stick", self.stick]
        argv.extend(extra_args)
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def _last_seq(self):
        with open(os.path.join(self.state_dir, "last-seq")) as f:
            return f.read().strip()

    def _seed_last_seq(self, value):
        os.makedirs(self.state_dir, exist_ok=True)
        with open(os.path.join(self.state_dir, "last-seq"), "w") as f:
            f.write(str(value))

    # --- (a) well-formed outbox: accepted, cert placed, last-seq advances ---

    def test_well_formed_receive_places_cert_and_advances_last_seq(self):
        job_id = str(uuid.uuid4())
        cert_bytes = b"FAKE-ALICE-CERT-BYTES\n"
        self._build_outbox(job_id, seq=7, status_value="ok",
                            outputs=[("alice.crt", cert_bytes)])

        result = self._run_caj_recv()

        assert result.returncode == 0, result.stderr.decode()
        placed_path = os.path.join(self.hosts_dir, "alice", "alice.crt")
        assert os.path.isfile(placed_path)
        with open(placed_path, "rb") as f:
            assert f.read() == cert_bytes
        assert self._last_seq() == "7"

    # --- (b) tampered output (sha mismatch) -> refused, nothing placed ---

    def test_tampered_output_sha_mismatch_is_refused(self):
        self._seed_last_seq(5)
        job_id = str(uuid.uuid4())
        self._build_outbox(
            job_id, seq=99, status_value="ok",
            outputs=[("alice.crt", b"REAL-BYTES-ON-DISK")],
            corrupt={"alice.crt": {"sha256": "0" * 64}},
        )

        result = self._run_caj_recv()

        assert result.returncode != 0
        assert not os.path.exists(os.path.join(self.hosts_dir, "alice", "alice.crt"))
        # The whole receive was refused -- last-seq must NOT move to 99.
        assert self._last_seq() == "5"

    # --- (c) last-seq is monotonic: advances forward, never regresses ---

    def test_last_seq_monotonic_never_decreases(self):
        job_id_1 = str(uuid.uuid4())
        self._build_outbox(job_id_1, seq=10, status_value="ok",
                            outputs=[("bob.crt", b"BOB-CERT-V1")])
        first = self._run_caj_recv()
        assert first.returncode == 0, first.stderr.decode()
        assert self._last_seq() == "10"

        # A second, DIFFERENT job reporting a LOWER seq (e.g. an operator
        # re-inserting an older stick snapshot) overwrites LATEST.json/outbox
        # to point at a new job_id -- last-seq must stay at 10, never regress
        # to 3, even though this second receive is itself well-formed and its
        # own output is still correctly placed (see mac/caj-recv's module
        # docstring: placement is independent of seq ordering -- that is also
        # what makes an R10e *replay* of an equal seq succeed).
        job_id_2 = str(uuid.uuid4())
        self._build_outbox(job_id_2, seq=3, status_value="ok",
                            outputs=[("carol.crt", b"CAROL-CERT")])
        second = self._run_caj_recv()
        assert second.returncode == 0, second.stderr.decode()
        assert self._last_seq() == "10"  # unchanged -- never regresses
        assert os.path.isfile(os.path.join(self.hosts_dir, "carol", "carol.crt"))

    # --- status:"error" -> no certs placed, non-zero exit, seq still reconciles ---

    def test_status_error_places_no_certs_but_reconciles_seq(self):
        job_id = str(uuid.uuid4())
        # Even a VALID, integrity-verified output (ca.crt, correct hash) must
        # NOT be placed when the job's overall status isn't "ok" -- a failed
        # job is never treated as delivered output (brief: "do not treat a
        # failed job as delivered output").
        self._build_outbox(
            job_id, seq=42, status_value="error",
            outputs=[("ca.crt", b"SOME-CA-CRT-BYTES")],
            error="handler_failed",
        )

        result = self._run_caj_recv()

        assert result.returncode != 0
        assert not os.path.exists(os.path.join(self.state_dir, "ca.crt"))
        assert b"handler_failed" in result.stderr or b"error" in result.stderr
        # last-seq still advances: the box's freshness gate already accepted
        # this seq before the job was attempted at all (S7.5, before the K1
        # gate/dispatch/commit of S7.6-8), so the Mac's repo baseline should
        # track it regardless of whether the operation itself succeeded --
        # otherwise a subsequent `caj build` could mint an already-consumed
        # seq the box would then reject as stale.
        assert self._last_seq() == "42"

    # --- a traversal outputs[].path is rejected (MUTATION-PROOF) ---

    def test_traversal_output_path_is_rejected_mutation_proof(self):
        # Mutation-proof: the traversal path is crafted to resolve to a REAL,
        # existing file whose declared sha256/bytes MATCH it -- so if the
        # _is_safe_basename guard were removed from _verify_outputs, the open
        # would succeed, the hash would match, integrity would PASS, and the
        # run would exit 0 (the "/"-containing path matches no placement rule,
        # so it'd merely be skipped). The ONLY thing that turns this into a
        # non-zero-exit rejection is the safety check itself -- disabling it
        # flips the outcome, which the previous FileNotFoundError-coincidence
        # version of this test could never prove.
        self._seed_last_seq(1)
        target = os.path.join(self.tmp, "resolvable_target.crt")
        target_bytes = b"IF-THE-SAFETY-CHECK-WERE-GONE-THIS-WOULD-VERIFY\n"
        _write_file(target, target_bytes)

        job_id = str(uuid.uuid4())
        job_dir = os.path.join(self.stick, "outbox", job_id)
        os.makedirs(job_dir)
        # From <tmp>/stick/outbox/<job_id>/ up to <tmp>/resolvable_target.crt
        # is three ".." levels (job_id -> outbox -> stick -> tmp). The realpath
        # assert below fails the test loudly if that arithmetic is ever wrong,
        # so a miscount can't silently turn this into a FileNotFoundError test.
        traversal = "../../../resolvable_target.crt"
        assert os.path.realpath(os.path.join(job_dir, traversal)) == \
            os.path.realpath(target)
        status = {
            "schema_version": 1, "status": "ok", "job_id": job_id, "box": "nebula-ca",
            "seq": 50, "started_at": "t", "finished_at": "t",
            "presence_confirmed": True, "exit_code": 0,
            "outputs": [{
                "path": traversal,
                "sha256": hashlib.sha256(target_bytes).hexdigest(),
                "bytes": len(target_bytes),
            }],
            "error": None, "replayed": False,
        }
        _write_json_file(os.path.join(job_dir, "status.json"), status)
        _write_json_file(os.path.join(self.stick, "outbox", "LATEST.json"), {
            "bundle_id": job_id, "box": "nebula-ca", "seq": 50,
            "job_id": job_id, "status": "ok", "replayed": False,
        })

        result = self._run_caj_recv()

        assert result.returncode != 0, result.stdout.decode()
        assert self._last_seq() == "1"  # refused whole receive -- unchanged
        # And the target's bytes were not exfiltrated into the repo anywhere.
        assert not _bytes_present_under(self.hosts_dir, target_bytes)
        assert not _bytes_present_under(self.state_dir, target_bytes)

    def test_job_id_traversal_in_latest_is_rejected_mutation_proof(self):
        # Same mutation-proof shape for LATEST.json's job_id (which builds the
        # job_dir path). A COMPLETE, valid ok-job is planted at a resolvable
        # off-outbox location, so if _is_safe_basename(job_id) were removed
        # from the receive flow the run would find the planted status.json +
        # output, verify it, and exit 0 -- proving only the safety check
        # produces the rejection.
        self._seed_last_seq(1)
        plant = os.path.join(self.tmp, "planted_job")
        os.makedirs(plant)
        cert = b"PLANTED-CERT\n"
        _write_file(os.path.join(plant, "mallory.crt"), cert)
        os.makedirs(os.path.join(self.stick, "outbox"), exist_ok=True)
        # <tmp>/stick/outbox/<job_id> with job_id="../../planted_job" resolves
        # to <tmp>/planted_job (outbox -> stick -> tmp is two ".." levels).
        traversal_job_id = "../../planted_job"
        assert os.path.realpath(
            os.path.join(self.stick, "outbox", traversal_job_id)
        ) == os.path.realpath(plant)
        status = {
            "schema_version": 1, "status": "ok", "job_id": traversal_job_id,
            "box": "nebula-ca", "seq": 77, "started_at": "t", "finished_at": "t",
            "presence_confirmed": True, "exit_code": 0,
            "outputs": [{
                "path": "mallory.crt",
                "sha256": hashlib.sha256(cert).hexdigest(), "bytes": len(cert),
            }],
            "error": None, "replayed": False,
        }
        _write_json_file(os.path.join(plant, "status.json"), status)
        _write_json_file(os.path.join(self.stick, "outbox", "LATEST.json"), {
            "bundle_id": "x", "box": "nebula-ca", "seq": 77,
            "job_id": traversal_job_id, "status": "ok", "replayed": False,
        })

        result = self._run_caj_recv()

        assert result.returncode != 0, result.stdout.decode()
        assert self._last_seq() == "1"
        assert not os.path.exists(os.path.join(self.hosts_dir, "mallory"))

    # --- outbox/LATEST.json absent -> clean no-op exit ---

    def test_latest_json_absent_is_a_clean_noop(self):
        result = self._run_caj_recv()

        assert result.returncode == 0, result.stderr.decode()
        assert b"nothing to receive" in result.stdout.lower()
        # No side effects at all -- ca-state/ isn't even created.
        assert not os.path.exists(self.state_dir)

    # --- [Critical] a symlink output is refused, its target NOT exfiltrated ---

    def test_symlink_output_is_refused_and_secret_not_placed(self):
        # A FAT32 stick can't hold a symlink, but a hostile NON-FAT stick
        # pointed at via --stick can (S1: the stick is outside the trust
        # boundary). An output declared as a symlink to an off-stick,
        # Mac-local "secret" file -- with the secret's REAL sha256 declared --
        # must NOT be followed: following it would make integrity "pass"
        # (target hashed and compared against its own declared hash) and place
        # the secret's bytes as a "verified" cert in hosts/<name>/. caj-recv
        # opens every output O_NOFOLLOW + fstat S_ISREG, so the symlink is
        # refused outright (this is the Mac-side analog of the box's R1
        # collect.py symlink paranoia).
        self._seed_last_seq(4)
        secret = os.path.join(self.tmp, "offstick_secret.pem")
        secret_bytes = b"-----MAC-LOCAL-SECRET-THAT-MUST-NOT-BE-EXFILTRATED-----\n"
        _write_file(secret, secret_bytes)
        secret_sha = hashlib.sha256(secret_bytes).hexdigest()

        job_id = str(uuid.uuid4())
        job_dir = os.path.join(self.stick, "outbox", job_id)
        os.makedirs(job_dir)
        os.symlink(secret, os.path.join(job_dir, "alice.crt"))  # the symlink output
        status = {
            "schema_version": 1, "status": "ok", "job_id": job_id, "box": "nebula-ca",
            "seq": 60, "started_at": "t", "finished_at": "t",
            "presence_confirmed": True, "exit_code": 0,
            "outputs": [{"path": "alice.crt", "sha256": secret_sha,
                         "bytes": len(secret_bytes)}],
            "error": None, "replayed": False,
        }
        _write_json_file(os.path.join(job_dir, "status.json"), status)
        _write_json_file(os.path.join(self.stick, "outbox", "LATEST.json"), {
            "bundle_id": job_id, "box": "nebula-ca", "seq": 60,
            "job_id": job_id, "status": "ok", "replayed": False,
        })

        result = self._run_caj_recv()

        assert result.returncode != 0
        # The cert was NOT placed ...
        assert not os.path.exists(os.path.join(self.hosts_dir, "alice", "alice.crt"))
        # ... and the secret's bytes are NOWHERE in the repo layout.
        assert not _bytes_present_under(self.hosts_dir, secret_bytes)
        assert not _bytes_present_under(self.state_dir, secret_bytes)
        # The refusal message must not leak the (would-be-followed) target's hash.
        assert secret_sha.encode() not in result.stderr
        # Refused whole receive -- last-seq unchanged.
        assert self._last_seq() == "4"

    # --- [Medium] embedded-NUL path / job_id -> clean error, never a traceback ---

    def test_nul_byte_in_output_path_is_a_clean_error(self):
        # A NUL byte (JSON "\u0000") in outputs[].path passes a naive "/", ".",
        # ".." check but makes os.open raise ValueError("embedded null byte").
        # It must be rejected cleanly by the basename safety check, never
        # crash out as a raw traceback.
        self._seed_last_seq(2)
        job_id = str(uuid.uuid4())
        job_dir = os.path.join(self.stick, "outbox", job_id)
        status = {
            "schema_version": 1, "status": "ok", "job_id": job_id, "box": "nebula-ca",
            "seq": 9, "started_at": "t", "finished_at": "t",
            "presence_confirmed": True, "exit_code": 0,
            "outputs": [{"path": "al\x00ice.crt", "sha256": "a" * 64, "bytes": 1}],
            "error": None, "replayed": False,
        }
        _write_json_file(os.path.join(job_dir, "status.json"), status)
        _write_json_file(os.path.join(self.stick, "outbox", "LATEST.json"), {
            "bundle_id": job_id, "box": "nebula-ca", "seq": 9,
            "job_id": job_id, "status": "ok", "replayed": False,
        })

        result = self._run_caj_recv()

        assert result.returncode == 1
        assert b"Traceback" not in result.stderr, result.stderr.decode()
        assert self._last_seq() == "2"

    def test_nul_byte_in_latest_job_id_is_a_clean_error(self):
        _write_json_file(os.path.join(self.stick, "outbox", "LATEST.json"), {
            "bundle_id": "x", "box": "nebula-ca", "seq": 1,
            "job_id": "job\x00id", "status": "ok", "replayed": False,
        })

        result = self._run_caj_recv()

        assert result.returncode == 1
        assert b"Traceback" not in result.stderr, result.stderr.decode()

    # --- [Medium] a placement filesystem error -> clean error, never a traceback ---

    def test_placement_oserror_is_a_clean_error_not_a_traceback(self):
        # A filesystem error during placement (here: hosts/<name>/ is blocked
        # by a pre-existing regular FILE at that path, so os.makedirs raises
        # FileExistsError) must surface as a clean CajRecvError exit, never a
        # raw traceback -- and, since reconcile runs only AFTER every placement
        # succeeds, last-seq must NOT advance.
        self._seed_last_seq(3)
        os.makedirs(self.hosts_dir)
        with open(os.path.join(self.hosts_dir, "alice"), "wb") as f:
            f.write(b"i am a file blocking the hosts/alice/ directory")
        job_id = str(uuid.uuid4())
        self._build_outbox(job_id, seq=88, status_value="ok",
                           outputs=[("alice.crt", b"ALICE-CERT")])

        result = self._run_caj_recv()

        assert result.returncode == 1
        assert b"Traceback" not in result.stderr, result.stderr.decode()
        assert self._last_seq() == "3"  # reconcile never reached

    # --- [Minor] ca.crt / registry.json placement into ca-state/ ---

    def test_ca_crt_and_registry_json_are_placed_in_ca_state(self):
        job_id = str(uuid.uuid4())
        ca_bytes = b"-----FAKE CA CERT-----\n"
        reg_bytes = b'[{"name":"alice","ip":"10.0.0.1/16"}]\n'
        self._build_outbox(job_id, seq=12, status_value="ok",
                           outputs=[("ca.crt", ca_bytes), ("registry.json", reg_bytes)])

        result = self._run_caj_recv()

        assert result.returncode == 0, result.stderr.decode()
        with open(os.path.join(self.state_dir, "ca.crt"), "rb") as f:
            assert f.read() == ca_bytes
        with open(os.path.join(self.state_dir, "registry.json"), "rb") as f:
            assert f.read() == reg_bytes
        assert self._last_seq() == "12"

    # --- on-stick pre-commit error breadcrumb (outbox/ERROR.json, S-errlog) ---

    def _build_error_breadcrumb(self, *, reason="bad_manifest", phase="extract",
                                job_id=None, seq=None, bundle_id=None,
                                schema_version=1, box="nebula-ca",
                                ts="2026-07-16T12:00:00Z", overrides=None):
        bc = {
            "schema_version": schema_version, "box": box, "ts": ts,
            "reason": reason, "phase": phase,
            "job_id": job_id, "seq": seq, "bundle_id": bundle_id,
        }
        if overrides:
            bc.update(overrides)
        _write_json_file(os.path.join(self.stick, "outbox", "ERROR.json"), bc)

    def test_error_breadcrumb_alone_reports_and_reconciles_nothing(self):
        # No LATEST.json: an authenticated job aborted before commit. Report it,
        # exit nonzero, and (crucially) do NOT advance last-seq -- the box
        # consumed no seq, so the operator can re-insert at the same seq.
        self._seed_last_seq(5)
        self._build_error_breadcrumb(reason="wrong_box", phase="freshness",
                                     job_id="job-b", seq=9, bundle_id="bundle-9")

        result = self._run_caj_recv()

        assert result.returncode != 0, result.stderr.decode()
        err = result.stderr.decode()
        assert "before the job ran" in err
        assert "wrong_box" in err and "freshness" in err
        assert b"Traceback" not in result.stderr
        assert self._last_seq() == "5"  # seq NOT consumed -> not advanced

    def test_error_breadcrumb_null_ids_report_unknown(self):
        self._build_error_breadcrumb(reason="bad_manifest", phase="extract",
                                     job_id=None, seq=None, bundle_id=None)

        result = self._run_caj_recv()

        assert result.returncode != 0
        err = result.stderr.decode()
        assert "bad_manifest" in err and "extract" in err
        assert "unknown" in err  # null job_id/seq surface as "unknown"

    def test_error_breadcrumb_verify_failed_is_worded_refused_not_forged(self):
        # An authenticated-but-scope-refused break-glass job reuses reason
        # verify_failed; the breadcrumb's PRESENCE marks it "refused", never a
        # forged signature (a forged/unsigned stick leaves no breadcrumb).
        self._build_error_breadcrumb(reason="verify_failed", phase="manifest",
                                     job_id="job-x", seq=3)

        result = self._run_caj_recv()

        assert result.returncode != 0
        err = result.stderr.decode()
        assert "was refused" in err
        assert "signature" not in err.lower()  # never implies a forged sig

    def test_malformed_error_breadcrumb_bad_schema_is_refused(self):
        self._build_error_breadcrumb(overrides={"schema_version": 2})

        result = self._run_caj_recv()

        assert result.returncode != 0
        assert b"unknown schema_version" in result.stderr

    def test_error_breadcrumb_unknown_phase_is_refused(self):
        self._build_error_breadcrumb(overrides={"phase": "not-a-phase"})

        result = self._run_caj_recv()

        assert result.returncode != 0
        assert b"unknown 'phase'" in result.stderr

    def test_error_breadcrumb_coexisting_with_delivered_latest_handles_both(self):
        # An earlier, still-unreceived successful job (LATEST.json) PLUS a newer
        # pre-commit failure (ERROR.json): the delivered outputs are placed and
        # last-seq advances, the failure is reported, and rc is nonzero.
        job_id = str(uuid.uuid4())
        cert = b"CERT-A\n"
        self._build_outbox(job_id, seq=7, status_value="ok",
                           outputs=[("alice.crt", cert)])
        self._build_error_breadcrumb(reason="bad_manifest", phase="extract")

        result = self._run_caj_recv()

        assert result.returncode != 0, result.stderr.decode()  # failure wins rc
        placed = os.path.join(self.hosts_dir, "alice", "alice.crt")
        assert os.path.isfile(placed)                      # delivered job received
        assert self._last_seq() == "7"                     # its seq advanced
        assert "before the job ran" in result.stderr.decode()  # failure reported

    def test_error_breadcrumb_control_bytes_in_ts_is_refused(self):
        # ts is UNTRUSTED stick content; a control/ANSI sequence must never reach
        # the operator's terminal (report spoofing). Strict ISO-UTC gate rejects.
        self._build_error_breadcrumb(
            overrides={"ts": "2026-07-16T12:00:00Z\x1b[2K\rSPOOFED"})

        result = self._run_caj_recv()

        assert result.returncode != 0
        assert b"invalid 'ts'" in result.stderr
        assert b"\x1b[2K" not in result.stderr  # the raw escape never echoed

    def test_error_breadcrumb_oversized_reason_is_refused(self):
        self._build_error_breadcrumb(overrides={"reason": "x" * 200})

        result = self._run_caj_recv()

        assert result.returncode != 0
        assert b"invalid 'reason'" in result.stderr

    def test_malformed_error_breadcrumb_does_not_sink_a_coexisting_delivery(self):
        # A malformed/hostile ERROR.json must NOT block an otherwise-valid,
        # already-committed LATEST.json delivery that coexists with it.
        job_id = str(uuid.uuid4())
        cert = b"CERT-A\n"
        self._build_outbox(job_id, seq=7, status_value="ok",
                           outputs=[("alice.crt", cert)])
        self._build_error_breadcrumb(overrides={"schema_version": 2})  # malformed

        result = self._run_caj_recv()

        assert result.returncode != 0, result.stderr.decode()
        assert os.path.isfile(os.path.join(self.hosts_dir, "alice", "alice.crt"))
        assert self._last_seq() == "7"                 # delivery still reconciled
        assert b"proceeding with the delivered result" in result.stderr


if __name__ == "__main__":
    unittest.main()
