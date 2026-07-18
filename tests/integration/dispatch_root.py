#!/usr/bin/env python3
"""Root, on-box integration checks for Task 14 (causb.dispatch's
privilege-separation core: S6/S8/S12, D12/D17/D20, S19 R2).

RUN AS ROOT, ON THE BOX ONLY:

    sudo python3 tests/integration/dispatch_root.py

Exercises exactly what `tests/unit/test_dispatch.py` cannot without root: a
REAL `setpriv --reuid=/--regid=` privilege drop against a REAL root-owned
`0400` file, a REAL scrubbed-environment child process, and a REAL per-op
timeout that has to reach into and kill a REAL backgrounded grandchild's
process group. Nothing here is mocked; `causb.dispatch.run()` is called
with no DI overrides (production defaults) except a short `timeout_s` on
the one timeout case (so this script finishes in seconds, not
`config.OP_TIMEOUT_S`'s real 300s).

**The core DAC proof (brief's explicit required scenario):** a dummy
`root:root 0400` file is planted at the REAL `config.CA_DIR/ca.key` (the
exact path a bootstrapped box's real CA key lives at, R2) -- refusing to
run at all if a real `ca.key` is already there, so this can never clobber
actual key material. A non-privileged `run-script` job whose entrypoint
`cat`s that path is proven to run AS `nebula-job` (its `id` output is
captured) and to get `Permission denied` (the dummy key's BYTES never
appear anywhere this test can see); a `privileged`+`cosigned=True` job
running the identical `cat` is proven to run AS ROOT (`uid=0`) and to
actually read the key, with its sha256+byte-length landing in the REAL
`config.AUDIT_LOG`, mode `0600`. A `privileged` job with `cosigned=False`
is proven to run NOTHING at all (no output file is even created).

**Test out_dir/payload_dir are deliberately world-writable/-readable
(`0777`/`0755`) here** -- an integration-note flagged for the report: the
REAL harness (Task 16) is what will be responsible for provisioning
`out_dir` with permissions `nebula-job` can actually write into (`cwd=
out_dir` is part of run-script's contract); `dispatch.run()` itself takes
both dirs as already-prepared paths, so this test prepares them the way a
real harness eventually must, rather than exercising a permissions problem
that belongs to a different task.

Cleans up the dummy ca.key, every temp payload/out dir, and the injected
test env var, in `finally` blocks, even on failure. Prints PASS/FAIL per
case and a final summary; exits non-zero if anything failed.
"""

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import uuid

if os.geteuid() != 0:
    print("dispatch_root.py must be run as root (sudo) -- it plants a dummy "
          "root-owned ca.key and drives real setpriv-confined children.")
    sys.exit(1)

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "box", "lib"))

from causb import config  # noqa: E402
from causb.dispatch import DispatchError, run  # noqa: E402

DUMMY_CA_KEY_CONTENT = b"DUMMY CA KEY MATERIAL -- task 14 root integration test\n"


class _JobDir:
    """A payload_dir + out_dir pair for one case. `out_dir` is created ROOT-owned
    `0755` (mirroring the real harness's `_fresh_dir`); `dispatch._run_script`
    now chowns it to `nebula-job` on the drop path (the 2026-07-17 fix), so the
    unprivileged child can write into `cwd=out_dir` WITHOUT this test pre-widening
    it to 0777. This case therefore also regression-tests that hand-over: revert
    the dispatch chown and the non-privileged DAC-proof case's output vanishes.
    `payload_dir`/its script are `0755`/`0644` so the child can read the script."""

    def __init__(self, script_name, script_content):
        self.payload_dir = tempfile.mkdtemp(prefix="causb-dispatch-root-payload-")
        self.out_dir = tempfile.mkdtemp(prefix="causb-dispatch-root-out-")
        os.chmod(self.payload_dir, 0o755)
        os.chmod(self.out_dir, 0o755)
        self.script_path = os.path.join(self.payload_dir, script_name)
        with open(self.script_path, "w") as f:
            f.write(script_content)
        os.chmod(self.script_path, 0o644)
        self.script_name = script_name

    def read_out(self, name):
        with open(os.path.join(self.out_dir, name)) as f:
            return f.read()

    def out_exists(self, name):
        return os.path.exists(os.path.join(self.out_dir, name))

    def cleanup(self):
        shutil.rmtree(self.payload_dir, ignore_errors=True)
        shutil.rmtree(self.out_dir, ignore_errors=True)


def _job(entrypoint, privileged=False):
    return {
        "job_id": str(uuid.uuid4()),
        "operation": "run-script",
        "args": {"privileged": True} if privileged else {},
        "payload": [entrypoint],
        "entrypoint": entrypoint,
    }


def _plant_dummy_ca_key():
    ca_key_path = os.path.join(config.CA_DIR, "ca.key")
    if os.path.exists(ca_key_path):
        raise RuntimeError(
            f"refusing to run: {ca_key_path} already exists. This test only runs "
            "against a pre-bootstrap box with no real CA key -- remove/relocate "
            "the existing file first if this is intentional."
        )
    with open(ca_key_path, "wb") as f:
        f.write(DUMMY_CA_KEY_CONTENT)
    os.chmod(ca_key_path, 0o400)
    os.chown(ca_key_path, 0, 0)
    return ca_key_path


def _remove_dummy_ca_key(ca_key_path):
    if os.path.exists(ca_key_path):
        os.chmod(ca_key_path, 0o600)
        os.unlink(ca_key_path)


def _read_audit_lines():
    try:
        with open(config.AUDIT_LOG) as f:
            return [line for line in f if line.strip()]
    except FileNotFoundError:
        return []


# --------------------------------------------------------------------------
# cases needing the dummy ca.key
# --------------------------------------------------------------------------

def case_nonprivileged_cannot_read_ca_key(ca_key_path):
    # A shell script's OWN exit status is whatever its LAST command
    # returned -- capture cat's real exit code into $rc and `exit $rc`
    # explicitly as the last statement, so dispatch.run()'s returned int
    # actually reflects cat's outcome rather than the trailing echo's
    # (which always succeeds).
    script = (
        "id > result.txt 2>&1\n"
        "echo ---cat--- >> result.txt\n"
        f"cat {ca_key_path} >> result.txt 2>&1\n"
        "rc=$?\n"
        "echo exit:$rc >> result.txt\n"
        "exit $rc\n"
    )
    jd = _JobDir("probe.sh", script)
    try:
        job = _job("probe.sh")
        rc = run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=False)
        out = jd.read_out("result.txt")

        assert "uid=999" in out, f"did not run as nebula-job (uid 999): {out!r}"
        assert "Permission denied" in out, f"expected a permission-denied cat: {out!r}"
        assert DUMMY_CA_KEY_CONTENT.decode() not in out, \
            "DUMMY CA KEY CONTENT LEAKED into out_dir despite the permission error!"
        assert rc != 0, f"dispatch.run() should surface cat's nonzero exit, got rc={rc}"
        return True, f"nebula-job could not read ca.key (rc={rc}); result.txt={out.strip()!r}"
    finally:
        jd.cleanup()


def case_privileged_cosigned_can_read_and_is_audited(ca_key_path):
    # Same fix as case_nonprivileged_cannot_read_ca_key: propagate cat's
    # real exit code as the script's own, so `assert rc == 0` actually
    # means "cat succeeded," not merely "the trailing echo succeeded."
    script = (
        "id > result.txt 2>&1\n"
        "echo ---cat--- >> result.txt\n"
        f"cat {ca_key_path} >> result.txt 2>&1\n"
        "rc=$?\n"
        "echo exit:$rc >> result.txt\n"
        "exit $rc\n"
    )
    jd = _JobDir("privileged_probe.sh", script)
    try:
        job = _job("privileged_probe.sh", privileged=True)
        before_lines = _read_audit_lines()

        rc = run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=True)
        out = jd.read_out("result.txt")

        assert "uid=0" in out, f"did not run as root: {out!r}"
        assert DUMMY_CA_KEY_CONTENT.decode() in out, f"expected ca.key content readable as root: {out!r}"
        assert rc == 0, f"expected exit 0, got {rc}"

        after_lines = _read_audit_lines()
        new_lines = after_lines[len(before_lines):]
        assert len(new_lines) == 1, f"expected exactly 1 new audit line, got {len(new_lines)}"
        entry = json.loads(new_lines[0])
        assert entry["job_id"] == job["job_id"]
        assert entry["operation"] == "run-script"
        assert entry["privileged"] is True

        with open(jd.script_path, "rb") as f:
            script_bytes = f.read()
        expected_sha256 = hashlib.sha256(script_bytes).hexdigest()
        assert entry["sha256"] == expected_sha256, "audited sha256 does not match the actual script bytes"
        assert entry["bytes"] == len(script_bytes)

        mode = stat.S_IMODE(os.stat(config.AUDIT_LOG).st_mode)
        assert mode == 0o600, f"audit log mode is {oct(mode)}, expected 0o600"

        return True, (
            f"privileged+cosigned ran as root (uid=0) and read ca.key (rc={rc}); "
            f"audit sha256={entry['sha256']} bytes={entry['bytes']}"
        )
    finally:
        jd.cleanup()


def case_privileged_without_cosign_runs_nothing(ca_key_path):
    script = f"cat {ca_key_path} > result.txt 2>&1\n"
    jd = _JobDir("should_not_run.sh", script)
    try:
        job = _job("should_not_run.sh", privileged=True)
        reason = None
        try:
            run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=False)
        except DispatchError as exc:
            reason = exc.reason
        assert reason == "cosign_failed", f"expected DispatchError(cosign_failed), got reason={reason!r}"
        assert not jd.out_exists("result.txt"), \
            "script ran despite missing cosign -- result.txt must not exist"
        return True, "privileged without cosign -> DispatchError(cosign_failed); result.txt never created"
    finally:
        jd.cleanup()


def case_truthy_non_true_cosigned_runs_nothing(ca_key_path):
    # [Critical fix acceptance] cosigned="False" is TRUTHY -- a `not cosigned`
    # gate would run this AS ROOT and read ca.key. The strict `is not True`
    # gate must refuse it: DispatchError(cosign_failed), nothing runs.
    script = f"cat {ca_key_path} > leaked.txt 2>&1\n"
    jd = _JobDir("should_not_run.sh", script)
    try:
        job = _job("should_not_run.sh", privileged=True)
        results = []
        for bad in ("False", "0", "true", 1):
            reason = None
            try:
                run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=bad)
            except DispatchError as exc:
                reason = exc.reason
            assert reason == "cosign_failed", \
                f"cosigned={bad!r} was accepted as a co-signature (reason={reason!r})"
            assert not jd.out_exists("leaked.txt"), \
                f"script RAN with truthy-non-True cosigned={bad!r} -- ca.key could have leaked"
            results.append(repr(bad))
        return True, f"truthy-non-True cosigned {', '.join(results)} all -> cosign_failed, nothing ran"
    finally:
        jd.cleanup()


CASES_NEEDING_CA_KEY = [
    ("non-privileged run-script CANNOT read ca.key (runs as nebula-job)",
     case_nonprivileged_cannot_read_ca_key),
    ("privileged+cosigned run-script CAN read ca.key (runs as root), sha256 audited",
     case_privileged_cosigned_can_read_and_is_audited),
    ("privileged WITHOUT cosign -> cosign_failed, nothing runs",
     case_privileged_without_cosign_runs_nothing),
    ("privileged with TRUTHY-non-True cosigned -> cosign_failed, nothing runs",
     case_truthy_non_true_cosigned_runs_nothing),
]


# --------------------------------------------------------------------------
# standalone cases (no ca.key needed)
# --------------------------------------------------------------------------

def case_scrubbed_env_leaks_no_parent_vars():
    marker_name = "CAUSB_TEST_SECRET_MARKER"
    os.environ[marker_name] = "leaked-if-you-see-this"
    try:
        script = "env > result.txt 2>&1\n"
        jd = _JobDir("env_probe.sh", script)
        try:
            job = _job("env_probe.sh")
            rc = run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=False)
            out = jd.read_out("result.txt")
            assert marker_name not in out, f"parent env var LEAKED into the sandboxed child: {out!r}"
            env_names = {line.split("=", 1)[0] for line in out.splitlines() if "=" in line}
            assert env_names <= {"PATH", "HOME", "PWD"}, f"unexpected env vars visible: {env_names}"
            return True, f"scrubbed env confirmed: only {sorted(env_names)} visible to the child (rc={rc})"
        finally:
            jd.cleanup()
    finally:
        del os.environ[marker_name]


def case_timeout_reaps_setsid_detached_grandchild():
    # [High fix acceptance test] The grandchild is `setsid`-detached into
    # its OWN new session/process group -- so a plain os.killpg on the
    # start_new_session group does NOT reach it (reproduced live: it
    # survives and touches MARKER after run() returns 124). The
    # `unshare --pid --fork --kill-child` PID-namespace wrapper is what
    # reaps it: killing unshare on timeout tears the whole namespace down.
    # Uses an ABSOLUTE setsid path since the child's PATH is scrubbed to
    # /usr/bin:/bin (setsid lives at /usr/bin/setsid on this box, but being
    # explicit removes any doubt about whether a PATH miss, not the
    # reaping, is what kept MARKER absent).
    grandchild_delay = 6
    script = (
        f"/usr/bin/setsid sh -c 'sleep {grandchild_delay}; touch MARKER' &\n"
        "echo detached grandchild $! > result.txt\n"
        "sleep 30\n"
    )
    jd = _JobDir("setsid_escape.sh", script)
    try:
        job = _job("setsid_escape.sh")
        start = time.monotonic()
        rc = run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=False, timeout_s=1.5)
        elapsed = time.monotonic() - start

        assert rc == 124, f"expected the timeout sentinel 124, got {rc}"
        assert elapsed < 10, f"took {elapsed:.1f}s -- did not time out promptly"

        # Wait PAST the grandchild's delay: if the PID namespace had NOT
        # reaped it, MARKER would appear now, after run() already returned.
        time.sleep(grandchild_delay + 3)
        assert not jd.out_exists("MARKER"), (
            "setsid-detached grandchild SURVIVED the timeout and wrote MARKER "
            "after run() returned -- PID-namespace reaping failed"
        )
        return True, (
            f"timed out at ~{elapsed:.2f}s (rc=124); setsid-detached grandchild "
            f"confirmed REAPED (MARKER never created after +{grandchild_delay+3}s)"
        )
    finally:
        jd.cleanup()


def case_nul_in_entrypoint_is_clean_dispatch_error():
    # [Medium fix acceptance] a NUL in the entrypoint must surface as a
    # DispatchError, never a raw ValueError('embedded null byte') out of
    # Popen. (payload matches so only the control-char guard rejects it.)
    jd = _JobDir("probe.sh", "echo hi\n")
    try:
        job = {
            "job_id": str(uuid.uuid4()),
            "operation": "run-script",
            "args": {},
            "payload": ["pro\x00be.sh"],
            "entrypoint": "pro\x00be.sh",
        }
        reason = None
        raised_type = None
        try:
            run("run-script", job, jd.payload_dir, jd.out_dir, cosigned=False)
        except DispatchError as exc:
            reason = exc.reason
            raised_type = "DispatchError"
        except ValueError as exc:
            raised_type = f"ValueError (BAD -- raw): {exc}"
        assert raised_type == "DispatchError", \
            f"NUL entrypoint raised {raised_type}, not a clean DispatchError"
        assert reason == "bad_manifest", f"expected bad_manifest, got {reason!r}"
        return True, "NUL-in-entrypoint -> DispatchError(bad_manifest), not a raw ValueError"
    finally:
        jd.cleanup()


CASES_STANDALONE = [
    ("scrubbed env leaks no parent-process vars into the child",
     case_scrubbed_env_leaks_no_parent_vars),
    ("timeout REAPS a setsid-detached grandchild (PID namespace)",
     case_timeout_reaps_setsid_detached_grandchild),
    ("NUL in entrypoint -> clean DispatchError, not a raw ValueError",
     case_nul_in_entrypoint_is_clean_dispatch_error),
]


def main():
    passed = 0
    failed = 0

    def _run_case(name, fn, *args):
        nonlocal passed, failed
        try:
            ok, detail = fn(*args)
        except Exception as exc:  # noqa: BLE001 -- top-level test runner
            ok, detail = False, f"EXCEPTION: {type(exc).__name__}: {exc}"
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"[{status}] {name}\n         {detail}")

    ca_key_path = _plant_dummy_ca_key()
    try:
        for name, fn in CASES_NEEDING_CA_KEY:
            _run_case(name, fn, ca_key_path)
    finally:
        _remove_dummy_ca_key(ca_key_path)
        print(f"(cleaned up dummy ca.key at {ca_key_path})")

    for name, fn in CASES_STANDALONE:
        _run_case(name, fn)

    print(f"\n{passed}/{passed + failed} cases passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
