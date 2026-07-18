"""Tests for causb.dispatch: the privilege-separation core (S6/S8/S12,
D12/D17/D20, S19 R2).

Every test here runs WITHOUT root and WITHOUT ever actually spawning
`setpriv`/`/bin/sh`/a real handler: `run()`'s `popen` parameter is an
injectable seam (mirrors `causb.mountctl`'s injectable `runner`), so tests
assert on the EXACT argv/env/cwd a call WOULD make via `_RecordingPopen`
stubs that never touch a real process. `pwd.getpwnam(config.JOB_USER)` is
called for real (read-only passwd lookup, needs no privilege) so the
expected `--reuid=/--regid=` values always match this exact box's real
`nebula-job` account rather than a hardcoded guess.

The one thing that CANNOT be proven without root -- that `nebula-job`
genuinely cannot read a real root-owned `ca.key`, that a privileged+cosigned
run genuinely reads it as root, and that the scrubbed env genuinely has no
parent-process leakage -- is `tests/integration/dispatch_root.py`, run as
root on the box.
"""

import json
import os
import pwd
import subprocess
import tempfile
import unittest
import uuid
from unittest import mock

from causb import config
from causb.dispatch import (
    DispatchError,
    _grant_group_read_tree,
    _is_privileged,
    _safe_component,
    run,
)


def _run_stubbed(*args, **kwargs):
    """`run()` with dispatch's out_dir chown+chmod (the 2026-07-17 drop-path fix)
    stubbed for the duration of the call, so a NON-privileged run-script works
    against a PLACEHOLDER out_dir (these tests never spawn a real child; `popen`
    is a recording seam). Patched only around the call, so test setUps' own real
    `os.chmod` (handler dirs, script files) are untouched -- a module-wide stub
    would clobber those. A harmless no-op for the privileged/vetted paths, which
    never chown out_dir."""
    with mock.patch("causb.dispatch.os.chown"), mock.patch("causb.dispatch.os.chmod"):
        return run(*args, **kwargs)


def _job(**overrides):
    """Build a valid single run-script job dict (the shape
    `causb.manifest.parse()` returns at `jobs[0]`), overridable per-test."""
    job = {
        "job_id": str(uuid.uuid4()),
        "operation": "run-script",
        "args": {},
        "payload": ["probe.sh"],
        "entrypoint": "probe.sh",
    }
    job.update(overrides)
    return job


def _unreachable_popen(argv, **kwargs):
    raise AssertionError(f"popen must not be called for this case; got argv={argv!r}")


class _FakeProc:
    """Stands in for a `subprocess.Popen` handle. `communicate()` raises
    `TimeoutExpired` on its first call if `timeout_first` is set (simulating
    a hung child), then behaves like a normal completed process on any
    subsequent call (the post-kill reap)."""

    def __init__(self, pid=4242, returncode=0, timeout_first=False):
        self.pid = pid
        self.returncode = returncode
        self._timeout_first = timeout_first
        self.communicate_calls = 0

    def communicate(self, timeout=None):
        self.communicate_calls += 1
        if self._timeout_first and self.communicate_calls == 1:
            raise subprocess.TimeoutExpired(cmd="x", timeout=timeout)
        return (b"", b"")


class _RecordingPopen:
    """Stands in for `subprocess.Popen` itself (the callable, not a single
    instance): records every call's (argv, kwargs) and returns a
    preconfigured `_FakeProc`. For a vetted-handler call, also snapshots the
    job.json temp file's CONTENT at call time (it still exists then --
    `causb.dispatch` unlinks it only after `_exec` returns)."""

    def __init__(self, proc=None):
        self.proc = proc if proc is not None else _FakeProc()
        self.calls = []
        self.job_json_snapshot = None

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        if len(argv) >= 2 and isinstance(argv[1], str) and argv[1].endswith(".json") \
                and os.path.isfile(argv[1]):
            with open(argv[1]) as f:
                self.job_json_snapshot = f.read()
        return self.proc


class TestIsPrivileged(unittest.TestCase):
    def test_missing_args_key_is_not_privileged(self):
        assert _is_privileged({}) is False

    def test_args_none_is_not_privileged(self):
        assert _is_privileged({"args": None}) is False

    def test_args_wrong_type_is_not_privileged(self):
        assert _is_privileged({"args": ["privileged", True]}) is False

    def test_privileged_key_missing_is_not_privileged(self):
        assert _is_privileged({"args": {}}) is False

    def test_privileged_false_is_not_privileged(self):
        assert _is_privileged({"args": {"privileged": False}}) is False

    def test_privileged_true_is_privileged(self):
        assert _is_privileged({"args": {"privileged": True}}) is True

    def test_privileged_string_true_is_not_privileged(self):
        # A naive `if args.get("privileged"):` would treat this Python-
        # truthy STRING as privileged -- must not (module docstring).
        assert _is_privileged({"args": {"privileged": "true"}}) is False

    def test_privileged_string_false_is_not_privileged(self):
        # The classic footgun this strict check specifically avoids: the
        # non-empty string "false" is Python-truthy.
        assert _is_privileged({"args": {"privileged": "false"}}) is False

    def test_privileged_integer_one_is_not_privileged(self):
        assert _is_privileged({"args": {"privileged": 1}}) is False


class TestSafeComponent(unittest.TestCase):
    def test_plain_basename_is_safe(self):
        assert _safe_component("probe.sh") is True

    def test_empty_string_is_unsafe(self):
        assert _safe_component("") is False

    def test_contains_slash_is_unsafe(self):
        assert _safe_component("a/b") is False

    def test_dot_is_unsafe(self):
        assert _safe_component(".") is False

    def test_dotdot_is_unsafe(self):
        assert _safe_component("..") is False

    def test_non_string_is_unsafe(self):
        assert _safe_component(None) is False
        assert _safe_component(123) is False

    def test_embedded_nul_is_unsafe(self):
        # [Medium fix] a NUL would otherwise pass every other check here and
        # then raise a raw ValueError('embedded null byte') out of the later
        # os.path.join/Popen -- must be rejected as unsafe up front.
        assert _safe_component("probe\x00.sh") is False

    def test_other_control_chars_are_unsafe(self):
        for ch in ("\x01", "\x09", "\x0a", "\x1f", "\x7f"):
            assert _safe_component(f"probe{ch}.sh") is False, f"control char {ch!r} slipped past"

    def test_plain_printable_with_spaces_is_safe(self):
        # A space (0x20) is NOT a control char -- unusual for a basename but
        # not path-unsafe; the check rejects < 0x20 and 0x7f only.
        assert _safe_component("my probe.sh") is True


class TestPrivilegedWithoutCosignRejected(unittest.TestCase):
    """`privileged: true` without `cosigned` -> cosign_failed, nothing runs
    (brief's explicit required test)."""

    def test_cosign_failed_raised_and_popen_never_called(self):
        job = _job(args={"privileged": True})
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=False,
                popen=_unreachable_popen)
        assert cm.exception.reason == "cosign_failed"

    def test_cosign_false_explicit_also_rejected(self):
        job = _job(args={"privileged": True})
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=False,
                popen=_unreachable_popen)
        assert cm.exception.reason == "cosign_failed"

    def test_truthy_non_bool_cosigned_is_rejected_nothing_runs(self):
        # [Critical fix] `cosigned` must be checked with `is True`, NOT
        # ordinary truthiness: a truthy NON-bool (the string "False", the
        # string "0", any non-empty string, a non-zero int) is NOT a genuine
        # co-signature and must fail closed. A `not cosigned` check would
        # let `cosigned="False"` run the script AS ROOT against ca.key.
        # `_unreachable_popen` proves nothing executes.
        for bad_cosigned in ("False", "false", "0", "true", "yes", 1, 2, [1], {"x": 1}, object()):
            job = _job(args={"privileged": True})
            with self.assertRaises(DispatchError) as cm:
                run("run-script", job, "/payload", "/out", cosigned=bad_cosigned,
                    popen=_unreachable_popen)
            assert cm.exception.reason == "cosign_failed", \
                f"cosigned={bad_cosigned!r} was wrongly accepted as a co-signature"

    def test_cosigned_literal_true_is_the_only_accepted_value(self):
        # The positive control for the strict check: only the literal bool
        # True proceeds. Uses a real temp script so the audit read succeeds;
        # a recording popen stands in for the actual unshare/sh spawn.
        payload_dir = tempfile.mkdtemp(prefix="causb-dispatch-cosign-true-")
        try:
            with open(os.path.join(payload_dir, "probe.sh"), "w") as f:
                f.write("#!/bin/sh\n")
            fd, audit_path = tempfile.mkstemp(prefix="causb-dispatch-cosign-audit-")
            os.close(fd)
            os.unlink(audit_path)
            try:
                job = _job(args={"privileged": True})
                recorder = _RecordingPopen(_FakeProc(returncode=0))
                rc = run("run-script", job, payload_dir, "/out", cosigned=True,
                          popen=recorder, audit_log_path=audit_path)
                assert rc == 0
                assert len(recorder.calls) == 1  # it actually ran
            finally:
                if os.path.exists(audit_path):
                    os.unlink(audit_path)
        finally:
            os.unlink(os.path.join(payload_dir, "probe.sh"))
            os.rmdir(payload_dir)


class TestEntrypointRejected(unittest.TestCase):
    """entrypoint not in payload[] -> rejected (brief's explicit required
    test), plus the other defense-in-depth shapes this module's own
    _validate_entrypoint re-checks independently of manifest.parse()."""

    def test_entrypoint_not_in_payload_is_rejected(self):
        job = _job(payload=["other.sh"], entrypoint="probe.sh")
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=True,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"

    def test_entrypoint_with_slash_is_rejected(self):
        job = _job(payload=["sub/probe.sh"], entrypoint="sub/probe.sh")
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=True,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"

    def test_entrypoint_dotdot_is_rejected(self):
        job = _job(payload=[".."], entrypoint="..")
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=True,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"

    def test_entrypoint_not_a_string_is_rejected(self):
        job = _job(entrypoint=None)
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=True,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"

    def test_payload_not_a_list_is_rejected(self):
        job = _job(payload="probe.sh")  # a string, not a list
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=True,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"

    def test_entrypoint_with_embedded_nul_is_rejected_as_dispatch_error(self):
        # [Medium fix] a validly-shaped manifest whose entrypoint contains a
        # NUL (matching a same-named payload entry) must fail as a clean
        # DispatchError("bad_manifest"), NOT a raw ValueError out of Popen.
        # popen must never be reached.
        job = _job(payload=["probe\x00.sh"], entrypoint="probe\x00.sh")
        with self.assertRaises(DispatchError) as cm:
            run("run-script", job, "/payload", "/out", cosigned=True,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"

    def test_operation_with_embedded_nul_is_rejected_as_dispatch_error(self):
        # Same gap for the vetted-handler path: a NUL in `operation` must not
        # reach os.path.join/os.path.isfile as a raw ValueError.
        job = _job(operation="stat\x00us", entrypoint=None, payload=[])
        with self.assertRaises(DispatchError) as cm:
            run("stat\x00us", job, "/payload", "/out", cosigned=False,
                popen=_unreachable_popen)
        assert cm.exception.reason == "bad_manifest"


class TestRunScriptArgvAndEnv(unittest.TestCase):
    """Scrubbed-env/argv construction correct (brief's explicit required
    test) for the ordinary, non-privileged run-script path."""

    def setUp(self):
        self.pw = pwd.getpwnam(config.JOB_USER)

    def test_non_privileged_argv_and_env_and_cwd_exact(self):
        job = _job()
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        rc = _run_stubbed("run-script", job, "/payload", "/out", cosigned=False,
                  popen=recorder)

        assert rc == 0
        assert len(recorder.calls) == 1
        argv, kwargs = recorder.calls[0]
        # The confined child is wrapped in a throwaway PID namespace
        # (unshare --pid --fork --kill-child) so a per-op timeout reaps
        # anything it setsid-detaches; unshare runs as root, then setpriv
        # drops to nebula-job INSIDE the namespace.
        assert argv == [
            "unshare", "--pid", "--fork", "--kill-child",
            "setpriv",
            f"--reuid={self.pw.pw_uid}",
            f"--regid={self.pw.pw_gid}",
            "--clear-groups",
            "/bin/sh",
            "/payload/probe.sh",
        ]
        assert kwargs["cwd"] == "/out"
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "HOME": "/out"}
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["start_new_session"] is True

    def test_env_has_exactly_two_keys_no_parent_leak(self):
        job = _job()
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        _run_stubbed("run-script", job, "/payload", "/out", cosigned=False, popen=recorder)
        _, kwargs = recorder.calls[0]
        assert set(kwargs["env"].keys()) == {"PATH", "HOME"}

    def test_non_bool_privileged_value_still_takes_the_nebula_job_path(self):
        # "true" (a string) must NOT be treated as privileged==True -- see
        # TestIsPrivileged; confirm end-to-end via run() that it still goes
        # through setpriv rather than requiring/bypassing cosign.
        job = _job(args={"privileged": "true"})
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        rc = _run_stubbed("run-script", job, "/payload", "/out", cosigned=False, popen=recorder)
        assert rc == 0
        argv, _ = recorder.calls[0]
        assert argv[:5] == ["unshare", "--pid", "--fork", "--kill-child", "setpriv"]

    def test_real_child_exit_code_is_returned_unchanged(self):
        job = _job()
        recorder = _RecordingPopen(_FakeProc(returncode=17))
        rc = _run_stubbed("run-script", job, "/payload", "/out", cosigned=False, popen=recorder)
        assert rc == 17

    def test_out_dir_handed_to_nebula_job_so_the_child_can_write(self):
        # Regression (caught by the §13 gate, 2026-07-17): a non-privileged
        # run-script runs AS nebula-job with cwd=out_dir and produces output
        # ONLY by writing files there, so out_dir MUST be chowned to nebula-job
        # -- else its first `> file` fails EACCES and the job is handler_failed
        # with empty outputs. Root-side collect still reads it via DAC override.
        job = _job()
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        with mock.patch("causb.dispatch.os.chown") as chown, \
             mock.patch("causb.dispatch.os.chmod") as chmod:
            run("run-script", job, "/payload", "/out", cosigned=False, popen=recorder)
        # TWO paths handled now (INPUT-side fix, 2026-07-16 gate): out_dir is
        # CHOWNED to nebula-job so the child can WRITE its output; the payload
        # tree is only CHGRP'd (uid left -1, root stays owner) + widened to 0750
        # so the child can READ its entrypoint but NOT mutate it -- causb.extract
        # writes the payload root-owned 0700/0600, unreadable to nebula-job, so
        # /bin/sh could not open the script. _grant_group_read_tree walks the
        # (here nonexistent) "/payload", so only its top-level chgrp+chmod fire
        # under this mock.
        chown.assert_any_call("/out", self.pw.pw_uid, self.pw.pw_gid)
        chown.assert_any_call("/payload", -1, self.pw.pw_gid, follow_symlinks=False)
        self.assertEqual(chown.call_count, 2)
        chmod.assert_any_call("/out", 0o700)
        chmod.assert_any_call("/payload", 0o750)
        self.assertEqual(chmod.call_count, 2)


class TestGrantGroupReadTree(unittest.TestCase):
    """`_grant_group_read_tree` gives a non-privileged run-script's nebula-job
    child GROUP read+traverse over its extracted payload (causb.extract writes it
    root-owned 0700/0600) WITHOUT surrendering ownership: chgrp only (uid -1,
    root stays owner), dirs 0750 / files 0640, so the child reads but cannot
    mutate the payload. Runs anywhere -- no getpwnam, no root: os.chown/os.chmod
    are mocked."""

    def test_recurses_chgrp_only_dirs_0750_files_0640(self):
        with tempfile.TemporaryDirectory() as base:
            os.makedirs(os.path.join(base, "sub", "deeper"))
            for rel in ("top.txt", "sub/mid.txt", "sub/deeper/leaf.txt"):
                open(os.path.join(base, rel), "w").close()
            dirs = {base, os.path.join(base, "sub"), os.path.join(base, "sub", "deeper")}
            files = {
                os.path.join(base, "top.txt"),
                os.path.join(base, "sub", "mid.txt"),
                os.path.join(base, "sub", "deeper", "leaf.txt"),
            }
            with mock.patch("causb.dispatch.os.chown") as chown, \
                 mock.patch("causb.dispatch.os.chmod") as chmod:
                _grant_group_read_tree(base, 4343)
            # Every node chgrp'd to gid 4343, uid left -1 (root stays OWNER),
            # never chasing a symlink.
            self.assertEqual({c.args[0] for c in chown.call_args_list}, dirs | files,
                             "must chgrp EVERY payload node")
            for c in chown.call_args_list:
                self.assertEqual(c.args[1:], (-1, 4343), "must chgrp only (uid -1)")
                self.assertIs(c.kwargs.get("follow_symlinks"), False,
                              "must not chase symlinks off-tree")
            # Dirs widened to 0750 (r-x group), files to 0640 (r group) -- group
            # read/traverse but no write, so the child cannot mutate its payload.
            self.assertEqual({c.args[0]: c.args[1] for c in chmod.call_args_list},
                             {**{d: 0o750 for d in dirs}, **{f: 0o640 for f in files}})


class TestRunScriptPrivilegedCosigned(unittest.TestCase):
    """privileged+cosigned: runs as root (no setpriv), and its sha256+bytes
    land in the audit log (brief's explicit required root-integration
    proof; this class proves the LOGIC with an injectable audit_log_path,
    the real root-owned path is proven end-to-end in dispatch_root.py)."""

    def setUp(self):
        self.payload_dir = tempfile.mkdtemp(prefix="causb-dispatch-test-payload-")
        self.script_path = os.path.join(self.payload_dir, "probe.sh")
        self.script_content = b"#!/bin/sh\necho hi\n"
        with open(self.script_path, "wb") as f:
            f.write(self.script_content)
        fd, self.audit_log_path = tempfile.mkstemp(prefix="causb-dispatch-test-audit-")
        os.close(fd)
        os.unlink(self.audit_log_path)  # _audit_privileged_run must create it fresh

    def tearDown(self):
        os.unlink(self.script_path)
        os.rmdir(self.payload_dir)
        if os.path.exists(self.audit_log_path):
            os.unlink(self.audit_log_path)

    def test_argv_is_bare_sh_no_setpriv_and_env_still_scrubbed(self):
        job = _job(args={"privileged": True})
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        rc = run("run-script", job, self.payload_dir, "/out", cosigned=True,
                  popen=recorder, audit_log_path=self.audit_log_path)

        assert rc == 0
        argv, kwargs = recorder.calls[0]
        # Privileged path: bare /bin/sh (no setpriv -- runs as root), but
        # STILL PID-namespace-wrapped so a timeout reaps any setsid escapee.
        assert argv == ["unshare", "--pid", "--fork", "--kill-child", "/bin/sh", self.script_path]
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "HOME": "/out"}
        assert kwargs["cwd"] == "/out"

    def test_audit_log_gets_correct_sha256_and_bytes_and_job_id(self):
        job = _job(args={"privileged": True})
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        run("run-script", job, self.payload_dir, "/out", cosigned=True,
            popen=recorder, audit_log_path=self.audit_log_path)

        with open(self.audit_log_path) as f:
            lines = [line for line in f if line.strip()]
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["job_id"] == job["job_id"]
        assert entry["operation"] == "run-script"
        assert entry["privileged"] is True
        assert entry["bytes"] == len(self.script_content)

        import hashlib
        assert entry["sha256"] == hashlib.sha256(self.script_content).hexdigest()

    def test_audit_log_created_mode_0600(self):
        job = _job(args={"privileged": True})
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        run("run-script", job, self.payload_dir, "/out", cosigned=True,
            popen=recorder, audit_log_path=self.audit_log_path)
        mode = os.stat(self.audit_log_path).st_mode & 0o777
        assert mode == 0o600

    def test_audit_happens_before_exec_never_after(self):
        # A popen that raises would leave the audit line missing if audit
        # ran AFTER exec -- prove ordering by making the fake popen blow up
        # and confirming the audit entry is STILL there (audit precedes the
        # popen call entirely; module docstring's fail-closed ordering).
        def _raising_popen(argv, **kwargs):
            raise OSError("simulated spawn failure")

        job = _job(args={"privileged": True})
        with self.assertRaises(OSError):
            run("run-script", job, self.payload_dir, "/out", cosigned=True,
                popen=_raising_popen, audit_log_path=self.audit_log_path)

        with open(self.audit_log_path) as f:
            lines = [line for line in f if line.strip()]
        assert len(lines) == 1


class TestVettedHandlerDispatch(unittest.TestCase):
    def setUp(self):
        self.handlers_dir = tempfile.mkdtemp(prefix="causb-dispatch-test-handlers-")
        self.handler_path = os.path.join(self.handlers_dir, "status")
        with open(self.handler_path, "w") as f:
            f.write("#!/bin/sh\necho status handler\n")
        os.chmod(self.handler_path, 0o755)

    def tearDown(self):
        os.unlink(self.handler_path)
        os.rmdir(self.handlers_dir)

    def test_argv_is_handler_then_job_json_then_payload_then_out(self):
        job = _job(operation="status", entrypoint=None, payload=[])
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        rc = run("status", job, "/payload", "/out", cosigned=False,
                  popen=recorder, handlers_dirs=[self.handlers_dir])

        assert rc == 0
        assert len(recorder.calls) == 1
        argv, kwargs = recorder.calls[0]
        assert argv[0] == self.handler_path
        assert argv[2] == "/payload"
        assert argv[3] == "/out"
        assert argv[1].endswith(".json")

    def test_job_json_temp_file_contains_the_job_dict_and_is_cleaned_up(self):
        job = _job(operation="status", entrypoint=None, payload=[])
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        run("status", job, "/payload", "/out", cosigned=False,
            popen=recorder, handlers_dirs=[self.handlers_dir])

        assert recorder.job_json_snapshot is not None
        assert json.loads(recorder.job_json_snapshot) == job

        argv, _ = recorder.calls[0]
        job_json_path = argv[1]
        assert not os.path.exists(job_json_path), "temp job.json must be cleaned up after dispatch"

    def test_unknown_operation_raises_handler_failed_and_popen_never_called(self):
        job = _job(operation="no-such-op", entrypoint=None, payload=[])
        with self.assertRaises(DispatchError) as cm:
            run("no-such-op", job, "/payload", "/out", cosigned=False,
                popen=_unreachable_popen, handlers_dirs=[self.handlers_dir])
        assert cm.exception.reason == "handler_failed"

    def test_unsafe_operation_string_raises_bad_manifest_and_popen_never_called(self):
        # operation is NEVER validated by manifest.parse() beyond isinstance
        # str -- dispatch must not join it into a handlers_dir path unchecked
        # (module docstring, point 2).
        job = _job(operation="../../etc/passwd", entrypoint=None, payload=[])
        with self.assertRaises(DispatchError) as cm:
            run("../../etc/passwd", job, "/payload", "/out", cosigned=False,
                popen=_unreachable_popen, handlers_dirs=[self.handlers_dir])
        assert cm.exception.reason == "bad_manifest"

    def test_non_executable_handler_file_is_not_found(self):
        os.chmod(self.handler_path, 0o644)  # readable but not executable
        job = _job(operation="status", entrypoint=None, payload=[])
        with self.assertRaises(DispatchError) as cm:
            run("status", job, "/payload", "/out", cosigned=False,
                popen=_unreachable_popen, handlers_dirs=[self.handlers_dir])
        assert cm.exception.reason == "handler_failed"

    def test_repo_relative_fallback_dir_is_consulted_when_installed_dir_lacks_it(self):
        empty_installed_dir = tempfile.mkdtemp(prefix="causb-dispatch-test-empty-")
        try:
            job = _job(operation="status", entrypoint=None, payload=[])
            recorder = _RecordingPopen(_FakeProc(returncode=0))
            rc = run("status", job, "/payload", "/out", cosigned=False, popen=recorder,
                      handlers_dirs=[empty_installed_dir, self.handlers_dir])
            assert rc == 0
            argv, _ = recorder.calls[0]
            assert argv[0] == self.handler_path
        finally:
            os.rmdir(empty_installed_dir)

    def test_default_handlers_dirs_include_installed_and_repo_relative(self):
        from causb import dispatch as dispatch_mod
        dirs = dispatch_mod._default_handlers_dirs()
        assert dirs[0] == config.HANDLERS_DIR
        assert dirs[1].endswith(os.path.join("box", "handlers"))


class TestVettedHandlerCosignedEnv(unittest.TestCase):
    """The break-glass co-signature is threaded to a vetted handler ONLY via
    the `CA_USB_COSIGNED` child env var, and ONLY as "1" when `cosigned is
    True` (the strict Task-14 rigor -- a truthy non-bool must not surface as
    a genuine co-signature). `rotate-job-signers.__main__` reads exactly this
    var. Run-script's env-scrub is a SEPARATE contract and is untouched."""

    def setUp(self):
        self.handlers_dir = tempfile.mkdtemp(prefix="causb-dispatch-cosign-env-")
        self.handler_path = os.path.join(self.handlers_dir, "rotate-job-signers")
        with open(self.handler_path, "w") as f:
            f.write("#!/bin/sh\necho vetted\n")
        os.chmod(self.handler_path, 0o755)

    def tearDown(self):
        os.unlink(self.handler_path)
        os.rmdir(self.handlers_dir)

    def _env_for(self, cosigned):
        job = _job(operation="rotate-job-signers", entrypoint=None, payload=[])
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        rc = run("rotate-job-signers", job, "/payload", "/out", cosigned=cosigned,
                 popen=recorder, handlers_dirs=[self.handlers_dir])
        assert rc == 0
        assert len(recorder.calls) == 1
        _, kwargs = recorder.calls[0]
        return kwargs["env"]

    def test_cosigned_literal_true_sets_env_1(self):
        env = self._env_for(True)
        assert env["CA_USB_COSIGNED"] == "1"

    def test_non_true_cosigned_never_sets_env_1(self):
        # Every non-`True` value -- including truthy non-bools -- must map to
        # "0", never "1" (fail closed: a break-glass change must not be
        # authorized by a forged/mistyped co-sign flag).
        for bad in (False, None, "True", "true", "1", 1, 2, [1], {"x": 1}, object()):
            env = self._env_for(bad)
            assert env.get("CA_USB_COSIGNED") == "0", \
                f"cosigned={bad!r} must map to CA_USB_COSIGNED=0, not {env.get('CA_USB_COSIGNED')!r}"

    def test_vetted_env_still_inherits_parent_environment(self):
        # Unlike run-script (scrubbed to PATH/HOME only), a vetted handler
        # keeps dispatch's own environment -- CA_USB_COSIGNED is ADDED, not a
        # replacement of the whole env. PATH is a stable parent-env witness.
        os.environ["CAUSB_DISPATCH_ENV_WITNESS"] = "present"
        try:
            env = self._env_for(True)
        finally:
            os.environ.pop("CAUSB_DISPATCH_ENV_WITNESS", None)
        assert env.get("CAUSB_DISPATCH_ENV_WITNESS") == "present"
        assert env["CA_USB_COSIGNED"] == "1"

    def test_stale_parent_cosigned_flag_is_overridden_when_not_cosigned(self):
        # Defense-in-depth: a CA_USB_COSIGNED=1 already in dispatch's own
        # environment must NOT leak through as this job's co-signature when
        # the job is not co-signed -- it is overwritten to "0".
        os.environ["CA_USB_COSIGNED"] = "1"
        try:
            env = self._env_for(False)
        finally:
            os.environ.pop("CA_USB_COSIGNED", None)
        assert env["CA_USB_COSIGNED"] == "0"


class TestVettedHandlerBgAuthorizedEnv(unittest.TestCase):
    """The break-glass-ALONE authorization (F-a) is threaded to a vetted
    handler ONLY via the `CA_USB_BG_AUTHORIZED` child env var, and ONLY as "1"
    when `bg_authorized is True` (the strict Task-14 rigor -- a truthy non-bool
    must not surface as a genuine authorization). It is INDEPENDENT of
    `CA_USB_COSIGNED`. `rotate-job-signers.__main__` reads exactly this var.
    Run-script's env-scrub is a SEPARATE contract and is untouched."""

    def setUp(self):
        self.handlers_dir = tempfile.mkdtemp(prefix="causb-dispatch-bg-env-")
        self.handler_path = os.path.join(self.handlers_dir, "rotate-job-signers")
        with open(self.handler_path, "w") as f:
            f.write("#!/bin/sh\necho vetted\n")
        os.chmod(self.handler_path, 0o755)

    def tearDown(self):
        os.unlink(self.handler_path)
        os.rmdir(self.handlers_dir)

    def _env_for(self, bg_authorized, cosigned=False):
        job = _job(operation="rotate-job-signers", entrypoint=None, payload=[])
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        rc = run("rotate-job-signers", job, "/payload", "/out", cosigned,
                 bg_authorized=bg_authorized,
                 popen=recorder, handlers_dirs=[self.handlers_dir])
        assert rc == 0
        assert len(recorder.calls) == 1
        _, kwargs = recorder.calls[0]
        return kwargs["env"]

    def test_bg_authorized_literal_true_sets_env_1(self):
        env = self._env_for(True)
        assert env["CA_USB_BG_AUTHORIZED"] == "1"

    def test_non_true_bg_authorized_never_sets_env_1(self):
        # Every non-`True` value -- including truthy non-bools -- must map to
        # "0", never "1" (fail closed: a break-glass-alone authorization must
        # not be forged by a mistyped flag).
        for bad in (False, None, "True", "true", "1", 1, 2, [1], {"x": 1}, object()):
            env = self._env_for(bad)
            assert env.get("CA_USB_BG_AUTHORIZED") == "0", \
                f"bg_authorized={bad!r} must map to CA_USB_BG_AUTHORIZED=0, not " \
                f"{env.get('CA_USB_BG_AUTHORIZED')!r}"

    def test_bg_authorized_defaults_to_0_when_omitted(self):
        # A call that omits bg_authorized entirely (the default) must set "0",
        # never leave it absent/leaking from the parent env.
        job = _job(operation="rotate-job-signers", entrypoint=None, payload=[])
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        run("rotate-job-signers", job, "/payload", "/out", False,
            popen=recorder, handlers_dirs=[self.handlers_dir])
        _, kwargs = recorder.calls[0]
        assert kwargs["env"].get("CA_USB_BG_AUTHORIZED") == "0"

    def test_bg_authorized_and_cosigned_are_independent(self):
        # The two flags are set independently: every combination is faithfully
        # reflected, neither shadows the other.
        env = self._env_for(True, cosigned=True)
        assert env["CA_USB_BG_AUTHORIZED"] == "1" and env["CA_USB_COSIGNED"] == "1"
        env = self._env_for(True, cosigned=False)
        assert env["CA_USB_BG_AUTHORIZED"] == "1" and env["CA_USB_COSIGNED"] == "0"
        env = self._env_for(False, cosigned=True)
        assert env["CA_USB_BG_AUTHORIZED"] == "0" and env["CA_USB_COSIGNED"] == "1"
        env = self._env_for(False, cosigned=False)
        assert env["CA_USB_BG_AUTHORIZED"] == "0" and env["CA_USB_COSIGNED"] == "0"

    def test_stale_parent_bg_flag_is_overridden_when_not_bg_authorized(self):
        # Defense-in-depth: a CA_USB_BG_AUTHORIZED=1 already in dispatch's own
        # environment must NOT leak through as this job's authorization when the
        # job is not bg-authorized -- it is overwritten to "0".
        os.environ["CA_USB_BG_AUTHORIZED"] = "1"
        try:
            env = self._env_for(False)
        finally:
            os.environ.pop("CA_USB_BG_AUTHORIZED", None)
        assert env["CA_USB_BG_AUTHORIZED"] == "0"

    def test_vetted_env_still_inherits_parent_environment(self):
        # Like CA_USB_COSIGNED, the bg flag is ADDED to a copy of dispatch's own
        # env, not a replacement (vetted handlers are trusted, not scrubbed).
        os.environ["CAUSB_BG_ENV_WITNESS"] = "present"
        try:
            env = self._env_for(True)
        finally:
            os.environ.pop("CAUSB_BG_ENV_WITNESS", None)
        assert env.get("CAUSB_BG_ENV_WITNESS") == "present"

    def test_run_script_env_scrub_unaffected_by_bg_authorized(self):
        # run-script's child env is scrubbed to EXACTLY {PATH, HOME}; passing
        # bg_authorized=True must NOT leak a CA_USB_BG_AUTHORIZED into it. The
        # flag is a vetted-handler-only channel; the un-vetted run-script child
        # never sees it (bg_authorized is only ever set for rotate-job-signers,
        # a vetted handler -- this test is defense-in-depth on the scrub).
        job = _job()  # a run-script job
        recorder = _RecordingPopen(_FakeProc(returncode=0))
        _run_stubbed("run-script", job, "/payload", "/out", False,
            bg_authorized=True, popen=recorder)
        _, kwargs = recorder.calls[0]
        assert set(kwargs["env"].keys()) == {"PATH", "HOME"}


class TestTimeout(unittest.TestCase):
    def test_timeout_kills_process_group_and_returns_sentinel(self):
        from causb import dispatch as dispatch_mod
        proc = _FakeProc(pid=99999, timeout_first=True)
        recorder = _RecordingPopen(proc)

        calls = {}

        def _fake_getpgid(pid):
            calls["getpgid_pid"] = pid
            return 424242

        def _fake_killpg(pgid, sig):
            calls["killpg_args"] = (pgid, sig)

        real_getpgid, real_killpg = dispatch_mod.os.getpgid, dispatch_mod.os.killpg
        dispatch_mod.os.getpgid = _fake_getpgid
        dispatch_mod.os.killpg = _fake_killpg
        try:
            rc = dispatch_mod._exec(["sleep", "999"], cwd="/tmp", env={},
                                     popen=recorder, timeout_s=0.01)
        finally:
            dispatch_mod.os.getpgid = real_getpgid
            dispatch_mod.os.killpg = real_killpg

        assert rc == dispatch_mod._TIMEOUT_EXIT_CODE
        assert calls["getpgid_pid"] == 99999
        import signal as signal_mod
        assert calls["killpg_args"] == (424242, signal_mod.SIGKILL)
        assert proc.communicate_calls == 2  # once (times out), once more to reap

    def test_timeout_swallows_process_lookup_error_from_already_dead_group(self):
        from causb import dispatch as dispatch_mod
        proc = _FakeProc(pid=1, timeout_first=True)
        recorder = _RecordingPopen(proc)

        def _raising_getpgid(pid):
            raise ProcessLookupError()

        real_getpgid = dispatch_mod.os.getpgid
        dispatch_mod.os.getpgid = _raising_getpgid
        try:
            rc = dispatch_mod._exec(["sleep", "999"], cwd="/tmp", env={},
                                     popen=recorder, timeout_s=0.01)
        finally:
            dispatch_mod.os.getpgid = real_getpgid

        assert rc == dispatch_mod._TIMEOUT_EXIT_CODE
        assert proc.communicate_calls == 2

    def test_no_timeout_normal_completion_calls_communicate_once(self):
        proc = _FakeProc(returncode=3, timeout_first=False)
        recorder = _RecordingPopen(proc)
        from causb.dispatch import _exec
        rc = _exec(["true"], cwd="/tmp", env={}, popen=recorder, timeout_s=5)
        assert rc == 3
        assert proc.communicate_calls == 1


if __name__ == "__main__":
    unittest.main()
