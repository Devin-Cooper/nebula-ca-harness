"""Regression guard: the systemd sandbox must never re-break causb.extract's
openat2(2) requirement.

BACKGROUND (2026-07-16 incident). The first real signed job on the box
frantic-blinked on an extract failure (bad_manifest). Root cause: a
`RestrictSUIDSGID=yes` directive in ca-usb-job@.service. Its seccomp filter must
inspect the file-creation MODE to reject SUID/SGID bits, but openat2(2) carries
mode inside a by-POINTER `struct open_how` that seccomp cannot dereference -- so
systemd blocks openat2 outright (ENOSYS). `causb.extract` REQUIRES openat2
(RESOLVE_BENEATH|NO_SYMLINKS|NO_XDEV is its entire kernel-enforced confinement,
with NO fallback), so RestrictSUIDSGID and the hardened extractor are mutually
exclusive. Once air-gapped this failure is invisible as anything but an LED
blink, so a future sandbox-hardening change that reintroduces an openat2-hostile
directive must fail loudly HERE.

Two layers:
  * STATIC checks (always run, unprivileged) -- assert the unit files never carry
    the two known-hostile directive classes: RestrictSUIDSGID, and any
    SystemCallFilter (the unit deliberately omits it precisely because a bare
    @system-service breaks mount/openat2). This is the effective every-CI guard,
    since the suite runs unprivileged and cannot spin up the real root sandbox.
  * A RUNTIME reproduction (root + systemd-run only; skips otherwise) -- runs the
    real extractor under a real transient systemd sandbox and proves that
    RestrictSUIDSGID=yes really does break it on this kernel while its absence
    lets it succeed. This validates that the static guard guards a genuine
    hazard, not a stale folk belief.
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SYSTEMD_DIR = os.path.join(_REPO_ROOT, "box", "systemd")
_JOB_UNIT = os.path.join(_SYSTEMD_DIR, "ca-usb-job@.service")
_RECONCILE_UNIT = os.path.join(_SYSTEMD_DIR, "ca-usb-reconcile.service")
_BOX_LIB = os.path.join(_REPO_ROOT, "box", "lib")


def _directive_keys(unit_path):
    """The lower-cased KEY of every active (non-comment, non-blank) `Key=Value`
    line in a unit file."""
    keys = []
    with open(unit_path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            keys.append(line.split("=", 1)[0].strip().lower())
    return keys


def _directive_value(unit_path, key):
    """The value of the LAST active `key=value` line (case-insensitive key),
    or None if absent."""
    val = None
    with open(unit_path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip().lower() == key.lower():
                val = v.strip()
    return val


class TestSandboxUnitsStatic(unittest.TestCase):
    def test_units_exist(self):
        self.assertTrue(os.path.isfile(_JOB_UNIT), _JOB_UNIT)
        self.assertTrue(os.path.isfile(_RECONCILE_UNIT), _RECONCILE_UNIT)

    def test_job_unit_never_sets_restrictsuidsgid(self):
        self.assertNotIn(
            "restrictsuidsgid", _directive_keys(_JOB_UNIT),
            "RestrictSUIDSGID re-added to ca-usb-job@.service: it makes openat2(2) "
            "return ENOSYS, and causb.extract requires openat2 with NO fallback "
            "(2026-07-16 incident). Remove it -- see the runtime reproduction below.",
        )

    def test_reconcile_unit_never_sets_restrictsuidsgid(self):
        self.assertNotIn(
            "restrictsuidsgid", _directive_keys(_RECONCILE_UNIT),
            "RestrictSUIDSGID re-added to ca-usb-reconcile.service (runs the same "
            "ca-usb-run binary whose causb.extract needs openat2). Remove it.",
        )

    def test_job_unit_restrictnamespaces_allows_pid(self):
        # A non-privileged run-script's child is wrapped in `unshare --pid
        # --fork --kill-child` (causb.dispatch) so the harness can reap the
        # untrusted script's processes; that needs CLONE_NEWPID.
        # RestrictNamespaces=yes blocks it via seccomp, so EVERY real run-script
        # died handler_failed before it ran (2026-07-17 §13 gate finding;
        # verified on-box: `unshare --pid` fails under =yes, succeeds under
        # =pid). The unit must allow the pid namespace. Vetted handlers never
        # unshare, so this does not affect status/ca-bootstrap/etc.
        v = _directive_value(_JOB_UNIT, "RestrictNamespaces")
        self.assertIsNotNone(v, "ca-usb-job@.service has no RestrictNamespaces line")
        self.assertNotEqual(
            v.lower(), "yes",
            "RestrictNamespaces=yes blocks the run-script's `unshare --pid` "
            "confinement wrapper (seccomp EPERM) -- run-scripts fail before they run.",
        )
        self.assertIn(
            "pid", [t.lower() for t in v.split()],
            f"RestrictNamespaces must allow the pid namespace for run-scripts; got {v!r}.",
        )

    def test_job_unit_has_no_systemcallfilter(self):
        # The unit deliberately uses NO SystemCallFilter: a bare @system-service
        # breaks mount(2)/openat2 (verified in task 12). If one is ever genuinely
        # needed it MUST allow openat2 + the mount class -- update this guard
        # consciously when you do.
        self.assertNotIn(
            "systemcallfilter", _directive_keys(_JOB_UNIT),
            "ca-usb-job@.service added a SystemCallFilter; the unit intends NONE "
            "(a bare @system-service breaks openat2/mount).",
        )


def _build_known_good_tar(path):
    """A minimal well-formed job.tar (manifest.json + one payload file) that the
    hardened extractor accepts -- so success/failure isolates the sandbox, not
    the tar."""
    stage = tempfile.mkdtemp()
    try:
        mpath = os.path.join(stage, "manifest.json")
        with open(mpath, "wb") as f:
            f.write(b'{"schema_version": 1, "box": "nebula-ca", "seq": 1, "jobs": []}')
        pdir = os.path.join(stage, "payload")
        os.makedirs(pdir)
        with open(os.path.join(pdir, "f.txt"), "wb") as f:
            f.write(b"hello\n")
        with tarfile.open(path, "w") as tf:  # uncompressed: extract needs r:
            tf.add(mpath, arcname="manifest.json")
            tf.add(os.path.join(pdir, "f.txt"), arcname="payload/f.txt")
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _extract_under_sandbox(tar_path, out_dir, *, restrict_suidsgid):
    """Run the REAL causb.extract under a transient systemd sandbox with (or
    without) RestrictSUIDSGID=yes. Returns the child's exit code: 0 == the tar
    extracted, 3 == ExtractError (openat2 blocked), other == harness error."""
    snippet = (
        "import sys\n"
        "from causb import extract\n"
        "try:\n"
        "    extract.extract(sys.argv[1], sys.argv[2])\n"
        "except extract.ExtractError:\n"
        "    sys.exit(3)\n"
        "sys.exit(0)\n"
    )
    cmd = [
        "systemd-run", "--pipe", "--wait", "--quiet", "--collect",
        f"--setenv=PYTHONPATH={_BOX_LIB}",
    ]
    if restrict_suidsgid:
        cmd.append("--property=RestrictSUIDSGID=yes")
    cmd += [sys.executable, "-c", snippet, tar_path, out_dir]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


@unittest.skipUnless(
    os.geteuid() == 0 and shutil.which("systemd-run") is not None,
    "runtime sandbox reproduction needs root + systemd-run (the suite runs "
    "unprivileged; the static checks above are the every-CI guard)",
)
class TestSandboxOpenat2Runtime(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="causb-sandbox-")
        self.tar = os.path.join(self.base, "job.tar")
        _build_known_good_tar(self.tar)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_extract_succeeds_without_restrictsuidsgid(self):
        out = os.path.join(self.base, "out-ok")
        os.makedirs(out)
        rc = _extract_under_sandbox(self.tar, out, restrict_suidsgid=False)
        self.assertEqual(rc, 0, "extract must succeed under the sandbox WITHOUT "
                                "RestrictSUIDSGID (openat2 available)")

    def test_restrictsuidsgid_breaks_extract_the_incident_reproduced(self):
        out = os.path.join(self.base, "out-bad")
        os.makedirs(out)
        rc = _extract_under_sandbox(self.tar, out, restrict_suidsgid=True)
        self.assertNotEqual(rc, 0, "RestrictSUIDSGID=yes must break extract "
                                   "(openat2 -> ENOSYS): the 2026-07-16 hazard the "
                                   "static guard prevents. If this now passes, the "
                                   "kernel/systemd behavior changed -- re-evaluate.")


if __name__ == "__main__":
    unittest.main()
