"""Handler dispatch: the privilege-separation core (spec S6, S8, S12,
D12/D17/D20, S19 R2). `run()` is the single choke point through which every
job's handler actually executes, and it is where the design's central trust
boundary is enforced in code: an operator-signed but otherwise UN-VETTED
`run-script` payload must never see `ca.key`, and a `privileged` escalation
to root must never happen without an already-verified break-glass
co-signature.

**Two execution paths, one enforcement point.**

- **Vetted installed handlers** (`ca-bootstrap`, `sign-hosts`, `status`, ...)
  are pre-written, root-owned, operator-INSTALLED code (not something a job
  bundle can supply the bytes of) -- R2 says these simply run as root, no
  privilege check needed, because the code itself was already vetted at
  install time. `run()` looks one up by `operation` name in `handlers_dirs`
  (installed `config.HANDLERS_DIR` first, falling back to a repo-relative
  `box/handlers/` so this also works straight out of an uninstalled
  checkout) and execs it with argv `<handler> <job.json> <payload_dir>
  <out_dir>`.
- **`run-script`** is fundamentally different: the BYTES to execute are
  attacker-controlled job content (merely operator-*signed*, not vetted).
  Guarantee #5 (design S1) requires it run confined as the unprivileged
  `nebula-job` system account UNLESS `args.privileged` is `true`, in which
  case D20 requires an already-verified break-glass co-signature
  (`cosigned==True`, computed upstream by `causb.verify` -- this module
  trusts that bool, it does not re-verify anything) before running as root.

**Why there is no `box/handlers/run-script` file on disk (a deliberate
choice, not an oversight).** The task brief that produced this module
explicitly offered a choice: either ship a thin `box/handlers/run-script`
"handler" that `dispatch` execs like any other vetted handler, or have
`dispatch` invoke `/bin/sh` directly and skip the file entirely. This module
takes the second option. Reasoning: run-script's execution contract (drop to
`nebula-job` via `setpriv`, scrub the environment, pin `cwd`, close stdin,
pass no argv, audit+root instead when privileged+cosigned) is NOT the
generic `<handler> <job.json> <payload_dir> <out_dir>` vetted-handler
contract -- it is a distinct, narrower contract over the SAME two bytes
(`/bin/sh` + the entrypoint script). Routing it through a `box/handlers/
run-script` file would force that file to reimplement (in a second
language/process boundary, running AS ROOT before it could even consider
dropping privilege) exactly the uid/gid-resolution + setpriv + env-scrub
logic already sitting right here -- more indirection and a second copy of
the most security-critical code in this module, for no benefit: run-script
is never looked up by name in `handlers_dirs` (a job cannot smuggle a
same-named file into that directory; it isn't installed from job content),
so there is nothing for a separate file to add. `box/handlers/` therefore
ships only `status` (a genuine vetted handler); `run-script` is handled
entirely, and only, by the code below.

**The exit-code / exception contract.** `run(...) -> int` returns the
executed child's real exit status for both paths (0 typically; whatever the
handler/script itself returned otherwise) -- this is what a later task's
`status.json.exit_code` reflects directly. A timed-out child (see below)
reports back as `_TIMEOUT_EXIT_CODE` (124, the same sentinel GNU `timeout(1)`
uses) rather than a made-up value, since S19 R10a's status.json.error enum
has no dedicated "timed out" string of its own -- like `causb.collect`'s
`bad_output` before it, a caller mapping this into `status.json` folds it
into `"handler_failed"` (the natural, already-precedented bucket for "the
thing we tried to run did not complete successfully"). A PRE-EXECUTION guard
failure -- `cosign_failed` (privileged without a co-signature: guarantee #5;
"nothing runs" per the brief, achieved simply by raising before any exec is
even attempted) or `bad_manifest` (entrypoint/operation fails this module's
OWN defense-in-depth re-validation, or no vetted handler exists for
`operation`, folded into `handler_failed`) -- instead RAISES `DispatchError`
carrying a `.reason` from that same fixed S19 R10a enum, exactly like every
other spec-error module in this codebase (`ManifestError`/`MountError`/
`LedError`/`ButtonError`/`CollectError`); a later task catches it the same
uniform way it already catches those.

**Two things `causb.manifest.parse()` does NOT validate, that this module
must -- both genuine defense-in-depth, not redundant paperwork:**

1. `entrypoint`. `manifest.parse()` already enforces "a basename, no `/`, not
   `.`/`..`, present in `payload[]`" for `run-script` jobs -- but the task
   brief explicitly asks this module to re-derive that same property itself
   rather than blindly trust that some upstream caller ran `parse()` first
   (or ran it correctly). `_validate_entrypoint()` below re-implements the
   identical check from scratch, independent of `manifest.py`'s own copy.
2. `operation`. Unlike `entrypoint`/`payload[]` entries, `manifest.parse()`
   places NO restriction at all on the `operation` string beyond "is a str"
   -- it is never joined into a filesystem path inside `manifest.py`, so it
   never needed one there. It very much does get joined into a path HERE
   (`os.path.join(handlers_dir, operation)`, to look up a vetted handler
   executable), which means an `operation` value such as `"../../../usr/
   bin/something-world-executable"` would, without a guard, let a merely
   operator-*signed* manifest escape `handlers_dirs` entirely and exec an
   arbitrary pre-existing executable elsewhere on the box AS ROOT -- a real
   privilege/scope escalation the vetted-handler design (a small, curated,
   root-trusted set) exists specifically to prevent. `_safe_component()`
   below is checked before `operation` ever reaches a path join.

**Scrubbed env, verified live against this exact mechanism (not just
asserted from reading the man page).** `run-script`'s child always gets an
env of EXACTLY `{"PATH": "/usr/bin:/bin", "HOME": <out_dir>}` -- passed as
subprocess's `env=` kwarg, which REPLACES the environment outright rather
than merging over `os.environ` (unlike e.g. `causb.mountctl`'s `_run`, which
deliberately merges C-locale vars OVER the ambient env for a different
reason). `setpriv` itself does not touch the environment unless told to
(`--reset-env` was deliberately NOT used -- replacing `env=` at the
`subprocess.Popen` boundary already fully covers it), so this dict is
exactly what both `setpriv` and the `/bin/sh` it execs see. Verified live on
the box: a probe using this project's real
`nebula-job` uid/gid showed `id` inside the sandboxed child reporting
`uid=999(nebula-job) gid=990(nebula-job) groups=990(nebula-job)` (no
supplementary groups leaked -- confirms `--clear-groups`), `env` inside it
showing only `HOME`/`PATH` (plus shell-native `PWD`, which `/bin/sh` sets
itself from `cwd` and was never part of any parent's environment), and
`cat` against a real `root:root 0400` file failing `Permission denied`.

**Per-op timeout containment: PID namespace + process-group kill (S16,
S19 R3), live-verified against a deliberate escapee.** run-script's child
is wrapped in `unshare --pid --fork --kill-child` (see `_UNSHARE_PIDNS`),
so it and EVERYTHING it spawns live in a throwaway PID namespace. On
timeout, `_exec` SIGKILLs the process group led by `unshare` (spawned
`start_new_session=True`), which -- via the wrapper's parent-death-signal
+ the kernel's "PID-namespace init death reaps the whole namespace" rule
-- tears down the entire subtree. This is STRICTER than a plain
`os.killpg` on `start_new_session`'s group alone: `killpg` reaches a child
that merely backgrounds with `&` (which stays in the group), but a
run-script that does `setsid sh -c 'sleep 60; touch MARKER' &` puts its
grandchild in a NEW session/group that `killpg` cannot reach -- and that
grandchild survives the timeout and writes `MARKER` after `run()` has
already returned 124. REPRODUCED LIVE on the box:
plain `setpriv` leaks (`MARKER` appears), `unshare --pid --fork
--kill-child` reaps it (`MARKER` never appears), the confined child still
runs as `uid=999(nebula-job)`, and exit codes still propagate unchanged
through `unshare` (17->17, 0->0, 1->1). Vetted handlers are trusted, root-
installed code (not attacker-supplied bytes) and are NOT PID-namespace-
wrapped -- they keep the plain `start_new_session`+`killpg` path, since the
"deliberately setsid-escape the timeout" threat is specific to un-vetted
run-script content. `_exec()` uses `Popen.communicate(timeout=...)`
rather than a bare `.wait(timeout=...)`: `Popen.wait()` while `stdout=PIPE`/
`stderr=PIPE` is a documented stdlib deadlock hazard if the child writes
enough output to fill the OS pipe buffer before anyone drains it;
`communicate()` is the stdlib's own prescribed fix, and is used identically
on both the normal-completion and post-kill reap calls. Captured
stdout/stderr are intentionally discarded, never returned: S6 defines
`status.json.error` as a fixed enum, "never raw stderr" -- surfacing
captured child text anywhere would undermine that wire contract, so this
function's only channel to its caller is the integer exit code.

**The strict `is True` check on `args.privileged`.** `job["args"]`'s shape
is, unlike most of the manifest, entirely UNVALIDATED by `manifest.parse()`
(it never inspects `args` at all) -- it could be missing, `null`, a list, a
string, anything. `_is_privileged()` therefore treats anything other than
the literal JSON boolean `true` as "not privileged": a naive `if
args.get("privileged"):` would treat the STRING `"false"` as Python-truthy
and incorrectly force a job down the cosign-required root path it never
asked for (an availability bug -- a legitimate job now needs a co-signature
it wasn't built with) -- annoying but strictly on the SAFE side (LESS
privilege granted, not more; nothing can make this check grant root that
should not have). There is no failure mode of this strict check that grants
root undeservedly; only ones that could withhold it from a malformed-but-
well-intentioned job, which is the correct direction to err.

**Trust scope on the audit read.** `_audit_privileged_run()` opens and hashes
the entrypoint script via a plain `open()`/`read()`, not the fd-pinned
`os.fwalk`/`dir_fd` machinery `causb.collect` uses for `out_dir`. That
extra paranoia is about an ADVERSARY (the running `nebula-job` script)
mutating a directory `causb.collect` is about to read FROM, concurrently,
after having run. `payload_dir` here is the opposite: an already-verified,
freshly-extracted, root-owned tmpfs tree that nothing else has had a chance
to write into yet at this point in the pipeline (verification and
extraction both precede `dispatch.run()`) -- there is no concurrent
adversary with write access to race against, so a plain read is honest,
not a shortcut.
"""

import hashlib
import json
import os
import pwd
import signal
import subprocess
import tempfile
from datetime import datetime, timezone

from causb import audit, config

# box/lib/causb/dispatch.py -> box/handlers -- lets `run()` find vetted
# handlers straight out of an uninstalled repo checkout (e.g. this project's
# own on-box unit tests), falling back behind the real installed location.
_REPO_HANDLERS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "handlers")
)

_SCRIPT_INTERPRETER = "/bin/sh"
_SETPRIV = "setpriv"
_SCRUBBED_PATH = "/usr/bin:/bin"

# run-script's confining PID-namespace wrapper (S16/S19 R3 timeout
# containment). `unshare --pid --fork --kill-child` creates a new PID
# namespace while still root, `--fork`s an init (PID 1 of that namespace),
# and sets that init's parent-death signal to SIGKILL. `setpriv` (or, on the
# privileged path, `/bin/sh` directly) then runs INSIDE the namespace as a
# child of that init. On a per-op timeout, `_exec` SIGKILLs the process
# group whose leader is this `unshare` (it is `start_new_session=True`'s
# group leader in the PARENT namespace); killing `unshare` fires the init's
# PDEATHSIG, and the kernel's "PID-namespace init death SIGKILLs every
# process in the namespace" guarantee then reaps EVERYTHING inside --
# including a grandchild the script deliberately `setsid`-detached into its
# own session/process group to escape a plain `killpg`. Plain `killpg`
# alone does NOT reach such an escapee (reproduced live);
# the PID namespace is what closes it. `unshare` exits with its
# child's real status, so exit codes still propagate unchanged (verified
# live: 17->17, 0->0, 1->1). Creating a PID namespace needs CAP_SYS_ADMIN,
# which the harness has (design S4); `--mount-proc` is deliberately NOT used
# -- the reaping guarantee comes from init-death, not from a fresh /proc,
# and the DAC boundary (uid drop) is `setpriv`'s job, unaffected by /proc.
_UNSHARE_PIDNS = ["unshare", "--pid", "--fork", "--kill-child"]

# GNU coreutils timeout(1)'s own exit code for "command timed out" -- reused
# here rather than inventing a new sentinel, since none of this project's
# fixed enums has a dedicated "timed out" value (see module docstring).
_TIMEOUT_EXIT_CODE = 124


class DispatchError(Exception):
    """A job could not be dispatched at all -- raised BEFORE any child is
    spawned (never after; a spawned child's own outcome is always returned
    as an int exit code, never raised). `reason` is one of the fixed S19
    R10a status.json.error enum strings:

    - "cosign_failed": `args.privileged` is `true` but `cosigned` is not
      the literal boolean `True` (a truthy non-bool such as the string
      "False" is REFUSED, not accepted -- fail closed). Nothing executed.
    - "bad_manifest": `run-script`'s `entrypoint` fails this module's own
      defense-in-depth re-validation (not a basename, contains "/", a
      control char such as NUL, is "."/"..", or is not listed in
      `payload[]`), or `operation` is unsafe to join into a handler-lookup
      path (contains "/", a control char, is "."/"..).
    - "handler_failed": `operation` is not `run-script` and no vetted
      handler executable exists for it in `handlers_dirs`.

    This is a wire contract relied on by later tasks -- the strings must
    not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _safe_component(value):
    """True if `value` is a non-empty string safe to use as a single path
    component -- no "/", not "."/"..", and NO control characters (NUL,
    C0 `\\x00`-`\\x1f`, or DEL `\\x7f`). Used for BOTH `operation` (never
    validated by `causb.manifest.parse()` at all -- see module docstring)
    and, redundantly, `entrypoint` (already validated by `parse()`, but the
    brief calls for this module to re-check anyway).

    The control-char check specifically closes an embedded-NUL gap: a
    validly-signed manifest whose entrypoint/operation contains a `\\x00`
    would otherwise pass every OTHER check here (no "/", not "."/"..") and
    then raise a RAW, uncaught `ValueError('embedded null byte')` out of the
    later `os.path.join`/`Popen`/`os.path.isfile` call -- violating this
    module's "every dispatch-time rejection is a DispatchError, never a bare
    exception" contract. Rejecting all C0/DEL controls (not just NUL) is the
    same conservative posture `causb.manifest`/`caj-recv` take: a path
    component legitimately never contains one, so refusing the whole class
    costs nothing and avoids reasoning about which individual control bytes
    a downstream syscall happens to choke on."""
    if not isinstance(value, str) or not value:
        return False
    if "/" in value or value in (".", ".."):
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
        return False
    return True


def _validate_entrypoint(job):
    """Re-derive, independently of `causb.manifest.parse()`, that
    `job["entrypoint"]` is a safe basename actually present in
    `job["payload"]`. Returns the entrypoint string on success; raises
    `DispatchError("bad_manifest")` otherwise. Defense-in-depth (module
    docstring, point 1) -- this does not trust that `parse()` ran, or ran
    correctly, upstream of this call."""
    payload = job.get("payload")
    entrypoint = job.get("entrypoint")
    if not isinstance(payload, list):
        raise DispatchError("bad_manifest")
    if not _safe_component(entrypoint) or entrypoint not in payload:
        raise DispatchError("bad_manifest")
    return entrypoint


def _is_privileged(job):
    """True only if `job["args"]` is a dict whose `"privileged"` key is
    EXACTLY the JSON boolean `true` -- see module docstring for why this is
    a strict `is True` check rather than ordinary Python truthiness."""
    args = job.get("args")
    if not isinstance(args, dict):
        return False
    return args.get("privileged") is True


def _scrubbed_env(out_dir):
    """The run-script env contract, verbatim: empty except a minimal PATH
    and HOME=out_dir (module docstring's "scrubbed env" section)."""
    return {"PATH": _SCRUBBED_PATH, "HOME": out_dir}


def _audit_privileged_run(job_id, script_path, audit_log_path):
    """Append one JSONL entry recording a privileged run-script's identity
    (S19 §4's audit.log: "run-script logs script sha256+bytes") to
    `audit_log_path`, creating it `0600` root-owned on first write (append-
    only thereafter). Returns `(sha256_hex, byte_count)`. Raises a raw
    `OSError` on any failure to write -- deliberately NOT caught: this is
    the FAIL-CLOSED gate for privileged execution (module docstring's trust-
    scope note) -- called strictly BEFORE `_exec()` spawns anything, so an
    audit-write failure aborts the whole privileged run rather than let it
    proceed unrecorded.
    """
    with open(script_path, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    size = len(data)
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "job_id": job_id,
        "operation": "run-script",
        "privileged": True,
        "sha256": digest,
        "bytes": size,
    }
    # Shared writer (causb.audit) so this run-script IDENTITY record and
    # ca-usb-run's per-job TERMINAL record can never drift in on-disk format
    # (§4/§11: same canonical JSONL + fsync'd O_APPEND 0600 append). NOT
    # wrapped: an audit-write failure must PROPAGATE here to fail closed --
    # this runs strictly before _exec spawns the privileged child, so a
    # failure aborts the run rather than letting it proceed unrecorded (this
    # function's docstring's fail-closed gate).
    audit.append(entry, path=audit_log_path)
    return digest, size


def _exec(argv, cwd, env, popen, timeout_s):
    """Spawn `argv` (own process group, stdin closed, stdout/stderr
    captured-then-discarded -- module docstring), wait up to `timeout_s`,
    and return its exit code -- or `_TIMEOUT_EXIT_CODE` if it had to be
    killed. See the module docstring for why `communicate()` (not a bare
    `wait()`) and why `start_new_session=True` + `killpg` (not a plain
    `kill()`) are both load-bearing, not stylistic.

    A `ProcessLookupError` while resolving/killing the group (the child
    already exited in the race between the timeout firing and this code
    running) is swallowed -- the child is gone either way, which is exactly
    the outcome a timeout is trying to achieve.
    """
    proc = popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        proc.communicate(timeout=timeout_s)
        return proc.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()  # reap, and drain whatever was already buffered
        return _TIMEOUT_EXIT_CODE


def _grant_group_read_tree(path, gid):
    """Give group `gid` read+traverse over `path` and everything beneath it
    WITHOUT surrendering ownership: chgrp every node to `gid` (uid left as -1, so
    root stays OWNER) and widen dirs to 0750 / files to 0640 (group gets r-x/r--,
    never write). Used to let a non-privileged run-script's nebula-job child --
    dropped with `--regid` to this gid -- READ its own entrypoint and any payload
    files, since causb.extract writes the payload root-owned 0700 dirs / 0600
    files that the child could otherwise neither traverse nor read (/bin/sh
    EACCES -> handler_failed exit 2, the §13-gate bug this fixes).

    Root stays owner and the group has NO write, so the child cannot create,
    modify, unlink, or plant a symlink inside its payload dirs -- preserving this
    module's "payload_dir is immutable input" invariant (the child's writable
    scratch/output area is out_dir, chowned to it separately). This is the
    least-privilege form of the fix: read is all the child needs. The tree is
    causb.extract's output -- plain regular files + directories, no symlinks
    (extract rejects SYMTYPE/LNKTYPE/specials; dirs are mkdirat'd, files are
    fresh O_CREAT inodes) -- inside a per-job private tmpfs no other process can
    race (chown is pre-exec, jobs are flock-serialized), so a straightforward
    os.walk is safe; every chown is follow_symlinks=False belt-and-suspenders so
    not even a should-never-exist symlink could redirect it off-tree. Root
    remains owner of every dir (0750), so this same root os.walk keeps traversing
    as it widens."""
    os.chown(path, -1, gid, follow_symlinks=False)
    os.chmod(path, 0o750)
    for root, dirs, files in os.walk(path):
        for name in dirs:
            p = os.path.join(root, name)
            os.chown(p, -1, gid, follow_symlinks=False)
            os.chmod(p, 0o750)
        for name in files:
            p = os.path.join(root, name)
            os.chown(p, -1, gid, follow_symlinks=False)
            os.chmod(p, 0o640)


def _run_script(job, payload_dir, out_dir, cosigned, popen, timeout_s, audit_log_path):
    entrypoint = _validate_entrypoint(job)
    script_path = os.path.join(payload_dir, entrypoint)
    privileged = _is_privileged(job)

    if privileged and cosigned is not True:
        # STRICT `is not True` (NOT `not cosigned`): `cosigned` arrives from
        # an upstream caller (`causb.verify`, a later task) and, exactly like
        # `args.privileged` (see `_is_privileged`/module docstring), a truthy
        # NON-bool -- the string "False", the string "0", any non-empty
        # string, a non-zero int -- must NOT be accepted as a genuine
        # co-signature. `not cosigned` would let `cosigned="False"` sail
        # through (a non-empty string is truthy, so `not "False"` is False)
        # and run the script AS ROOT against `ca.key`. This is the fail-
        # CLOSED direction: anything that is not the literal boolean `True`
        # is treated as "not co-signed", so nothing runs. Raising here,
        # before any exec attempt, IS the "nothing runs" enforcement.
        raise DispatchError("cosign_failed")

    env = _scrubbed_env(out_dir)

    if privileged:
        # cosigned is guaranteed to be exactly True here (else the guard
        # above already raised) -- run as root, no setpriv. Audit BEFORE
        # exec (fail closed; see _audit_privileged_run's docstring).
        _audit_privileged_run(job.get("job_id"), script_path, audit_log_path)
        argv = _UNSHARE_PIDNS + [_SCRIPT_INTERPRETER, script_path]
    else:
        pw = pwd.getpwnam(config.JOB_USER)
        # The child runs AS nebula-job with cwd=out_dir and produces output ONLY
        # by writing files into it (its stdout/stderr are discarded, S6), so
        # out_dir MUST be writable by nebula-job. The harness creates it
        # root-owned; hand it to nebula-job HERE -- the single point that knows
        # the child is dropping to that uid. Without this a non-privileged
        # run-script cannot create any output file (its `> out.txt` fails EACCES),
        # so it exits nonzero with empty outputs -> handler_failed. (A privileged
        # run-script and every vetted handler run AS ROOT and need no chown: root
        # writes out_dir regardless, and the later root-side `causb.collect` reads
        # it regardless of owner via DAC override.) chmod 0700 keeps the untrusted
        # script's scratch/output area private to nebula-job.
        os.chown(out_dir, pw.pw_uid, pw.pw_gid)
        os.chmod(out_dir, 0o700)
        # Symmetric INPUT-side fix: the child must READ its entrypoint (and any
        # payload files it references), but causb.extract writes the payload
        # root-owned 0700 dirs / 0600 files -- unreadable+untraversable to
        # nebula-job, so /bin/sh could not even open the entrypoint (EACCES ->
        # exit 2, no output). Grant the child GROUP read+traverse WITHOUT giving
        # it ownership (root stays owner; group r-x/r-- only, no write), so it
        # reads its payload but cannot mutate it -- payload_dir stays "immutable
        # input" (below). Safe: the tree is signature-verified + symlink-safe-
        # extracted, lives in the private per-job tmpfs, and root never re-reads
        # payload_dir after dispatch (collect reads out_dir). ONLY on the
        # nebula-job drop path -- a root child reads the payload as root already.
        _grant_group_read_tree(payload_dir, pw.pw_gid)
        argv = _UNSHARE_PIDNS + [
            _SETPRIV,
            f"--reuid={pw.pw_uid}",
            f"--regid={pw.pw_gid}",
            "--clear-groups",
            _SCRIPT_INTERPRETER,
            script_path,
        ]

    return _exec(argv, cwd=out_dir, env=env, popen=popen, timeout_s=timeout_s)


def _default_handlers_dirs():
    return [config.HANDLERS_DIR, _REPO_HANDLERS_DIR]


def _find_handler(operation, handlers_dirs):
    if not _safe_component(operation):
        return None
    for d in handlers_dirs:
        candidate = os.path.join(d, operation)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _write_job_json(job):
    """Serialize `job` (the single validated job dict) to a fresh temp JSON
    file for a vetted handler's `<job.json>` argv slot -- deliberately NOT
    written inside `payload_dir` (input, immutable by convention) or
    `out_dir` (a later step, `causb.collect`, walks `out_dir` to gather the
    job's OWN outputs; a scratch file dispatch itself wrote there would be
    incorrectly shipped to the stick as if the handler produced it)."""
    fd, path = tempfile.mkstemp(prefix="causb-dispatch-job-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(job, f)
    except BaseException:
        os.unlink(path)
        raise
    return path


def _vetted_handler_env(cosigned, bg_authorized):
    """The environment a vetted handler is exec'd with: a copy of dispatch's
    own environment (vetted handlers are trusted, root-installed code -- they
    are NOT env-scrubbed like the un-vetted run-script child) plus TWO
    independent flags that thread upstream authorization results down to a
    handler that cares about them (currently only `rotate-job-signers`):

    - `CA_USB_COSIGNED`: the break-glass CO-signature result (primary + a
      distinct break-glass sig), read by the handler as `== "1"`.
    - `CA_USB_BG_AUTHORIZED`: the F-a break-glass-ALONE authorization -- this
      job's ONLY valid signature was a break-glass one standing in for a lost
      primary (the recovery/lockout path), read by the handler as `== "1"`.
      A bg-authorized rotate may change ONLY allowed_signers, never
      breakglass_signers (the handler enforces that off this flag).

    Both use STRICT `is True` -- exactly the same rigor applied to
    `args.privileged`/the run-script cosign gate: a truthy NON-bool (the string
    "True", a non-zero int, ...) must NOT be surfaced as a genuine
    co-signature/authorization, so it maps to "0", never "1". Each flag is
    always set explicitly ("0" when not granted) rather than left to leak from
    dispatch's own environment, so a stray inherited `CA_USB_COSIGNED=1` /
    `CA_USB_BG_AUTHORIZED=1` can never masquerade as this job's grant. The two
    are INDEPENDENT: a break-glass-alone job is `bg_authorized=True`,
    `cosigned=False` (there is no primary to co-sign with)."""
    env = dict(os.environ)
    env["CA_USB_COSIGNED"] = "1" if cosigned is True else "0"
    env["CA_USB_BG_AUTHORIZED"] = "1" if bg_authorized is True else "0"
    return env


def _run_vetted_handler(operation, job, payload_dir, out_dir, cosigned, bg_authorized,
                        popen, timeout_s, handlers_dirs):
    if not _safe_component(operation):
        # Never even attempt the lookup with an unsafe operation string
        # (module docstring, point 2) -- fail the same way manifest.py
        # fails a structurally bad field.
        raise DispatchError("bad_manifest")

    handler_path = _find_handler(operation, handlers_dirs)
    if handler_path is None:
        raise DispatchError("handler_failed")

    job_json_path = _write_job_json(job)
    try:
        argv = [handler_path, job_json_path, payload_dir, out_dir]
        try:
            return _exec(argv, cwd=out_dir,
                         env=_vetted_handler_env(cosigned, bg_authorized),
                         popen=popen, timeout_s=timeout_s)
        except OSError:
            # A spawn-time race (e.g. the handler vanished between
            # _find_handler's check and exec) -- fold into the same bucket
            # a handler that ran and failed would use, rather than let a
            # raw OSError escape this module's enum contract.
            raise DispatchError("handler_failed")
    finally:
        os.unlink(job_json_path)


def run(operation, job, payload_dir, out_dir, cosigned, bg_authorized=False,
        *, popen=subprocess.Popen, timeout_s=None, handlers_dirs=None,
        audit_log_path=None):
    """Dispatch one validated job (S6/S8). `job` is the single job dict
    `causb.manifest.parse()` returned at `jobs[0]` (job_id/operation/args/
    payload/entrypoint). `cosigned` is the already-computed break-glass
    co-signature result and `bg_authorized` the already-computed F-a
    break-glass-ALONE authorization result (both from `causb.verify` via
    `box/bin/ca-usb-run`) -- this function only ever READS those bools, never
    verifies anything itself. They are INDEPENDENT flags.

    Returns the executed child's exit code (int) on every path that
    actually ran something -- including a non-zero exit from a failing
    script/handler, and `_TIMEOUT_EXIT_CODE` (124) on a per-op timeout.
    Raises `DispatchError(reason)` (module docstring) for every case where
    NOTHING was executed at all: a `run-script` failing this module's own
    entrypoint/operation defense-in-depth re-validation, `privileged`
    without `cosigned`, or no vetted handler found for a non-run-script
    `operation`.

    `bg_authorized` is threaded ONLY to the vetted-handler path (as the child
    env `CA_USB_BG_AUTHORIZED`, `is True`-strict): it is meaningful only to
    `rotate-job-signers`, which is a vetted handler, never `run-script` (whose
    scrubbed {PATH,HOME}-only env is a separate contract, left untouched).

    `timeout_s` defaults to `config.OP_TIMEOUT_S` (S16); `popen`/
    `handlers_dirs`/`audit_log_path` default to the real
    `subprocess.Popen`/installed-then-repo-relative handler dirs/
    `config.AUDIT_LOG` and exist purely as DI seams for tests (mirrors this
    project's established `causb.mountctl` convention of an injectable
    `runner`). Each is resolved fresh inside this call (never bound as a
    literal default at import time) so a test that points `config.AUDIT_LOG`
    /`config.OP_TIMEOUT_S` at a temp path/short value ahead of an
    unqualified call still takes effect.
    """
    effective_timeout = config.OP_TIMEOUT_S if timeout_s is None else timeout_s
    effective_handlers_dirs = (
        _default_handlers_dirs() if handlers_dirs is None else list(handlers_dirs)
    )
    effective_audit_log_path = config.AUDIT_LOG if audit_log_path is None else audit_log_path

    if operation == "run-script":
        # run-script never consults bg_authorized: it is not the recovery
        # handler, and its env is scrubbed to {PATH,HOME} regardless.
        return _run_script(
            job, payload_dir, out_dir, cosigned,
            popen=popen, timeout_s=effective_timeout, audit_log_path=effective_audit_log_path,
        )

    return _run_vetted_handler(
        operation, job, payload_dir, out_dir, cosigned, bg_authorized,
        popen=popen, timeout_s=effective_timeout, handlers_dirs=effective_handlers_dirs,
    )
