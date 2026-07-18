"""Crash-atomic job commit + boot reconciliation (spec S19 R7, D22, S7.8).

**Why this exists.** Certs this harness issues carry `NotBefore=now` -- they
are not reproducible. If a job is re-run after a crash or a `--retry`, the
second run's bytes would NOT be the same as the first run's, even though
both claim to answer the same `job_id`. D22's fix is a durable, crash-safe
results store: once a job is committed, EVERY later reference to that
`job_id` (a retry, a re-inserted stick, a reboot mid-delivery) must replay
the ORIGINAL bytes rather than ever re-running the handler. This module is
that store's write side (`commit()`) and its boot-time repair pass
(`reconcile_on_boot()`), plus the read side retry/replay uses
(`cached_result()`).

**The DONE marker is the single source of truth.** `{STATE_DIR}/seq` and
`{STATE_DIR}/consumed-jobs` (which `causb.freshness` reads to answer
"is this seq stale" / "is this job_id a replay") are DERIVED CACHES, never
independently authoritative -- mirrors `causb.freshness`'s own docstring,
which states the read side of this same contract. The only fact that is
ever allowed to make a job "count" is the presence of a structurally valid
`results/<job_id>/DONE` file. Everything else (the output files,
`status.json`, the seq/consumed-jobs caches) is either a precondition that
must exist BEFORE `DONE` is created, or a projection that can always be
rebuilt AFTER the fact by rescanning `RESULTS_DIR` for `DONE` files. This is
what makes crash recovery total and mechanical: `reconcile_on_boot()` never
has to reason about WHERE in `commit()` a crash happened, only whether
`DONE` made it to disk.

**`commit()`'s ordering, and why each step is where it is (R7):**

  0. Create `results/<job_id>/`, then **fsync `RESULTS_DIR` (the PARENT)**.
     A freshly-created directory ENTRY only survives power loss if its
     CONTAINING directory is fsync'd -- `fsync(2)` on the new `job_dir`
     itself makes its *contents* durable but does NOT make the *link to it*
     from `RESULTS_DIR` durable. Skipping this is the difference between a
     post-power-loss `reconcile_on_boot()` finding a committed `job_dir`
     (replay the exact bytes, per D22) and finding it vanished (re-run the
     handler -> a DIFFERENT `NotBefore=now` cert -> the exact
     duplicate/inconsistent-cert failure D22 exists to prevent).
  1. Write every entry in `outputs` (`{"path": <flat filename>, "data":
     <bytes>}`) into `results/<job_id>/`, each via tmp-name -> write ->
     `os.fsync` the fd -> `os.rename` into place. A crash here leaves
     `results/<job_id>/` populated with some subset of files and no `DONE`
     -- exactly as if the job had never been attempted, because...
  2. ...`status.json` (the caller's `out_status` dict, plus `job_id`/`seq`/
     the `outputs[]` metadata this function computes from what it just
     wrote) is written the same tmp -> fsync -> rename way. Still no
     `DONE`, so a crash here is equally harmless.
  3. `results/<job_id>/DONE` (`{"seq": <seq>}`) is written via
     tmp -> fsync -> rename -> **fsync the containing directory fd**. This
     rename is THE commit point. The directory fsync at this step is enough
     for every rename INSIDE `job_dir`: `fsync(2)` on a directory flushes
     every pending metadata change recorded against that directory's inode
     (every rename from steps 1-2 included), not just the operation
     immediately preceding the call -- so by construction, if `DONE`'s
     rename is durable, every earlier rename in the same directory is too.
     This is also why every output file this module writes must be a FLAT
     name directly inside `results/<job_id>/` (no nested subdirectories,
     enforced by `_validate_output_name`): a nested subdirectory's own
     directory-entry creation lives in a DIFFERENT inode than
     `results/<job_id>/` itself, which this single fsync would not cover.
     (Step 0's `RESULTS_DIR` fsync and this step's `job_dir` fsync are
     distinct inodes and both required -- neither substitutes for the
     other.)
  4. Only after `DONE` is durable does `commit()` bump the derived caches:
     `{STATE_DIR}/seq` = `max(current, seq)` (tmp -> fsync -> rename) and
     `{STATE_DIR}/consumed-jobs` gets `job_id` appended (open `O_APPEND`,
     write, `fsync`), then `STATE_DIR` itself is fsync'd so those entries'
     renames/appends are durable. A crash between step 3 and step 4 leaves
     a `results/<job_id>/DONE` that is valid but whose caches are stale/
     absent -- `reconcile_on_boot()` is what repairs exactly that gap, by
     rebuilding both caches from a fresh scan of every `DONE` file on disk
     rather than trusting whatever they currently say. (The `STATE_DIR`
     fsync here is therefore belt-and-braces -- reconcile would rebuild
     these regardless -- but it is cheap and keeps the caches honest across
     an ordinary clean reboot that never calls reconcile.)

**Idempotency (the crux of D22).** If `results/<job_id>/DONE` already
exists and is valid, `commit()` returns immediately without writing
anything -- even if the caller passes different `outputs`/`out_status`/
`seq` this time (e.g. a second, `NotBefore=now`-regenerated attempt at the
same `job_id`). The already-committed bytes are authoritative; a caller
that wants the actual (possibly-replayed) result must read it back via
`cached_result()`, never assume its own just-passed-in `outputs` were used.

**Symlink safety on the wipe/purge paths.** Both `commit()`'s stale-partial
wipe and `reconcile_on_boot()`'s no-`DONE` purge could, on a naive
implementation, follow a symlink planted AT `results/<job_id>` and delete
the SYMLINK TARGET's contents (a real risk given this store sits right
beside `CA_DIR`). Neither path is live-exploitable today (`RESULTS_DIR` is
root-only `0700` and `job_id` is a validated uuid4), but consistency with
`causb.collect`/`causb.extract`'s symlink paranoia -- and defense in depth
one bug away from mattering -- demands the same discipline here: every
entry is `lstat`'d (never a symlink-following `os.path.isdir`) and REFUSED
(never followed, never deleted-through) the instant it is a symlink.
`commit()` fails closed (raises) on a symlink where `job_dir` should be;
`reconcile_on_boot()` leaves it untouched and warns, rather than let one
tampered entry either corrupt an unrelated target or abort the whole boot.

**Trust scope.** Unlike `causb.extract`/`causb.collect` (which hardens
against a fully adversarial tar member name or a hostile run-script's
`out_dir` contents), this module's inputs are already-validated,
harness-internal values by the time they reach here: `job_id` is a uuid4
string `causb.manifest.parse()` already checked, and `outputs`/`out_status`
originate from the harness's own handler/collection step, not raw wire
bytes. Accordingly `commit()` raises a plain `ValueError` (a caller/
programming-error signal, not a wire-facing error enum) for a `job_id` or
output filename shape that would be unsafe to join into a path, or for a
symlink/non-directory sitting where `job_dir` belongs -- cheap defense-in-
depth, not a hardening boundary of its own.
"""

import hashlib
import json
import os
import stat
import sys

from causb import config

_DONE_NAME = "DONE"
_STATUS_NAME = "status.json"
_SEQ_NAME = "seq"
_CONSUMED_NAME = "consumed-jobs"
_RESERVED_OUTPUT_NAMES = frozenset({_DONE_NAME, _STATUS_NAME})


def _warn(message: str) -> None:
    """Emit an operator-facing line to stderr (systemd journal on the box).
    Used for the two conditions an operator must be able to tell apart on
    boot: a job dir whose `DONE` is PRESENT BUT CORRUPT (real outputs are
    being purged -- possible data loss on that job), versus a symlink
    planted where a job dir belongs (tampering/bug, left untouched)."""
    print(f"commitlog: {message}", file=sys.stderr)


def _validate_job_id(job_id: str) -> None:
    """Guard the one property that matters for THIS module's own safety:
    `job_id` must join into `RESULTS_DIR` as a single path component, never
    escaping it or resolving to `.`/`..`. (Its full uuid4 shape is already
    enforced upstream by `causb.manifest.parse()`; this is cheap defense-
    in-depth, not a re-implementation of that check.)"""
    if not job_id or "/" in job_id or job_id in (".", ".."):
        raise ValueError(f"unsafe job_id: {job_id!r}")


def _validate_output_name(name: str) -> None:
    """Guard an `outputs[]` entry's `path`: must be a single flat filename
    directly inside `results/<job_id>/` (see the module docstring for why
    nesting is out of scope -- it would escape the single directory-fsync
    that makes the whole commit batch durable), and must not collide with
    this module's own control files (`DONE`/`status.json`), which a
    same-named output would otherwise silently corrupt or be overwritten
    by."""
    if not name or "/" in name or name in (".", "..") or name in _RESERVED_OUTPUT_NAMES:
        raise ValueError(f"unsafe or reserved output filename: {name!r}")


def _lstat_or_none(path: str):
    """`os.lstat(path)` (never following a final symlink), or `None` if the
    path does not exist. Any other OSError (e.g. a permission error on the
    parent) propagates -- that is an environment bug on a root-only tree,
    not an expected 'entry absent' case."""
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _fsync_dir(path: str) -> None:
    """Open `path` as a directory and `os.fsync` it, so pending changes to
    THAT directory's inode -- newly-created child entries (`mkdir`/`rename`
    of a child) -- are made durable. A file's own `fsync` never covers the
    durability of the directory ENTRY that names it; this is the companion
    call that does (see `commit()`'s step 0 / step 3 in the module
    docstring)."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(dir_path: str, name: str, data: bytes) -> None:
    """Write `data` as `name` inside `dir_path`: open a `.tmp` sibling,
    write, `fsync` the fd, close, then atomically replace `name` with it.

    Deliberately does NOT fsync `dir_path` itself -- callers that need the
    new/renamed ENTRY to be durable (not just its contents) pair this with
    an explicit `_fsync_dir(dir_path)` at the right point in their ordering
    (see `commit()`/`reconcile_on_boot()`), so a batch of writes into one
    directory needs only a single trailing directory fsync rather than one
    per file.
    """
    final_path = os.path.join(dir_path, name)
    tmp_path = final_path + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)


def _write_done(job_dir: str, seq: int) -> None:
    """The single atomic commit point (R7/D22): tmp -> fsync -> rename ->
    fsync the CONTAINING DIRECTORY's fd. Everything written into `job_dir`
    before this call is disposable (a crash before this rename lands
    leaves a dir indistinguishable from "job never started", purged by
    `reconcile_on_boot`); everything after it (the seq/consumed-jobs cache
    bump) is re-derivable from this marker alone, so this rename is the
    ONLY step in the whole commit that must itself be crash-atomic.
    """
    _atomic_write(job_dir, _DONE_NAME, json.dumps({"seq": seq}).encode())
    _fsync_dir(job_dir)


def _has_done_file(job_dir: str) -> bool:
    """True if a `DONE` entry exists in `job_dir` (via `lexists`, so a
    symlink named `DONE` counts as present rather than being followed).
    Used only to distinguish a "DONE present but corrupt" purge (real
    outputs lost -- warn the operator) from a "never had a DONE" purge (a
    cleanly re-runnable partial -- silent)."""
    return os.path.lexists(os.path.join(job_dir, _DONE_NAME))


def _read_done_seq(job_dir: str):
    """Return the `seq` recorded in `job_dir`'s `DONE` marker if it exists
    and is structurally valid (parses as JSON, is an object, has a
    NON-NEGATIVE integer -- not bool -- `seq`, mirroring `manifest.py`'s
    `seq >= 0` rule), else `None`. `None` covers every reason a dir isn't
    authoritative yet: no `DONE` at all, `job_dir` itself missing, or a
    `DONE` that somehow isn't a well-formed marker -- all of which
    `reconcile_on_boot` treats identically (purge candidate).
    """
    try:
        with open(os.path.join(job_dir, _DONE_NAME)) as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    seq = payload.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return None
    return seq


def _write_output(job_dir: str, entry: dict) -> dict:
    """Write one `outputs[]` entry (`{"path": <flat name>, "data": <bytes>}`)
    atomically into `job_dir`, returning the `status.json`-shaped
    `{"path", "sha256", "bytes"}` metadata for it (the same shape
    `causb.collect.collect()` already returns, for consistency across the
    codebase's two `results/<job_id>/`-populating call sites)."""
    name = entry["path"]
    data = entry["data"]
    _validate_output_name(name)
    _atomic_write(job_dir, name, data)
    return {
        "path": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _read_seq() -> int:
    """Read `{STATE_DIR}/seq` (default 0 if absent -- a box that has never
    committed a job has no seq history yet). Mirrors
    `causb.freshness._last_seq()` exactly; duplicated rather than imported
    across modules to keep each module's on-disk-format assumptions local
    and self-contained."""
    try:
        with open(os.path.join(config.STATE_DIR, _SEQ_NAME)) as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0


def _append_consumed(job_id: str) -> None:
    """Append `job_id` (newline-terminated) to `{STATE_DIR}/consumed-jobs`,
    fsync'd. This is the one FAST-PATH cache update `commit()` performs
    itself (append-only, no rescan); `reconcile_on_boot()` is the only
    place that ever fully REBUILDS this file from scratch."""
    path = os.path.join(config.STATE_DIR, _CONSUMED_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, f"{job_id}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _bump_caches(job_id: str, seq: int) -> None:
    """Step 4 of `commit()`'s ordering (see module docstring): bump
    `{STATE_DIR}/seq` to `max(current, seq)` (never regress it) and append
    `job_id` to `consumed-jobs`, then fsync `STATE_DIR` so both entries'
    renames/appends are durable. Only ever called AFTER `_write_done` has
    already made `DONE` durable -- these caches are re-derivable from the
    `DONE` markers by `reconcile_on_boot`, so this fsync is belt-and-braces
    for an ordinary clean reboot, not a correctness prerequisite."""
    new_seq = max(_read_seq(), seq)
    _atomic_write(config.STATE_DIR, _SEQ_NAME, str(new_seq).encode())
    _append_consumed(job_id)
    _fsync_dir(config.STATE_DIR)


def _remove_tree(path: str) -> None:
    """Recursively remove a PLAIN DIRECTORY `path` without `shutil` (stdlib
    os only, per this project's convention). Refuses to operate on a
    symlink (raises) and never follows one during descent
    (`os.walk(followlinks=False)`, the default, stated explicitly): a
    deletion that followed a symlinked `results/<job_id>` or a symlinked
    subdir would delete an unrelated TARGET's contents rather than the job
    dir's -- exactly the footgun the wipe/purge paths must avoid given this
    store sits beside `CA_DIR`. Callers `lstat`-guard before invoking this;
    the top-of-function check is redundant defense in depth against a
    future caller that forgets."""
    if os.path.islink(path):
        raise ValueError(f"refusing to remove a symlink as a tree: {path!r}")
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            entry = os.path.join(root, name)
            # `os.walk(followlinks=False)` still LISTS a symlink-to-directory
            # in `dirs` (it just doesn't descend into it) -- but `os.rmdir` on
            # a symlink raises NotADirectoryError, which would abort the whole
            # scan (and, wired into F2's boot reconcile, leave a partial job
            # dir + stale caches behind). Unlink such a symlink IN PLACE
            # (never following it to rmdir the unrelated target); only a real
            # subdirectory is os.rmdir'd. Symlinks-to-FILES are already in
            # `files` above and os.remove'd, so this covers both.
            if os.path.islink(entry):
                os.remove(entry)
            else:
                os.rmdir(entry)
    os.rmdir(path)


def commit(job_id: str, seq: int, outputs: list, out_status: dict) -> None:
    """Durably commit one job's results (R7/D22). `outputs` is a list of
    `{"path": <flat filename>, "data": <bytes>}` entries to write into
    `results/<job_id>/`; `out_status` is the rest of `status.json`'s
    fields (e.g. `schema_version`/`status`/`box`/timestamps/`error`/etc.
    per S6) -- `commit()` fills in/overwrites `job_id`, `seq`, and
    `outputs` (computed as `{"path","sha256","bytes"}` per entry) itself.

    If `results/<job_id>/DONE` already exists and is valid, this is a
    silent no-op: the job was already committed, and D22 requires a retry
    to replay those exact bytes rather than accept new ones (see the
    module docstring's idempotency section). Otherwise, see the module
    docstring for the exact write ordering and why it is crash-safe.

    If `job_dir` already exists WITHOUT a valid `DONE` -- a previous
    `commit()` attempt for this same `job_id` crashed before completing --
    it is wiped first rather than written into as-is: through the commit
    point, a no-`DONE` dir is indistinguishable from "job never started"
    (the same premise `reconcile_on_boot` acts on), so starting this
    attempt from a clean directory is what prevents a file the EARLIER,
    incomplete attempt wrote (but this attempt's `outputs` no longer
    includes) from lingering on disk, untracked by the `status.json` this
    attempt writes.

    Raises `ValueError` (fail closed) if `job_id`/an output name is
    path-unsafe, or if a SYMLINK or a non-directory sits where `job_dir`
    belongs -- it is never followed or written through (see the module
    docstring's symlink-safety section).
    """
    _validate_job_id(job_id)
    job_dir = os.path.join(config.RESULTS_DIR, job_id)

    # lstat FIRST (never a symlink-following os.path.isdir): a symlink where
    # job_dir belongs is refused before it can be read through by the DONE
    # check or deleted through by the wipe below.
    existing = _lstat_or_none(job_dir)
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise ValueError(f"results/<job_id> is a symlink; refusing: {job_dir!r}")

    if _read_done_seq(job_dir) is not None:
        return  # already committed -- replay the existing bytes, never re-run.

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    if existing is not None:
        if not stat.S_ISDIR(existing.st_mode):
            raise ValueError(
                f"results/<job_id> exists but is not a directory: {job_dir!r}"
            )
        _remove_tree(job_dir)  # stale pre-DONE partial from an earlier crash.
    os.makedirs(job_dir, mode=0o700)

    # Step 0: make the job_dir ENTRY itself durable in its parent before any
    # content goes in -- a file fsync never covers the durability of the
    # directory link that names its container (see module docstring).
    _fsync_dir(config.RESULTS_DIR)

    outputs_meta = [_write_output(job_dir, entry) for entry in outputs]

    status = dict(out_status)
    status["job_id"] = job_id
    status["seq"] = seq
    status["outputs"] = outputs_meta
    _atomic_write(
        job_dir, _STATUS_NAME, json.dumps(status, indent=2, sort_keys=True).encode()
    )

    _write_done(job_dir, seq)  # THE commit point.

    _bump_caches(job_id, seq)


def reconcile_on_boot() -> None:
    """Boot-time repair pass (R7's "Restart recovery"): rescans
    `RESULTS_DIR` and makes `{STATE_DIR}/seq`/`consumed-jobs` agree with
    whatever `DONE` markers actually exist on disk, discarding any
    partial/crashed job directory (see module docstring). Idempotent and
    safe to call on every boot regardless of whether the previous
    shutdown was clean.

    Each entry is `lstat`'d, never a symlink-following `os.path.isdir`: a
    symlink where a job dir belongs is left UNTOUCHED (never followed,
    never purged-through -- that would delete an unrelated target) and
    warned about, rather than aborting the whole boot over one tampered
    entry.
    """
    os.makedirs(config.RESULTS_DIR, exist_ok=True)

    max_seq = 0
    consumed = []
    for entry in sorted(os.listdir(config.RESULTS_DIR)):
        job_dir = os.path.join(config.RESULTS_DIR, entry)
        st = _lstat_or_none(job_dir)
        if st is None:
            continue  # vanished between listdir and lstat; nothing to do.
        if stat.S_ISLNK(st.st_mode):
            # Never follow or purge through a symlink -- it could point at a
            # sensitive target beside this store (CA_DIR). Leave it in place
            # and surface it; it is not a legitimate committed job.
            _warn(f"results/{entry} is a symlink; refusing to follow or purge it")
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue  # a stray non-dir entry; not a job dir, not this pass's job.

        seq = _read_done_seq(job_dir)
        if seq is None:
            # No valid DONE -> discard. Distinguish a corrupt-but-PRESENT
            # DONE (real outputs are being thrown away -- an operator should
            # see this) from a never-had-a-DONE partial (cleanly re-runnable,
            # expected, silent).
            if _has_done_file(job_dir):
                _warn(
                    f"results/{entry}: DONE present but corrupt; "
                    "purging committed outputs (possible data loss for this job)"
                )
            _remove_tree(job_dir)
            continue

        consumed.append(entry)
        max_seq = max(max_seq, seq)

    _atomic_write(
        config.STATE_DIR, _SEQ_NAME, str(max(_read_seq(), max_seq)).encode()
    )
    body = "".join(f"{job_id}\n" for job_id in consumed).encode()
    _atomic_write(config.STATE_DIR, _CONSUMED_NAME, body)
    # Make both rebuilt cache entries' renames durable (see _bump_caches).
    _fsync_dir(config.STATE_DIR)


def cached_result(job_id: str) -> str | None:
    """Return the `results/<job_id>/` directory path if it has been
    durably committed (a valid `DONE` marker present), else `None`. Used
    by the replay path (D22/R10e): a fresh/replayed delivery reads the
    committed bytes from this directory rather than re-running anything.

    A symlink sitting where `job_dir` belongs is treated as NOT a
    committed result (`None`, never followed) -- consistent with
    `commit()`/`reconcile_on_boot()` refusing to trust one.
    """
    _validate_job_id(job_id)
    job_dir = os.path.join(config.RESULTS_DIR, job_id)
    st = _lstat_or_none(job_dir)
    if st is not None and stat.S_ISLNK(st.st_mode):
        return None
    if _read_done_seq(job_dir) is not None:
        return job_dir
    return None
