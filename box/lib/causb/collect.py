"""Symlink-safe output collection: the ROOT harness copies a job's
outputs from an unprivileged run-script's `out_dir` into the trusted
`results/<job_id>/` store (spec S19 R1 -- the rev-3 BLOCKER -- and
S7.8-9).

**Why this exists.** `run-script` executes operator-signed but otherwise
un-vetted script content, sandboxed as the unprivileged `nebula-job` user
with `/etc/nebula-ca` and `/var/lib/nebula-ca` (which holds `ca.key`) made
inaccessible (S19 R2) -- that DAC/sandbox boundary is what keeps the JOB
itself from reading `ca.key` directly. But immediately afterward, the
harness's own COLLECTION step runs as ROOT and walks `out_dir` to gather
whatever the job left behind. A signature check on the job bundle does
not protect this later step: if collection ever resolved a symlink the
job planted, root -- which CAN read `ca.key` -- would read straight
through it on the job's behalf and copy the key's bytes into
`results_dir`, from where the normal outbox-delivery path (S7.9) would
carry them onto the USB stick in plain sight. `collect()` is the fix.

**The read side is fully fd-pinned (this is load-bearing, not belt-and-
braces).** A naive implementation walks with `os.walk` (which yields path
STRINGS) and reopens each leaf by reconstructing the full path string
with `O_NOFOLLOW`. That is exploitable: `O_NOFOLLOW` guards only the FINAL
path component, so a surviving `nebula-job` process can, in the window
between the walk discovering an intermediate directory `out_dir/sub` and
the leaf `out_dir/sub/x` being opened, atomically swap `sub` for a
symlink -- `os.symlink("/var/lib/nebula-ca/ca", "out_dir/sub")` -- so that
a leaf named `x` (or `ca.key`) now resolves through the symlinked
ancestor to a real, regular, single-linked `ca.key`, sails past
`S_ISREG`/`st_nlink==1`, and is copied out by root. (This was demonstrated
live on the box against a string-path prototype.)

The fix is to never reconstruct a path string for any read: descend with
`os.fwalk(out_dir, follow_symlinks=False)`, which yields
`(dirpath, dirnames, filenames, dirfd)` where `dirfd` is a real open file
descriptor PINNED to the directory's inode, and open every leaf with
`os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirfd)`. A
`dir_fd`-relative open resolves `name` inside the exact inode `os.fwalk`
already opened during descent, so renaming the `sub` NAME to a symlink
afterward cannot redirect it -- an fd follows the inode, not the name.
This mirrors the WRITE side (`_open_dir_component`/`_write_dest`), which
was already fd-pinned; the fix brings the read side to parity.
`os.fwalk(follow_symlinks=False)` additionally uses the kernel
`lstat`/`open`/`fstat` `samestat` trick internally so it never recurses
INTO a symlinked subdirectory (verified empirically on this box's 6.1.141
kernel), and `os.walk`/`os.scandir`/any
path-string leaf open appears nowhere in this module.

Per-entry, on top of that pinned descent:

- **Leaf files** are opened `dir_fd`-relative with
  `os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK`, then verified via
  `os.fstat` on the resulting fd -- never a path-based `os.stat`/
  `os.lstat`, which inspects whatever inode is AT the name right now
  rather than the one this fd already holds. The fd is REQUIRED to be
  `stat.S_ISREG()` (rejects a directory or a device/socket/fifo node,
  none of which `O_NOFOLLOW` alone rejects -- only a *symlink* final
  component triggers `ELOOP`) AND `st_nlink == 1` (rejects a hardlink: a
  second directory entry for the same inode elsewhere, which the harness
  must not agree to disclose just because the job's own limited
  permissions happened to let it `link()` to it). `O_NONBLOCK` is there
  purely so a planted FIFO with no writer connected cannot hang the
  harness at `open()` (empirically it would block indefinitely without
  it; with it the open returns immediately and the very next `fstat`
  rejects the FIFO via `S_ISREG`); `O_NONBLOCK` is a documented no-op for
  regular files, so the accept path is unaffected.

- **Symlinked subdirectories** appear in `os.fwalk`'s `dirnames` (a
  symlink-to-dir has `is_dir()` true) but are never recursed into by the
  walk. On top of that already-safe non-traversal, `_collect_into`
  lstat's each `dirnames` entry `dir_fd`-relative
  (`os.stat(dname, dir_fd=dirfd, follow_symlinks=False)`) and RAISES
  `CollectError("path_traversal")` the instant one is a symlink -- a
  deliberate strengthening beyond silent non-traversal (a directory
  symlink is at least as dangerous as a file symlink: `out_dir/evil ->
  /var/lib/nebula-ca` would expose an entire sensitive tree, not one
  named file), so this module fails the WHOLE collection loudly rather
  than let one planted directory symlink be silently skipped while the
  rest of the run looks normal.

- **Depth** is capped at `config.CAPS["depth"]` (4) on the out_dir-
  relative path, mirroring `causb.extract`: a directory whose relative
  depth exceeds the cap raises `CollectError("path_traversal")` (which
  also bounds descent so a pathologically deep tree cannot exhaust file
  descriptors), and a file whose relative path has more than
  `config.CAPS["depth"]` components is rejected before it is even opened.

- **Count** is capped at `config.CAPS["tar_files"]` (64) output files.
  S16 (the design's caps table) defines no distinct output-side count or
  byte cap of its own -- it is scoped to the INBOUND job.tar/manifest/
  payload -- and this task's brief lists only an over-COUNT test as
  required, with no byte-cap test; reusing `tar_files` keeps this
  module's behavior traceable to an actual, already-reviewed design
  number rather than inventing a new, undefined constant (S19 R1's prose
  mentions "count+byte caps (§16)" in passing, but no distinct output-
  byte-cap constant exists to implement against).

**Error model (mirrors `causb.extract`'s "no raw OSError escapes for
attacker-influenced input" contract).** `CollectError.reason` is one of:
"path_traversal" (a REFUSED ENTRY TYPE -- symlink/hardlink/device/socket/
fifo, or an over-depth path); "cap_exceeded" (too many output files);
"bad_output" (a content-triggered `OSError` -- an unreadable subdir the
walk cannot descend, or a leaf whose open/fstat fails for a non-
type-refusal reason). On this LED-only headless box an uncaught `OSError`
leaves the error-reporting path undefined, so every failure driven by the
CONTENTS of `out_dir` (walk descent errors, leaf open/stat errors) folds
into the enum. The SOLE intentionally-raw `OSError` is the top-level
bootstrap: `out_dir` itself missing/not-a-directory (surfaced directly by
`os.fwalk`, not via its `onerror`), and `results_dir` itself not being an
openable directory -- both are trusted, harness-created paths (like
`causb.extract.extract`'s `dest_dir`), so a bad one is a caller/
environment bug, not attacker-influenced input, and propagates plainly.

**Write side (`results_dir`, trusted but written defensively).** Every
destination file is opened `dir_fd`-relative, descending one component at
a time from a single `root_fd` opened once in `collect()`, with the leaf
opened `os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW` -- `O_EXCL`
fails outright if anything already exists at that name (no silent
overwrite/follow) and `O_NOFOLLOW` guards the intermediate directories
`O_EXCL` does not cover. `open()`/`shutil.copy`/`os.walk` are never used
anywhere in this module.

**Scope note vs. `causb.extract`.** `causb.extract` additionally drives a
raw `openat2(2)` syscall with `RESOLVE_BENEATH` to confine a FULLY
attacker-controlled tar member NAME -- a string that could itself contain
`..` or an absolute path. This module does not need that: every name it
opens came from a real `os.fwalk`/`os.scandir` directory listing, which
can never yield `..`, `.`, an empty component, or an absolute string (the
OS guarantees this for a real directory's entries) -- so there is no
untrusted *string* to confine here, only untrusted file TYPE and an
untrusted directory *inode identity*, both of which `dir_fd`-pinned
`O_NOFOLLOW` opens + `fstat` fully close. "Absolute path" and ".."
rejection (named in this module's S19 R1 rejection list) are therefore
satisfied STRUCTURALLY -- `collect()` never accepts a caller-supplied
per-file name, so no such string can ever reach an `open()` call.

Every rejection raises `CollectError(reason)` IMMEDIATELY, aborting the
whole `collect()` call -- mirroring `causb.extract`'s per-member
fail-fast contract. S19 R7's commit protocol (populate `results/<job_id>/`
then write a single atomic `DONE` marker) is the real atomicity boundary
for the box; this module's sole job is to guarantee that whatever bytes DO
land in `results_dir` are genuine regular-file content the job itself
wrote, never a followed symlink, an ancestor-swapped inode, or a hardlink
to something else.
"""

import errno
import hashlib
import os
import stat

from causb import config

_READ_CHUNK = 1024 * 1024  # 1 MiB per read() call while hashing+copying.


class CollectError(Exception):
    """A collected entry (or the running file count, or the out_dir
    contents) failed the S19 R1 output-collection policy.

    `reason` is one of the fixed enum strings:

    - "path_traversal": a REFUSED ENTRY TYPE anywhere in out_dir -- a
      symlink (file or directory), hardlink, device, socket, or fifo --
      or a path nested deeper than config.CAPS["depth"].
    - "cap_exceeded": more output files than config.CAPS["tar_files"]
      allows, OR the copy exhausted the shared 32M tmpfs (ENOSPC/EDQUOT on
      the write side -- out_dir and collect_dir share it).
    - "bad_output": a content-triggered OSError -- from the out_dir CONTENTS
      (an unreadable subdirectory the walk cannot descend, or a leaf whose
      open/fstat fails for a reason other than a type refusal), OR from the
      write side (an O_EXCL collision, a mid-copy source read error, or a
      non-capacity I/O error writing into results_dir).

    This is a wire contract relied on by later tasks (status.json.error,
    S19 R10a) -- the strings must not change. (Note: "bad_output" is this
    module's own content-error value; it is not one of S19 R10a's en-
    umerated status.json.error strings, so the harness must map it into
    that enum -- most naturally onto "handler_failed" -- when it writes
    status.json. Flagged for the integrating task.)
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _fold_walk_error(error):
    """`onerror` callback for `os.fwalk`: fold any error hit while
    descending the CONTENTS of out_dir (e.g. a `nebula-job`-owned
    chmod-000 subdirectory the walk cannot open) into
    `CollectError("bad_output")`, so no raw `OSError` escapes `collect()`
    for attacker-influenced content (mirrors `causb.extract`'s enum
    contract; an uncaught OSError on this LED-only box leaves the error-
    reporting path undefined).

    This fires ONLY for content errors: `os.fwalk` surfaces a failure to
    open `out_dir` ITSELF (missing/not-a-directory -- the one genuinely
    environment-scoped, non-attacker case) by raising directly, NOT
    through this `onerror` (verified empirically on the box), so that
    top-level bootstrap failure stays a raw
    `OSError`.
    """
    raise CollectError("bad_output") from error


def _classify_open_failure(dirfd, name):
    """Return the `CollectError` for a leaf `os.open(..., dir_fd=dirfd)`
    that raised `OSError`, WITHOUT trusting a path string and without
    ever following anything.

    lstat `name` relative to the same pinned `dirfd` purely to LABEL the
    error: a symlink final component (which failed the open with `ELOOP`)
    or any other non-regular type such as a Unix domain socket (which
    fails the open with `ENXIO`, confirmed empirically) is a
    REFUSED ENTRY TYPE -> "path_traversal"; a regular file
    whose open nonetheless failed (a permission/I/O error), or a name we
    can no longer lstat at all, is a content/environment failure ->
    "bad_output". The open has ALREADY failed, so nothing is opened or
    copied based on this lstat -- a race between the failed open and this
    lstat can only mislabel an already-rejecting error, never affect
    safety.
    """
    try:
        lst = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    except OSError:
        return CollectError("bad_output")
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        return CollectError("path_traversal")
    return CollectError("bad_output")


def _open_source_nofollow(dirfd, name):
    """Open the single leaf `name` (never a path with "/"; a real entry
    `os.fwalk` reported for the directory pinned by `dirfd`) fd-relative
    with `O_NOFOLLOW` (+ `O_NONBLOCK`, see module docstring), then verify
    -- via `os.fstat` on the resulting fd, never a path-based `os.stat`/
    `os.lstat` -- that it is a genuine regular file with exactly one hard
    link. Because the open is `dir_fd`-relative to an inode `os.fwalk`
    already pinned, no swap of an ancestor NAME can redirect it.

    Returns the open fd on success. Raises `CollectError("path_traversal")`
    for a refused entry type (symlink/socket via a failed open, or a
    device/fifo/directory/hardlink caught by `fstat`), or
    `CollectError("bad_output")` for a content OSError (a regular file
    that could not be opened/fstat'd). The fd is always closed before any
    raise, so no descriptor leaks on a rejection.
    """
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
    except OSError as exc:
        raise _classify_open_failure(dirfd, name) from exc
    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise CollectError("bad_output") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise CollectError("path_traversal")
    return fd


def _open_dir_component(parent_fd, name):
    """Create (if not already present) and open the single path
    component `name` as a directory strictly one level beneath
    `parent_fd` in results_dir, refusing to follow a symlink already
    sitting at that name.

    `name` never contains "/": callers descend one component at a time
    (see the module docstring's "Scope note" for why no `..`/absolute
    confinement is needed here, unlike `causb.extract`).
    `os.mkdir(..., dir_fd=parent_fd)` is itself safe for a single
    component with no confinement flags of its own: it either creates a
    new directory entry or fails `FileExistsError` (an earlier sibling
    file's descent, within this same `collect()` call, already created
    it) -- it can never be redirected through an existing symlink at that
    name. The follow-up `O_NOFOLLOW` open is what actually guards against
    that entry turning out to be a symlink.
    """
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd
    )


def _write_dest(root_fd, rel_path, src_f):
    """Stream all bytes from the already-opened, already-verified
    `src_f` into a new file at `rel_path` beneath `root_fd`
    (results_dir's root), descending one directory component at a time
    via `_open_dir_component` -- exactly like `causb.extract._write_member`
    does for the tar-extraction side. Returns `(sha256_hex, byte_count)`.
    """
    *dir_parts, leaf = rel_path.split("/")
    dirfd = root_fd
    opened = False
    try:
        for component in dir_parts:
            next_fd = _open_dir_component(dirfd, component)
            if opened:
                os.close(dirfd)
            dirfd = next_fd
            opened = True

        dest_fd = os.open(
            leaf,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=dirfd,
        )
        hasher = hashlib.sha256()
        total = 0
        with os.fdopen(dest_fd, "wb") as dest_f:
            while True:
                chunk = src_f.read(_READ_CHUNK)
                if not chunk:
                    break
                hasher.update(chunk)
                total += len(chunk)
                dest_f.write(chunk)
        return hasher.hexdigest(), total
    except OSError as exc:
        # A WRITE-side failure must not escape as a raw OSError: on this LED-only
        # box that bypasses the status.json.error enum and surfaces as a bare
        # FAULT with no operator-readable reason. The dominant real case: out_dir
        # and this collect_dir share the ONE 32M tmpfs (alongside job.tar +
        # extract/), so a large-but-legitimate run-script output exhausts it ->
        # ENOSPC here. Fold into the enum like the read side -- ENOSPC/EDQUOT is a
        # capacity abort ("cap_exceeded" -> status "aborted"); any other write
        # error (an O_EXCL collision, a mid-copy source read failure, an I/O
        # error) is "bad_output" -> handler_failed. Fails closed either way:
        # commitlog writes DONE only on a clean return, so a partial copy is
        # never committed or delivered.
        if exc.errno in (errno.ENOSPC, errno.EDQUOT):
            raise CollectError("cap_exceeded") from exc
        raise CollectError("bad_output") from exc
    finally:
        if opened:
            os.close(dirfd)


def collect(out_dir: str, results_dir: str) -> list:
    """Copy every regular file found by fd-pinned-walking `out_dir` (never
    following a symlink, never recursing into a symlinked subdirectory,
    never reconstructing a path string for a read) into `results_dir`,
    preserving each file's relative path, and return
    `[{"path": <relative name>, "sha256": <hex>, "bytes": <int>}, ...]`
    for `status.json.outputs[]` (one entry per collected file).

    Raises `CollectError("path_traversal")` the instant any entry is a
    symlink (file or directory), hardlink, device, socket, or fifo, or is
    nested deeper than `config.CAPS["depth"]`; `CollectError("cap_exceeded")`
    if the output-file count would exceed `config.CAPS["tar_files"]`;
    `CollectError("bad_output")` for a content-triggered OSError (an
    unreadable subdirectory, or a leaf whose open/fstat fails for a
    non-type-refusal reason). The whole call aborts on the first such
    rejection.

    `out_dir` and `results_dir` are both caller-trusted, harness-created
    paths: an `OSError` from either not existing/not being a directory
    propagates raw (a caller/environment bug, not attacker-influenced
    input). Only the CONTENTS `out_dir` ends up holding are untrusted
    (written by the unprivileged `nebula-job`).
    """
    root_fd = os.open(results_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return _collect_into(out_dir, root_fd)
    finally:
        os.close(root_fd)


def _collect_into(out_dir: str, root_fd: int) -> list:
    outputs = []
    file_count = 0
    # os.fwalk yields a real, pinned directory fd per level; leaf reads go
    # through that fd (never a reconstructed path string), which is what
    # makes an intermediate-directory-symlink swap unable to redirect a
    # read. follow_symlinks=False (the default, stated explicitly) means
    # the walk never recurses into a symlinked subdir; _fold_walk_error
    # folds a content descent error into CollectError("bad_output"); a
    # failure to open out_dir ITSELF is raised directly by os.fwalk (not
    # via onerror) and stays a raw OSError -- the one bootstrap case.
    for dirpath, dirnames, filenames, dirfd in os.fwalk(
        out_dir, onerror=_fold_walk_error, follow_symlinks=False
    ):
        rel_dir = os.path.relpath(dirpath, out_dir)
        dir_depth = 0 if rel_dir == os.curdir else len(rel_dir.split(os.sep))
        # A directory nested deeper than the cap is itself a traversal
        # violation; raising here also bounds descent so a pathologically
        # deep tree cannot exhaust file descriptors (os.fwalk holds one fd
        # per level).
        if dir_depth > config.CAPS["depth"]:
            raise CollectError("path_traversal")

        # Reject a symlinked subdirectory loudly (fd-relative lstat), on
        # top of os.fwalk's own guarantee that it never recurses into one.
        for dname in dirnames:
            try:
                dst = os.stat(dname, dir_fd=dirfd, follow_symlinks=False)
            except OSError as exc:
                raise CollectError("bad_output") from exc
            if stat.S_ISLNK(dst.st_mode):
                raise CollectError("path_traversal")

        for name in sorted(filenames):
            file_count += 1
            if file_count > config.CAPS["tar_files"]:
                raise CollectError("cap_exceeded")

            if rel_dir == os.curdir:
                rel_path = name
            else:
                rel_path = f"{rel_dir}{os.sep}{name}"
            rel_path = rel_path.replace(os.sep, "/")
            # File depth is checked BEFORE the file is opened -- fail
            # closed before any I/O, mirroring causb.extract.
            if len(rel_path.split("/")) > config.CAPS["depth"]:
                raise CollectError("path_traversal")

            src_fd = _open_source_nofollow(dirfd, name)
            with os.fdopen(src_fd, "rb") as src_f:
                digest, size = _write_dest(root_fd, rel_path, src_f)

            outputs.append({"path": rel_path, "sha256": digest, "bytes": size})
    return outputs
