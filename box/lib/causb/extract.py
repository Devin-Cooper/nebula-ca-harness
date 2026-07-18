"""Hardened tar extraction from a verified job.tar into trusted tmpfs
(spec S7.5, S11, D18, clarity M3).

extract() sits between an attacker-influenced tar (already ssh-sig
verified upstream per S7.4 -- but a signature check does not protect the
layers that run *after* it: `tarfile`'s own parsing, and the filesystem
calls used to materialize its contents, must not be trusted with hostile
member names or types) and a trusted destination directory. Two
independent layers of defense are used together, deliberately redundant:

1. **Pure-Python content policy** (`_safe_name()` + `member.isreg()`):
   only regular-file members are accepted, and only two name shapes --
   the literal "manifest.json" or a path strictly under a single
   top-level "payload/" dir. Every other member (symlink, hardlink,
   device, fifo, directory, an absolute path, a ".." component anywhere,
   or a path deeper than `causb.config.CAPS["depth"]`) is rejected as
   "path_traversal" before a single byte of its data is ever read.
   Running totals (member count, uncompressed bytes) are checked against
   `causb.config.CAPS` ("tar_files"/"tar_bytes") using only each member's
   HEADER-declared `size` -- before that member's data is read at all.
   This ordering is what makes a decompression-bomb member (a header
   that lies about its size, with no archive bytes backing it up) fail
   closed as "cap_exceeded" without ever attempting to read or allocate
   based on the hostile size. `tarfile.open(..., mode="r:")` additionally
   refuses any compressed input outright (no gzip/bz2/xz transport is
   accepted), which forecloses classic compression-ratio decompression
   bombs at the format level, not just via the size-cap check.

2. **Kernel-enforced confinement** (defense in depth *underneath* #1, in
   case #1 has a bug): every byte written to `dest_dir` goes through a
   raw `openat2(2)` syscall (see `_openat2()`) with
   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`, resolved
   relative to a directory fd rooted at `dest_dir`. This makes the
   *kernel itself* refuse to resolve any path outside `dest_dir`, refuse
   to follow a symlink anywhere in the path (including one planted as an
   intermediate directory component), and refuse to cross a mount point
   -- independently of whatever `_safe_name()` already decided.
   `tarfile.TarFile.extract()`/`.extractall()` are NEVER called anywhere
   in this module: both follow member symlinks/hardlinks and write via
   ordinary path-based `open()`, which is exactly the TOCTOU/symlink-
   escape class of bug this module exists to avoid.

`__NR_openat2` (437) is hardcoded rather than looked up via a
`SYS_openat2`/glibc wrapper: openat2 (added in Linux 5.6) has no glibc
wrapper function on any glibc version, and the C header that would
define `SYS_openat2` may not be present at all depending on the
libc/kernel-header combination a given box was built with (S11/F10). 437
is the number both `arm64` and `x86_64` assign it (architectures whose
syscall tables were extended after Linux 4.17 share the "generic"
`asm-generic/unistd.h` numbering for syscalls added from that point on)
-- verified empirically via a raw `syscall(437, ...)` against this
project's actual target kernel (6.1.141, aarch64) before this module was
written, including that `RESOLVE_BENEATH` rejects `..`/absolute paths and
`RESOLVE_NO_SYMLINKS` rejects a symlink both as a final component and as
an intermediate directory component. If the syscall is unavailable or fails for any
reason (`ENOSYS` on an unexpectedly old kernel, or any other errno),
`_openat2()` raises a plain `OSError` -- there is no fallback branch to
an unconfined `os.open()` anywhere in this module, so a broken/missing
`openat2` fails the whole extraction closed rather than silently
downgrading to an unsafe path-based write.

**Scope note on error classification:** the public contract is that
`extract()` raises `ExtractError(reason)` on ANY rejection of a member or
the tar -- it must NOT let a raw `OSError` escape for attacker-influenced
input, because on this LED-only headless box an uncaught `OSError` leaves
the error-reporting path undefined. Accordingly, an `OSError` from the
write path -- the `openat2`/`mkdirat` calls that materialize an
already-accepted member (`_write_member`/`_ensure_dir_beneath`) -- is
folded into the enum as `bad_tar`. The realistic trigger is a hostile tar
whose member SHAPES conflict with each other within one extraction:
"payload/subdir" as a plain file followed by "payload/subdir/evil" (its
"subdir" component is now a file, `ENOTDIR`), or the reverse collision
("payload/subdir/evil" creating a directory, then "payload/subdir" as a
file over it, `EISDIR`). The confinement still holds in every such case
(`openat2` refuses the operation; nothing is written outside `dest_dir`)
-- folding to `bad_tar` is purely about honoring the enum contract, not
about safety. The SOLE intentionally-raw `OSError` is the initial
`dest_dir` bootstrap open in `extract()`: `dest_dir` is a trusted,
box-controlled path the caller is responsible for creating (unlike a tar
member's name, it is not attacker-influenced), so a bad `dest_dir`
(missing, not a directory, unreadable) is a caller/environment bug and
propagates plainly -- exactly like `causb.verify._require_absolute`
treats a bad anchor path as a caller bug rather than folding it into
`VerifyError`. (A consequence of folding the write path to `bad_tar` is
that a genuinely environmental write failure -- e.g. `ENOSPC` -- is also
reported as `bad_tar`; on a 32 MB tmpfs bounded by the 8 MB `tar_bytes`
cap this is effectively unreachable, and the enum-contract guarantee is
worth that theoretical imprecision.)
"""

import ctypes
import os
import tarfile

from causb import config

__NR_openat2 = 437  # see module docstring; hardcoded, no SYS_openat2 relied on.

_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08

# The exact confinement S11/F10 specifies: refuse to leave dest_dir
# (RESOLVE_BENEATH, which also rejects absolute pathnames), refuse to
# follow a symlink anywhere in the path including as an intermediate
# component (RESOLVE_NO_SYMLINKS), refuse to cross into a different
# mounted filesystem (RESOLVE_NO_XDEV).
_CONFINE = _RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_XDEV

_MANIFEST_NAME = "manifest.json"
_PAYLOAD_PREFIX = "payload/"


class ExtractError(Exception):
    """A tar member (or the tar itself) failed extraction policy.

    `reason` is one of the fixed S19 R10a error-enum strings this module
    is responsible for: "path_traversal" (a member's name or type is not
    an allowed regular file under manifest.json/payload/), "cap_exceeded"
    (too many members, or too many uncompressed bytes -- including a
    single member whose header-declared size alone exceeds the cap), or
    "bad_tar" (the archive itself could not be opened or parsed). This is
    a wire contract relied on by later tasks (status.json.error) -- the
    strings must not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class _OpenHow(ctypes.Structure):
    """Mirrors the kernel's `struct open_how` (openat2(2)): three `u64`
    fields, `flags`/`mode`/`resolve`, 24 bytes total with no padding --
    the exact ABI shape `openat2` expects for its 3rd argument (a
    pointer to this struct) and 4th argument (`sizeof` this struct)."""

    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


_libc = ctypes.CDLL(None, use_errno=True)
# Explicit argtypes/restype -- rather than relying on ctypes' default
# guessing for an unprototyped variadic call -- so every argument is
# marshalled at its correct width. This matters most for the syscall
# number and the trailing size_t: glibc's `syscall(long, ...)` reads its
# first argument as a full 64-bit long, and leaving argtypes unset is a
# well-known source of silent register-garbage corruption on 64-bit
# platforms for exactly this kind of raw syscall call.
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [
    ctypes.c_long,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
]


def _openat2(dirfd: int, pathname: str, flags: int, mode: int) -> int:
    """Raw `openat2(dirfd, pathname, &how, sizeof(how))` via
    `syscall(437, ...)`; `how.resolve` is always the fixed `_CONFINE`
    mask (RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV).

    `pathname` must be a single path component resolved directly beneath
    `dirfd` -- callers always descend one component at a time (see
    `_ensure_dir_beneath`/`_write_member`) so that `_CONFINE` is a
    kernel-enforced guarantee at every single step, not just at the end.

    Returns the new fd on success. Raises `OSError(errno)` on ANY
    failure -- there is no fallback to plain `os.open()` anywhere in
    this module; if openat2 is unsupported on this kernel (`ENOSYS`) or
    refuses the path for any other reason, the caller sees a real
    exception, never a silent unsafe open.
    """
    how = _OpenHow(flags=flags, mode=mode, resolve=_CONFINE)
    ret = _libc.syscall(
        __NR_openat2,
        dirfd,
        os.fsencode(pathname),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), pathname)
    return ret


def _safe_name(name: str) -> bool:
    """True iff `name` is a tar member path this module is willing to
    extract at all: not absolute, no ".." path component and no empty
    path component anywhere, no deeper than `causb.config.CAPS["depth"]`
    path components, and either exactly "manifest.json" or strictly under
    a single top-level "payload/" dir (S7.5/S11). Every other shape --
    including a bare "payload" with nothing under it -- is rejected.

    The ".." and "" checks are **per path component** (on `name.split("/")`),
    NOT substring scans. A substring `".." in name` test wrongly rejects a
    perfectly benign filename like "payload/notes..v2.txt" (where ".." is
    part of a single component, not a parent-dir reference); splitting on
    "/" and rejecting only a component that *is* exactly ".." fixes that
    while still rejecting a real "payload/../x" traversal. The empty-
    component arm rejects a bare/empty name, a trailing slash
    ("payload/x/" -> [..., ""]) and a doubled slash ("payload//x" ->
    [..., "", ...]) -- shapes that are malformed member *names* (correctly
    a path_traversal rejection) rather than being allowed to reach the
    write path and surface there as a raw filesystem OSError (ENOENT).

    This checks only the *name*; member TYPE (regular file vs.
    symlink/device/etc.) is checked separately by the caller via
    `member.isreg()`.
    """
    if os.path.isabs(name):
        return False
    parts = name.split("/")
    if len(parts) > config.CAPS["depth"]:
        return False
    if any(part in ("", "..") for part in parts):
        return False
    if name == _MANIFEST_NAME:
        return True
    # A bare "payload" (no slash) fails startswith; "payload/" alone is
    # already rejected above by its empty trailing component -- so this
    # accepts exactly a non-empty path strictly under "payload/".
    return name.startswith(_PAYLOAD_PREFIX)


def _ensure_dir_beneath(dirfd: int, component: str) -> int:
    """Create (if needed) and open the single path component `component`
    as a directory strictly beneath `dirfd`, returning a new dirfd.

    `component` must never contain "/" -- callers descend one path
    component at a time so that every step, both the `mkdir` and the
    follow-up `openat2`, is confined to exactly one level beneath a
    directory this module already trusts (either `dest_dir`'s own root
    fd, or a directory this same function opened this same way one
    level up). `os.mkdir(..., dir_fd=...)` (mkdirat) is itself safe for
    a single component with no confinement flags of its own: it either
    creates a new directory entry or fails `FileExistsError` -- it can
    never be redirected through an existing symlink at that name the way
    a path-based multi-component `mkdir -p` could be. The follow-up
    `openat2` (with `RESOLVE_NO_SYMLINKS`) is what then guards against
    that existing entry turning out to be something other than a real,
    directly-reachable directory (a symlink, or -- for a hostile tar
    that lists e.g. both "payload/x" as a file and "payload/x/y" as a
    path through it -- a plain file): it fails closed with an `OSError`
    (`ENOTDIR` for the file case), which `_extract_into` catches at the
    `_write_member` call site and folds into `ExtractError("bad_tar")`
    (see the module docstring's scope note) so no raw `OSError` escapes.
    """
    try:
        os.mkdir(component, 0o700, dir_fd=dirfd)
    except FileExistsError:
        pass  # created by a previous sibling member; the open below still
        # verifies it is actually a plain, symlink-free directory.
    return _openat2(dirfd, component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, 0)


def _write_member(root_fd: int, name: str, data: bytes) -> None:
    """Write `data` as the tar member named `name` (already validated by
    `_safe_name`/`isreg()`) into the directory tree rooted at `root_fd`,
    descending one path component at a time so every step -- each
    intermediate directory and the final file -- is opened via
    `_openat2()`'s kernel-enforced confinement, never a plain path-based
    `open()`.
    """
    *dir_parts, leaf = name.split("/")
    dirfd = root_fd
    opened = False
    try:
        for component in dir_parts:
            next_fd = _ensure_dir_beneath(dirfd, component)
            if opened:
                os.close(dirfd)
            dirfd = next_fd
            opened = True

        fd = _openat2(
            dirfd, leaf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    finally:
        if opened:
            os.close(dirfd)


def extract(tar_path: str, dest_dir: str) -> None:
    """Extract `tar_path` (an already-verified-elsewhere job.tar; see
    `causb.verify`/S7.4) into `dest_dir`, enforcing the S7.5/S11
    hardening described in this module's docstring.

    Raises `ExtractError(reason)`, `reason` one of "path_traversal",
    "cap_exceeded", "bad_tar" (see `ExtractError`'s docstring for exactly
    what each covers). `dest_dir` is assumed trusted and already
    present; an OSError from a bad `dest_dir`, or from an operational
    failure while writing an already-accepted member, propagates raw
    rather than being folded into the enum (see the module docstring's
    scope note). Returns None on success.
    """
    root_fd = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _extract_into(tar_path, root_fd)
    finally:
        os.close(root_fd)


def _extract_into(tar_path: str, root_fd: int) -> None:
    try:
        tar = tarfile.open(tar_path, mode="r:")  # "r:" == uncompressed only;
        # a gzip/bz2/xz payload fails to parse here rather than being
        # transparently decompressed, foreclosing classic compression-
        # ratio decompression bombs at the format level.
    except (tarfile.TarError, OSError):
        raise ExtractError("bad_tar")

    try:
        running_files = 0
        running_bytes = 0
        while True:
            try:
                member = tar.next()
            except tarfile.TarError:
                raise ExtractError("bad_tar")
            if member is None:
                break

            running_files += 1
            if running_files > config.CAPS["tar_files"]:
                raise ExtractError("cap_exceeded")

            # Header-declared size only, checked BEFORE any data is read
            # -- this is what makes a decompression-bomb member (a size
            # the actual archive bytes don't back up) fail closed here
            # rather than during an attempted read/allocation. A negative
            # size (reachable via a hand-crafted GNU base-256 header
            # field) is rejected outright rather than let it silently
            # reduce the running total below what earlier members added.
            if member.size < 0:
                raise ExtractError("bad_tar")
            running_bytes += member.size
            if running_bytes > config.CAPS["tar_bytes"]:
                raise ExtractError("cap_exceeded")

            if not _safe_name(member.name):
                raise ExtractError("path_traversal")
            if not member.isreg():
                raise ExtractError("path_traversal")

            try:
                data = tar.extractfile(member).read()
            except (tarfile.TarError, OSError):
                raise ExtractError("bad_tar")

            try:
                _write_member(root_fd, member.name, data)
            except OSError as exc:
                # The write path (openat2 for each intermediate directory
                # component + the final file, plus the mkdirat in
                # _ensure_dir_beneath) can fail with a raw OSError for a
                # member whose SHAPE conflicts with filesystem state an
                # earlier sibling member already created within THIS same
                # extraction -- e.g. a member "payload/subdir/evil" whose
                # "subdir" component is a plain file another member wrote
                # first (ENOTDIR), or a member "payload/subdir" that is a
                # regular file colliding with a directory an earlier
                # "payload/subdir/evil" created (EISDIR). Those are
                # malformed-*bundle* conditions, not environment bugs, so
                # they are folded into the enum as bad_tar rather than
                # allowed to escape as a raw OSError -- on this LED-only
                # headless box, an uncaught OSError leaves the error-
                # reporting path undefined; the contract is ExtractError on
                # every rejection. The confinement itself still held
                # (openat2 refused the operation; nothing was written
                # outside dest_dir). The ONE intentionally-raw OSError is
                # dest_dir's own bootstrap open in extract() -- the sole
                # genuinely environment-scoped (not attacker-influenced)
                # path.
                raise ExtractError("bad_tar") from exc
    finally:
        tar.close()
