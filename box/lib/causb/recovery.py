"""Public-only recovery-kit writer (design S7A, D15, R8).

After air-gap the box has no network, serial, or monitor -- its ONLY I/O is a
USB stick. When an operator inserts a BLANK stick (`inbox/job.tar` absent,
S7A trigger), the harness offers to write a "recovery kit": the public docs +
the redistributable Mac tooling (`caj`/`caj-recv`) + the box's PUBLIC trust
material, so a cold operator (or a fresh agent) who lost their transfer stick
can rebuild everything and resume commanding the CA. `write()` is that
writer; the orchestrator (`box/bin/ca-usb-run`) owns the LED/K1 choreography and calls it.

`write(mp, confirm2, ...)` is PURE filesystem logic -- no LED, no button, no
await. Given the already-mounted-rw stick path `mp` and the boolean
`confirm2` (whether the operator gave the DISTINCT second K1 confirmation,
resolved from the button presses by the orchestrator), it writes `<mp>/CA-RECOVERY/`.
That makes it fully unit-testable without hardware.

THE ONE CRITICAL SECURITY INVARIANT (R8, and where the last review criticals
lived): `write()` MUST NEVER copy `ca.key` -- or ANY private key -- onto the
stick. `ca_dir` (`config.CA_DIR`) holds `ca.key` (root:root 0400) right next
to `ca.crt`. So CA artifacts are copied INDIVIDUALLY, BY EXACT FILENAME, from
a STRICT ALLOWLIST of exactly {`ca.crt`, `registry.json`} -- never a
`copytree(ca_dir, ...)`, never a glob/sweep of `ca_dir`, never a
"copy-everything-but-ca.key" denylist. `registry.json` (mesh topology, R8's
"sensitive") is copied ONLY when `confirm2` is True. `ca.crt` (the public CA
cert) is copied only if the box is bootstrapped. `OFFLINE-SECRETS-MAP.md` is
PAPER-ONLY and is never written here; the README merely points to it.

Robustness (the stick is untrusted input and this runs as root): the
pinned-vfat mount structurally cannot hold symlinks, but as defense
in depth `write()` refuses a `<mp>/CA-RECOVERY` that already exists as
anything other than a plain directory (`unsafe_dest`), never follows a
symlink when writing (copies open the source `O_NOFOLLOW`), makes the write
idempotent (a re-run replaces stale kit contents cleanly), and fails closed
with a `RecoveryError(reason)` on any OSError rather than leaking a traceback.
The trusted staged `src` is the only place code is read from -- never the
stick.
"""

import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess

from causb import config, freshness

# Where install.sh stages the TRUSTED recovery source tree (the analogue of
# the causb pkg / handlers staging): `caj`, `caj-recv`, `causb/{__init__,
# config,manifest}.py`, and the `recovery-kit/` templates. `write()` copies
# FROM here, never from the (untrusted) stick.
RECOVERY_SRC = "/usr/local/share/ca-usb/recovery"

# The public trust anchors live one directory up from config.ALLOWED
# (/etc/nebula-ca); derived from config so this can never drift from what
# install.sh provisions (install.sh computes ETC_DIR the same way).
ANCHORS_DIR = os.path.dirname(config.ALLOWED)

# The kit's top-level directory on the stick.
KIT_DIRNAME = "CA-RECOVERY"

# Templates authored under the repo's recovery-kit/ and staged by install.sh.
TEMPLATES = (
    "README-OPERATOR.md",
    "README-AGENT.md",
    "RECOVERY-CEREMONY.md",
    "setup-new-stick.sh",
)

# Redistributable Mac-side tooling.
TOOLS = ("caj", "caj-recv")

# The ONLY causb modules caj/caj-recv import (caj: config + manifest;
# caj-recv: config). Shipping exactly this closure keeps the kit self-contained
# enough to run `caj` on a second machine without leaking box-only modules.
CAUSB_MODULES = ("__init__.py", "config.py", "manifest.py")

# The public anchor files, copied BY EXACT NAME from ANCHORS_DIR.
_ANCHOR_FILES = ("allowed_signers", "breakglass_signers")

# THE STRICT CA-DIR ALLOWLIST. Only these two names are ever read out of
# ca_dir, each by exact filename. ca.key (and anything else in ca_dir) is
# categorically excluded. Do NOT turn this into a glob or a copytree.
_CA_CRT = "ca.crt"
_CA_REGISTRY = "registry.json"


class RecoveryError(Exception):
    """Writing the recovery kit failed. `reason` is one of a small fixed enum
    (same machine-readable `.reason` convention as MountError/LedError/
    ManifestError/DispatchError):

      "unsafe_dest"  -- <mp>/CA-RECOVERY already exists as something other
                        than a plain directory (a file, a symlink, a device):
                        refuse to follow or clobber it.
      "src_missing"  -- a REQUIRED file in the trusted staged `src` tree is
                        absent (an install/staging bug): fail before touching
                        the stick.
      "write_failed" -- any OSError while preparing the destination or
                        copying/writing a kit file.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _read_seq(state_dir):
    """Read `{state_dir}/seq` (default 0 if absent -- a box that has never
    committed a job has no seq history yet). Duplicates the tiny read in
    `causb.freshness._last_seq()` / `causb.commitlog._read_seq()`,
    parameterized on `state_dir` for the test seam.

    Fail-safe to 0 on ANY read/parse problem: unlike freshness/commitlog
    (which catch only FileNotFoundError because a malformed seq there is a
    caller bug), this runs inside write() whose whole contract is "never leak
    a raw traceback -- always a RecoveryError(reason) or a clean result." An
    EMPTY or non-integer seq file (ValueError) or an unreadable one (OSError)
    must therefore degrade to 0, not escape as a raw exception without a
    `.reason`."""
    try:
        with open(os.path.join(state_dir, "seq")) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def _is_regular(path):
    """True iff `path` is a regular file, WITHOUT following a symlink (lstat).
    A symlink, directory, device, or absent path is not "present" for our
    purposes -- so a hostile/broken `ca.crt -> ca.key` symlink in ca_dir is
    simply treated as absent and skipped, never followed."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def _require_src(src):
    """Validate the trusted staged source tree BEFORE touching the stick.
    Raises RecoveryError("src_missing") if any required tool/module/template
    is missing (an install bug), so a broken staging never yields a
    half-written kit."""
    required = [os.path.join(src, t) for t in TOOLS]
    required += [os.path.join(src, "causb", m) for m in CAUSB_MODULES]
    required += [os.path.join(src, "recovery-kit", t) for t in TEMPLATES]
    for p in required:
        if not _is_regular(p):
            raise RecoveryError("src_missing")


def _prepare_dest(mp):
    """Return `<mp>/CA-RECOVERY`, freshly (re)created as an empty directory.

    If an entry already exists there and is NOT a plain directory (a file, a
    symlink, ...), fail closed with "unsafe_dest" rather than following or
    clobbering it. If it is a real directory, remove it wholesale first so a
    re-run leaves NO stale kit contents (idempotent). rmtree unlinks symlink
    ENTRIES rather than following them."""
    dest = os.path.join(mp, KIT_DIRNAME)
    if os.path.islink(dest):
        raise RecoveryError("unsafe_dest")
    if os.path.exists(dest):
        if not os.path.isdir(dest):
            raise RecoveryError("unsafe_dest")
        try:
            shutil.rmtree(dest)
        except OSError as exc:
            raise RecoveryError("write_failed") from exc
    try:
        os.makedirs(dest)
    except OSError as exc:
        raise RecoveryError("write_failed") from exc
    return dest


def _copy_nofollow(src_path, dst_path):
    """Copy a REGULAR file `src_path` -> `dst_path` without following a
    symlink at the source (O_NOFOLLOW): a symlinked source raises OSError
    (ELOOP), surfaced upstream as "write_failed", so no source symlink is ever
    dereferenced. Preserves the source's permission bits best-effort (a vfat
    stick ignores Unix modes anyway; the README tells operators to `chmod +x`
    the tooling after copying it off)."""
    fd = os.open(src_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fsrc:
        st = os.fstat(fsrc.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise RecoveryError("write_failed")
        with open(dst_path, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)
    try:
        os.chmod(dst_path, stat.S_IMODE(st.st_mode))
    except OSError:
        pass


# Upstream release pages recorded in TOOL-VERSIONS.md so an operator can
# re-fetch the matching build (§7A: "versions + SHA256 + URLs so the box is
# rebuildable").
_NEBULA_RELEASES_URL = "https://github.com/slackhq/nebula/releases"
_AGE_RELEASES_URL = "https://github.com/FiloSottile/age/releases"

# The rebuild-critical binaries: (name, version-flag, releases URL). All on
# the box PATH today; a missing one degrades to "not installed", never crashes.
_VERSIONED_TOOLS = (
    ("nebula-cert", "-version", _NEBULA_RELEASES_URL),
    ("nebula", "-version", _NEBULA_RELEASES_URL),
    ("age", "--version", _AGE_RELEASES_URL),
    ("age-keygen", "--version", _AGE_RELEASES_URL),
)


def _run_capture(argv, run):
    """Run `argv` (a LIST -- never shell=True) capturing combined output,
    bounded by a 10s timeout. Returns the CompletedProcess, or None if the
    binary can't be executed / times out -- never raises."""
    try:
        return run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _first_line(data):
    if isinstance(data, (bytes, bytearray)):
        text = data.decode(errors="replace")
    else:
        text = data or ""
    text = text.strip()
    return text.splitlines()[0].strip() if text else ""


def _sha256_file(path):
    """SHA-256 hex of `path`'s bytes, or None if it can't be read. This is what
    makes a rebuilt box verifiable against the exact on-box build (§7A)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _nebula_cert_version(*, path=None, run=subprocess.run):
    """The version string `nebula-cert -version` reports (e.g. "1.10.3"), or
    None if the binary is missing/unreachable or its output doesn't match the
    expected "Version: <x>" shape. `path` overrides PATH lookup (test seam)."""
    resolved = shutil.which("nebula-cert", path=path)
    if resolved is None:
        return None
    result = _run_capture([resolved, "-version"], run)
    if result is None or not result.stdout:
        return None
    m = re.search(r"Version:\s*(\S+)", result.stdout.decode(errors="replace"))
    return m.group(1) if m else None


def _ca_fingerprint(ca_crt, *, path=None, run=subprocess.run):
    """The CA cert's fingerprint via `nebula-cert print -json -path <ca_crt>`
    (which emits a JSON ARRAY of certs; `fingerprint` is a top-level field on
    each). Returns the fingerprint string, or None on ANY failure (binary
    missing, non-zero exit, unparseable output) -- always degrades, never
    crashes write()."""
    resolved = shutil.which("nebula-cert", path=path)
    if resolved is None:
        return None
    result = _run_capture([resolved, "print", "-json", "-path", ca_crt], run)
    if result is None or result.returncode != 0 or not result.stdout:
        return None
    try:
        data = json.loads(result.stdout.decode(errors="replace"))
        if isinstance(data, list) and data:
            fp = data[0].get("fingerprint")
        elif isinstance(data, dict):
            fp = data.get("fingerprint")
        else:
            fp = None
    except (ValueError, TypeError, AttributeError):
        return None
    return fp if isinstance(fp, str) and fp else None


def _build_box_info(state_dir, ca_dir, bootstrapped, *, run=subprocess.run, path=None):
    """The §5 box-info.json dict, filled to the authoritative shape where
    derivable on the box TODAY, degrading gracefully otherwise:

      box, seq, bootstrapped         -- always.
      nebula_cert_version            -- parsed from nebula-cert, or None.
      curve                          -- "25519" (the design's pinned CA curve).
      schema_versions                -- from config.SCHEMA_VERSIONS (no drift).
      rtc_ok                         -- freshness.clock_sane(current year).
      ca_fingerprint                 -- populated from ca.crt when bootstrapped
                                        (None on parse failure); None otherwise.
      overlay_cidr                   -- None (no config source yet).
      pending_bootstrap              -- the fields still null because the box
                                        isn't bootstrapped / has no source yet.

    The box has a real RTC, so a datetime stamp (`generated_at`) is fine here.
    """
    ca_crt = os.path.join(ca_dir, _CA_CRT)
    fingerprint = _ca_fingerprint(ca_crt, path=path, run=run) if bootstrapped else None
    # overlay_cidr has no source on the box yet, so it is always pending;
    # ca_fingerprint is pending only until the CA is bootstrapped.
    pending = ["overlay_cidr"] if bootstrapped else ["ca_fingerprint", "overlay_cidr"]
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "box": config.BOX_NAME,
        "seq": _read_seq(state_dir),
        "bootstrapped": bootstrapped,
        "nebula_cert_version": _nebula_cert_version(path=path, run=run),
        "curve": "25519",
        "schema_versions": dict(config.SCHEMA_VERSIONS),
        "rtc_ok": bool(freshness.clock_sane(now.year)),
        "ca_fingerprint": fingerprint,
        "overlay_cidr": None,
        "pending_bootstrap": pending,
        "generated_at": now.isoformat(),
    }


def _write_box_info(dst_path, state_dir, ca_dir, bootstrapped, *, run=subprocess.run, path=None):
    info = _build_box_info(state_dir, ca_dir, bootstrapped, run=run, path=path)
    with open(dst_path, "w") as f:
        json.dump(info, f, indent=2, sort_keys=True)
        f.write("\n")


def _write_tool_versions(dst_path, *, path=None, run=subprocess.run):
    """Record, for each rebuild-critical binary on the box PATH: its version
    string, the SHA-256 of the ACTUAL on-box binary (so a rebuild is
    verifiable, §7A), and the upstream releases URL. A missing tool is
    recorded as "not installed" -- never a crash. `path` overrides PATH lookup
    (test seam)."""
    lines = [
        "# Tool versions (match these when rebuilding the box)",
        "",
        "For each binary: the version this box runs, the SHA-256 of the actual",
        "on-box binary (so a rebuilt box can be verified against this exact",
        "build), and the upstream releases page to re-fetch the matching arm64",
        "build from.",
        "",
    ]
    for name, version_arg, url in _VERSIONED_TOOLS:
        lines.append(f"## {name}")
        resolved = shutil.which(name, path=path)
        if resolved is None:
            lines.append("- not installed")
        else:
            result = _run_capture([resolved, version_arg], run)
            version = _first_line(result.stdout) if result is not None else ""
            lines.append(f"- version: `{version or 'unknown'}`")
            lines.append(f"- sha256: `{_sha256_file(resolved) or 'unknown'}`")
            lines.append(f"- path: `{resolved}`")
        lines.append(f"- releases: {url}")
        lines.append("")
    lines.append(f"- python3: `{platform.python_version()}`")
    lines.append("")
    with open(dst_path, "w") as f:
        f.write("\n".join(lines))


def _assemble_kit(dest, confirm2, src, anchors_dir, ca_dir, state_dir):
    """Populate `dest` (an empty CA-RECOVERY dir). All OSErrors here bubble to
    write()'s wrapper, which maps them to RecoveryError("write_failed")."""
    # 1. Templates (public docs + setup-new-stick.sh) from the staged src.
    for name in TEMPLATES:
        _copy_nofollow(os.path.join(src, "recovery-kit", name),
                       os.path.join(dest, name))

    # 2. Redistributable tooling + its causb import closure, from the TRUSTED
    #    staged src (never the stick).
    for name in TOOLS:
        _copy_nofollow(os.path.join(src, name), os.path.join(dest, name))
    causb_dst = os.path.join(dest, "causb")
    os.makedirs(causb_dst)
    for name in CAUSB_MODULES:
        _copy_nofollow(os.path.join(src, "causb", name),
                       os.path.join(causb_dst, name))

    # 3. Public trust anchors, by exact name (public keys -- safe). Copied
    #    only if actually present, so a half-provisioned box still emits
    #    whatever public material it has rather than failing the whole write.
    for name in _ANCHOR_FILES:
        anchor = os.path.join(anchors_dir, name)
        if _is_regular(anchor):
            _copy_nofollow(anchor, os.path.join(dest, name))

    # 4. CA artifacts -- STRICT ALLOWLIST, exact filenames only. ca.key (and
    #    anything else in ca_dir) is categorically excluded: we NEVER sweep
    #    ca_dir. ca.crt iff bootstrapped; registry.json iff confirm2 AND
    #    present (R8: mesh topology needs the distinct second confirmation).
    ca_crt = os.path.join(ca_dir, _CA_CRT)
    bootstrapped = _is_regular(ca_crt)
    if bootstrapped:
        _copy_nofollow(ca_crt, os.path.join(dest, _CA_CRT))
    # `confirm2 is True` -- a STRICT bool identity check, not mere truthiness:
    # this gates disclosure of R8-sensitive mesh topology, so a stray truthy
    # value (1, "false", a non-empty list) from a future caller must NOT open
    # the gate (the same truthiness-bypass bug class caught elsewhere in this
    # codebase). The orchestrator's contract is that confirm2 is a real bool.
    if confirm2 is True:
        registry = os.path.join(ca_dir, _CA_REGISTRY)
        if _is_regular(registry):
            _copy_nofollow(registry, os.path.join(dest, _CA_REGISTRY))

    # 5. Generated metadata.
    _write_box_info(os.path.join(dest, "box-info.json"), state_dir, ca_dir, bootstrapped)
    _write_tool_versions(os.path.join(dest, "TOOL-VERSIONS.md"))


def write(mp, confirm2, *, src=RECOVERY_SRC, state_dir=config.STATE_DIR,
          anchors_dir=ANCHORS_DIR, ca_dir=config.CA_DIR):
    """Write the public-only recovery kit under `<mp>/CA-RECOVERY/` (S7A/R8).

    `mp`        -- path to the ALREADY-mounted-rw stick (the orchestrator mounts it).
    `confirm2`  -- did the operator give the DISTINCT second K1 confirmation?
                   Gates inclusion of the sensitive `registry.json` (R8).
                   MUST be a real `bool` (the orchestrator's contract): only the literal
                   `True` opens the gate -- any other value (including a truthy
                   `1`/`"yes"`) is treated as "no", fail-safe toward secrecy.
    `src`       -- trusted staged source tree (RECOVERY_SRC); templates +
                   caj/caj-recv + causb closure are copied FROM here.
    `state_dir`/`anchors_dir`/`ca_dir` -- injectable box paths (test seams).

    Returns None on success. Raises RecoveryError(reason) -- never a raw
    traceback -- on a hostile destination ("unsafe_dest"), a broken staged
    source ("src_missing"), or any OSError during the write ("write_failed").
    """
    # Validate the trusted source BEFORE touching the stick, so a bad install
    # never leaves a half-written kit on the medium.
    _require_src(src)

    # Prepare (or refuse) the destination. Raises unsafe_dest / write_failed.
    dest = _prepare_dest(mp)

    try:
        _assemble_kit(dest, confirm2, src, anchors_dir, ca_dir, state_dir)
    except RecoveryError:
        raise
    except OSError as exc:
        raise RecoveryError("write_failed") from exc
