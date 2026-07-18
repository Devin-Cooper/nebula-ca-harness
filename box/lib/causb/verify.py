"""ssh-keygen -Y verify + break-glass co-sign (spec S7.4, R6, D20, clarity B1).

verify() is the box's trust-anchor check: it authenticates a job.tar against
the box-local allowed_signers file using ssh-keygen's native SSHSIG
mechanism (Ed25519, namespace nebula-ca-job) -- never a hand-rolled crypto
check. verify_cosign() layers the D20 break-glass co-signature requirement
on top, additionally enforcing the R6 distinct-key rule.

**R6 distinct-key rule, implemented as key-set disjointness.** R6 requires
`allowed_signers ∩ breakglass_signers = ∅`. verify_cosign() enforces this by
comparing the *entire set* of key blobs in allowed_signers against the entire
set in breakglass_signers -- NOT by looking up a single key by principal name.
The by-name approach was CVE-class unsound: `ssh-keygen -Y verify -I
<principal>` accepts a signature from ANY key line listed under that
principal, so with a multi-line operator principal (the realistic D19 FIDO2
migration shape: old + new key both under `nebula-ca-operator`), an attacker
whose one key is a *non-first* line of allowed_signers AND the key in
breakglass_signers could sign both the primary job and the "break-glass"
co-signature himself; a first-line-by-name comparison would see a different
(decoy) key and wrongly accept. Set disjointness is immune: the primary sig
(verified by the caller against allowed_signers) is from some key in the
allowed set; the break-glass sig (verified here against breakglass_signers)
is from some key in the breakglass set; if those two sets do not intersect,
the two signing keys are provably distinct regardless of how many lines any
principal spans.

Both functions shell out to the real `ssh-keygen` binary via subprocess with
argv lists (never shell=True, never a merged/concatenated anchor file --
R6). Anchor files are always read by absolute, box-local path, never from
the (untrusted) USB stick, and this module never chdir()s (S7.4: "never
chdir into the mount"). Every failure mode -- a non-matching/ambiguous
principal, a bad signature, an intersecting key set, a missing/unreadable
anchor file, a subprocess error or timeout -- collapses to the fixed error
enum (VerifyError "verify_failed" | "cosign_failed"), never raw stderr; the
contract is fail-closed on ANY failure.
"""

import os
import subprocess

from causb import config

# Hard ceiling on any single ssh-keygen invocation (fail-closed: a hung or
# wedged verify must not stall the harness indefinitely -- a timeout is just
# another failure that maps to the error enum).
_SSH_KEYGEN_TIMEOUT_S = 30

# Known SSH public-key type tokens, used ONLY to locate the (keytype,
# base64) columns of an allowed-signers line for the disjointness check
# (never for authentication -- that is always ssh-keygen's job). Scanning for
# the keytype token (rather than blindly taking the 2nd field) correctly
# parses a line even if an optional sshd(8)-style `options` field
# (cert-authority, namespaces=..., valid-after=...) precedes the key, which
# this project's own tooling never emits but a hand-edited anchor file could.
# Includes the sk-* FIDO2 types because D19's whole migration path adds an
# sk-ssh-ed25519 key under the operator principal -- exactly the multi-line
# shape the disjointness rule must handle.
_KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)


class VerifyError(Exception):
    """A signature failed verification. `reason` is one of the fixed enum
    strings "verify_failed" | "cosign_failed" (status.json.error, S19 R10a)
    -- this is a wire contract relied on by later tasks; the strings must
    not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _require_absolute(path: str) -> None:
    """Defensive guard for the S7.4/S18 "absolute anchor path" requirement:
    allowed_signers/breakglass_signers must always be referenced by
    absolute, box-local path so their meaning can never shift with the
    process's current working directory (this module also never chdir()s).
    A relative anchor path is a caller/config bug, not a signature failure,
    so this raises ValueError rather than VerifyError.
    """
    if not os.path.isabs(path):
        raise ValueError(f"anchor path must be absolute: {path!r}")


def _find_principal(sig_path: str, anchor_path: str):
    """Run `ssh-keygen -Y find-principals -s sig_path -f anchor_path` and
    return the single matched principal name, or None unless ssh-keygen
    exited 0 AND printed exactly one non-blank output line (0 lines = no
    matching key in this anchor file; >1 = ambiguous; non-zero exit = any
    other failure) -- all rejected by the caller (S7.4: "require exactly
    one line"; fail-closed: a non-zero exit is never treated as success).

    Run against exactly one anchor file per call -- R6 requires
    find-principals to be run per file, never against a merged/
    concatenated allowed-signers set, so callers must never pre-concatenate
    allowed_signers+breakglass_signers before calling this.
    """
    result = subprocess.run(
        ["ssh-keygen", "-Y", "find-principals", "-s", sig_path, "-f", anchor_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=_SSH_KEYGEN_TIMEOUT_S,
    )
    if result.returncode != 0:
        return None
    lines = [line for line in result.stdout.decode().splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    return lines[0].strip()


def _verify_bytes(tar_path: str, sig_path: str, anchor_path: str, principal: str) -> bool:
    """Run `ssh-keygen -Y verify` for one (signature, anchor, principal)
    triple with tar_path's bytes fed on stdin (never re-read from the
    stick -- callers pass the already-copied tmpfs/tempdir path). Namespace
    is always causb.config.NS ("nebula-ca-job"). Returns True iff
    ssh-keygen exits zero (its documented success signal).
    """
    with open(tar_path, "rb") as f:
        tar_bytes = f.read()
    result = subprocess.run(
        [
            "ssh-keygen", "-Y", "verify",
            "-f", anchor_path,
            "-I", principal,
            "-n", config.NS,
            "-s", sig_path,
        ],
        input=tar_bytes,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=_SSH_KEYGEN_TIMEOUT_S,
    )
    return result.returncode == 0


def _verify_against_anchor(tar_path: str, sig_path: str, anchor_path: str) -> str:
    """Shared body of verify() and verify_breakglass_primary(): authenticate
    `tar_path`'s bytes against `sig_path` using the box-local `anchor_path`
    (S7.4). Exact flow: find-principals against `anchor_path` requiring exactly
    one match, then `-Y verify` that principal's signature over the tar bytes
    in the fixed nebula-ca-job namespace, exit code checked.

    Returns the matched principal on success. Raises VerifyError("verify_failed")
    on ANY failure: no/ambiguous principal, a verify step that doesn't return
    success (tampered bytes, untrusted signing key, wrong namespace, ...), or an
    infrastructure error (missing/unreadable sig or anchor file, subprocess
    failure or timeout, non-UTF-8 ssh-keygen output). status.json.error is an
    enum, never raw stderr.

    The ONLY thing that differs between the operator-primary check (verify) and
    the break-glass-alone recovery check (verify_breakglass_primary) is WHICH
    box-local anchor authenticates the signature -- so factoring the body here
    makes "same flow, same rigor" a structural guarantee, not a copy that could
    drift. Both public wrappers below are behavior-identical to this; neither
    weakens the other (R6 disjointness of the two anchors means a key that
    authenticates against one never authenticates against the other)."""
    _require_absolute(anchor_path)

    try:
        principal = _find_principal(sig_path, anchor_path)
        if principal is None:
            raise VerifyError("verify_failed")
        if not _verify_bytes(tar_path, sig_path, anchor_path, principal):
            raise VerifyError("verify_failed")
        return principal
    except (FileNotFoundError, OSError, UnicodeDecodeError, subprocess.SubprocessError):
        # Any infrastructure failure -> fail closed with the fixed enum.
        # VerifyError itself is unrelated to these types and propagates
        # unchanged (it carries its own already-correct reason).
        raise VerifyError("verify_failed")


def verify(tar_path: str, sig_path: str, allowed_path: str) -> str:
    """Authenticate `tar_path` against `sig_path` using the box-local
    `allowed_path` (S7.4). Exact flow: find-principals against allowed_path
    requiring exactly one match, then -Y verify that principal's signature
    over the tar bytes in the fixed nebula-ca-job namespace.

    Returns the matched principal (e.g. "nebula-ca-operator") on success.
    Raises VerifyError("verify_failed") on ANY failure: no/ambiguous
    principal, a verify step that doesn't return success (tampered bytes,
    untrusted signing key, wrong namespace, ...), or an infrastructure
    error (missing/unreadable sig or anchor file, subprocess failure or
    timeout, non-UTF-8 ssh-keygen output). status.json.error is an enum,
    never raw stderr.
    """
    return _verify_against_anchor(tar_path, sig_path, allowed_path)


def verify_breakglass_primary(tar_path: str, sig_path: str, breakglass_path: str) -> str:
    """Authenticate `tar_path`/`sig_path` against the box-local BREAK-GLASS
    anchor `breakglass_path`, with the SAME flow and rigor as verify() (S7.4):
    find-principals requiring exactly one match, then `-Y verify -n
    nebula-ca-job` with the tar bytes on stdin, exit code checked. Returns the
    matched break-glass principal on success; raises VerifyError("verify_failed")
    on ANY failure (this shares verify()'s body verbatim via
    _verify_against_anchor -- it is verify() pointed at a different anchor).

    **The break-glass-ALONE recovery/lockout authenticator (R6/D20/§7A/F-a).**
    When the operator has LOST their PRIMARY key entirely, they cannot produce
    an operator (allowed_signers) signature -- so they sign the job.tar with a
    BREAK-GLASS key into the PRIMARY signature slot (job.tar.sig, the same file
    verify() checks; NOT the co-sign job.tar.bg.sig). This function checks that
    same primary-slot signature against breakglass_signers instead of
    allowed_signers.

    This is NOT a widening of who may command the CA: ca-usb-run calls it ONLY
    as a fallback AFTER verify() (the operator-anchor check) has failed, and a
    break-glass-alone authorization is honored ONLY for a job whose parsed
    operation is exactly `rotate-job-signers` (the recovery path that installs
    a fresh primary) -- every other operation is refused verify_failed by the
    orchestrator. R6 disjointness (allowed_signers ∩ breakglass_signers = ∅,
    enforced in verify_cosign / the rotate handler) guarantees a break-glass key
    never authenticates against allowed_signers and an operator key never
    authenticates here, so this cannot silently authorize an ordinary job."""
    return _verify_against_anchor(tar_path, sig_path, breakglass_path)


def _key_blobs(anchor_path: str) -> set:
    """Return the set of (keytype, base64_key) tuples for every key-bearing
    line in the allowed-signers-format file at `anchor_path`.

    Skips blank lines and '#' comments. For each remaining line, locates
    the first token that is a known SSH key type (`_KEY_TYPES`) and pairs
    it with the immediately following token (the base64 key) -- so a line
    is parsed correctly whether or not an optional sshd(8) `options` field
    precedes the key. This is deliberately NOT a general-purpose
    allowed-signers authenticator: it is used only to compute set
    disjointness for the R6 distinct-key rule, never to decide whether a
    signature is valid (that is always delegated to ssh-keygen -Y verify).
    """
    blobs = set()
    with open(anchor_path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            for i, token in enumerate(fields):
                if token in _KEY_TYPES and i + 1 < len(fields):
                    blobs.add((token, fields[i + 1]))
                    break
    return blobs


def verify_cosign(
    tar_path: str,
    bg_sig_path: str,
    breakglass_path: str,
    allowed_path: str,
) -> None:
    """Enforce the D20/R6 break-glass co-signature requirement.

    Two independent checks, both of which must pass:

    (a) The break-glass signature `bg_sig_path` verifies against the
        box-local, immutable `breakglass_path` using the SAME flow as
        verify() -- find-principals (exactly one match) then `-Y verify -n
        nebula-ca-job` with the tar bytes on stdin, exit code checked. This
        anchor file is processed independently of allowed_signers (R6:
        find-principals per file, never a merged set).

    (b) The R6 distinct-key invariant, as key-set disjointness: the set of
        key blobs in `allowed_path` and the set in `breakglass_path` MUST
        NOT intersect. Because the primary signature (verified by the
        caller against allowed_signers) is from a key in the allowed set,
        and the break-glass signature is from a key in the breakglass set,
        disjoint sets prove the two signing keys are distinct -- immune to
        the multi-line-principal self-cosign bypass that a by-name key
        lookup allowed (see module docstring). As a fail-closed guard, an
        empty parse of either anchor file (which would make the
        intersection vacuously empty and wrongly accept) is itself rejected.

    Raises VerifyError("cosign_failed") on ANY failure of either check, or
    on any infrastructure error (missing/unreadable anchor or sig file,
    subprocess failure or timeout, non-UTF-8 output). Returns None on
    success.
    """
    _require_absolute(breakglass_path)
    _require_absolute(allowed_path)

    try:
        bg_principal = _find_principal(bg_sig_path, breakglass_path)
        if bg_principal is None:
            raise VerifyError("cosign_failed")
        if not _verify_bytes(tar_path, bg_sig_path, breakglass_path, bg_principal):
            raise VerifyError("cosign_failed")

        allowed_keys = _key_blobs(allowed_path)
        breakglass_keys = _key_blobs(breakglass_path)
        # Fail closed: an empty key set means we could not parse a file we
        # must reason about (ssh-keygen just verified a key exists in the
        # breakglass file, and the caller verified one exists in the
        # allowed file), so we cannot prove disjointness -> reject.
        if not allowed_keys or not breakglass_keys:
            raise VerifyError("cosign_failed")
        if allowed_keys & breakglass_keys:
            raise VerifyError("cosign_failed")
    except (FileNotFoundError, OSError, UnicodeDecodeError, subprocess.SubprocessError):
        raise VerifyError("cosign_failed")
