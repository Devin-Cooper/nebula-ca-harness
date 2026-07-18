"""Thin, tested wrapper over the `nebula-cert` binary.

Why this module exists: the CA operation handlers built in later tasks
(`ca-bootstrap`, `sign-hosts`, `backup-ca`) all need to shell out to
`nebula-cert` -- to mint a CA, sign a host cert, or inspect a cert's
details. Rather than each handler hand-building its own argv (three
separate places where a typo'd flag, wrong flag order, or missed edge
case could silently produce a malformed or unintended cert), every
caller funnels through this one small module so the exact nebula-cert
invocation for each operation lives in a single, unit-tested place.

Every function shells out via a list-argv only (never `shell=True`),
through an injectable `runner` keyword (defaults to the real
`subprocess.run`, mirroring `causb.mountctl`'s `runner=subprocess.run`
seam) so tests assert on the EXACT argv a call would make without ever
invoking the real `nebula-cert` binary. `nebula-cert` itself is invoked
as a bare command name, never an absolute path -- PATH resolves it (the
box installs it at /usr/local/bin/nebula-cert), matching the rest of
this codebase's tool-invocation style and keeping this module portable
and testable off-box.

Every argv element is checked for an embedded control character (NUL
0x00, C0 0x01-0x1f, or DEL 0x7f) BEFORE any subprocess is spawned -- the
same defense `causb.manifest` applies to payload basenames, extended
here to every nebula-cert argv element, since names/curves/durations/
paths all ultimately flow from caller-controlled or manifest-derived
data upstream. Without this check, a contaminated argument would reach
`subprocess.run` and raise a raw, uncaught `ValueError` ("embedded null
byte"), escaping this module's error contract; raising a clean, explicit
`ValueError` here instead (mirroring `causb.verify._require_absolute`'s
precedent of a plain `ValueError` for a caller/programming-level bad
input, as opposed to an operational failure) fails fast and loud instead
of leaking an unrelated stdlib exception.

Every OPERATIONAL failure (as opposed to the caller/programming bugs
above) collapses to `NebulaError`, whose `.reason` is one of the fixed
enum strings `"nebula_failed"` (the binary ran and exited non-zero, or
its output could not be parsed into the expected shape), `"timeout"`
(the call exceeded its `timeout` budget and was killed), or
`"tool_missing"` (the `nebula-cert` binary itself could not be found on
PATH -- `FileNotFoundError`). Raw stderr is never included in the
exception message -- only the fixed reason -- so a caller that logs or
surfaces a NebulaError can never leak nebula-cert's raw diagnostic text.

`print_json()` note: the real nebula-cert v1.10.3 binary (verified live
against the box) always wraps `print -json`'s output in a JSON array --
`[{...}]` -- even for a single certificate, since a cert file can in
principle bundle more than one certificate. Every cert this harness ever
inspects (a CA cert, a signed host cert) is a single-certificate file,
so `print_json()` unwraps a one-element array down to the bare dict
inside (matching this module's documented `-> dict` return type). A bare
dict (as an older/future nebula-cert version, or a test double, might
supply directly) is returned as-is. Any other shape -- zero elements,
more than one, or not a JSON object/array at all -- is treated as a
failure to parse into the expected shape and raises
`NebulaError("nebula_failed")` rather than handing a caller some
ambiguous, differently-shaped value.
"""

import json
import subprocess

_CONTROL_CHARS = frozenset(chr(c) for c in range(0x20)) | {chr(0x7F)}


class NebulaError(Exception):
    """A nebula-cert invocation failed. `reason` is one of the fixed enum
    strings "nebula_failed" | "timeout" | "tool_missing" -- a wire
    contract the CA operation handlers built in later tasks key off of;
    the strings must not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _check_clean(argv):
    """Reject any argv element containing an embedded control character
    (NUL, C0, or DEL) BEFORE exec. Raises a plain ValueError -- this is a
    caller/programming bug, never a nebula-cert operational failure (it
    never got to run), so it deliberately does NOT raise NebulaError (see
    module docstring)."""
    for arg in argv:
        if any(ch in _CONTROL_CHARS for ch in arg):
            raise ValueError(f"argument contains a control character: {arg!r}")


def _run(argv, runner, timeout):
    """Shared exec+error-mapping path for every public function below:
    validate, invoke `runner` with the standard kwargs, map
    TimeoutExpired/FileNotFoundError/nonzero-exit to NebulaError, and
    return the CompletedProcess on success."""
    _check_clean(argv)
    try:
        result = runner(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise NebulaError("timeout")
    except FileNotFoundError:
        raise NebulaError("tool_missing")
    if result.returncode != 0:
        raise NebulaError("nebula_failed")
    return result


def ca(name, curve, version, duration, out_crt, out_key, *, runner=subprocess.run, timeout=120):
    """Run `nebula-cert ca` to mint a new self-signed CA certificate+key
    pair: `nebula-cert ca -name <name> -curve <curve> -version <version>
    -duration <duration> -out-crt <out_crt> -out-key <out_key>`.

    Raises `NebulaError` on any nonzero exit, timeout, or missing binary.
    Returns None on success (the cert/key are written to
    out_crt/out_key by nebula-cert itself, not read back here).
    """
    argv = [
        "nebula-cert", "ca",
        "-name", name,
        "-curve", curve,
        "-version", version,
        "-duration", duration,
        "-out-crt", out_crt,
        "-out-key", out_key,
    ]
    _run(argv, runner, timeout)


def sign(
    ca_crt, ca_key, in_pub, name, networks, duration, out_crt,
    *, groups=None, out_qr=None, runner=subprocess.run, timeout=120,
):
    """Run `nebula-cert sign` to sign a host certificate against an
    existing CA: `nebula-cert sign -ca-crt <ca_crt> -ca-key <ca_key>
    -in-pub <in_pub> -name <name> -networks <networks> -duration
    <duration> -version 1 -out-crt <out_crt>`, always at cert format
    version 1 (fixed, per this module's documented interface -- not
    caller-configurable).

    Appends `-groups <a,b,...>` (comma-joined) only when `groups` is a
    non-empty list -- omitted entirely for `None` or an empty list.
    Appends `-out-qr <out_qr>` only when `out_qr` is given (not `None`).
    When both are given, `-groups` is appended before `-out-qr`.

    Raises `NebulaError` on any nonzero exit, timeout, or missing binary.
    Returns None on success.
    """
    argv = [
        "nebula-cert", "sign",
        "-ca-crt", ca_crt,
        "-ca-key", ca_key,
        "-in-pub", in_pub,
        "-name", name,
        "-networks", networks,
        "-duration", duration,
        "-version", "1",
        "-out-crt", out_crt,
    ]
    if groups:
        argv += ["-groups", ",".join(groups)]
    if out_qr is not None:
        argv += ["-out-qr", out_qr]
    _run(argv, runner, timeout)


def print_json(cert_path, *, runner=subprocess.run, timeout=30):
    """Run `nebula-cert print -json -path <cert_path>` and return the
    parsed certificate details as a dict (fingerprint, details, ...).

    See the module docstring for why a real nebula-cert's one-element
    JSON array is unwrapped to the bare dict inside. Raises
    `NebulaError("nebula_failed")` if the output isn't valid JSON, or
    isn't exactly one certificate's worth of it, as well as on any
    nonzero exit; `NebulaError("timeout"/"tool_missing")` per the usual
    mapping.
    """
    argv = ["nebula-cert", "print", "-json", "-path", cert_path]
    result = _run(argv, runner, timeout)
    try:
        parsed = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise NebulaError("nebula_failed")
    if isinstance(parsed, list):
        if len(parsed) != 1:
            raise NebulaError("nebula_failed")
        parsed = parsed[0]
    if not isinstance(parsed, dict):
        raise NebulaError("nebula_failed")
    return parsed


def version(*, runner=subprocess.run, timeout=30):
    """Run `nebula-cert -version` and return the parsed version string
    (e.g. "1.10.3", parsed from the real binary's "Version: 1.10.3"
    stdout line).

    Raises `NebulaError` per the usual mapping, including
    `"nebula_failed"` if stdout doesn't contain a parseable version.
    """
    argv = ["nebula-cert", "-version"]
    result = _run(argv, runner, timeout)
    text = (result.stdout or "").strip()
    if ":" in text:
        text = text.split(":", 1)[1].strip()
    if not text:
        raise NebulaError("nebula_failed")
    return text
