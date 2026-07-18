"""Strict manifest parser for the job bundle wire contract (spec S6/S16, D8).

parse() validates a manifest.json byte string against the fixed schema and
the caps in causb.config.CAPS, and enforces the payload[] strict allowlist
symmetrically against the basenames actually present on disk (payload_names):
every listed name must be on disk AND every on-disk file must be listed. It
never uses yaml or eval (OWASP; clarity MIN6) -- json.loads is the only parser.
"""

import json
import uuid

from causb import config


class ManifestError(Exception):
    """A manifest failed strict validation.

    `reason` is one of the fixed S6 error-enum strings: bad_manifest,
    jobs_gt_1, oversize, cap_exceeded, path_traversal. This is a wire
    contract relied on by later tasks (status.json.error) -- the strings
    must not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _is_strict_int(value):
    """True for a JSON integer, rejecting JSON booleans (bool is an int
    subclass in Python, so `True == 1` would otherwise slip past a plain
    `schema_version == 1` check)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_uuid4(value):
    """True if `value` is a canonically-formatted uuid4 string."""
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return parsed.version == 4 and str(parsed) == value.lower()


def parse(raw: bytes, payload_names: set) -> dict:
    """Validate `raw` manifest.json bytes against the S6 wire contract.

    `payload_names` is the set of basenames actually extracted into
    payload/ on disk; the manifest's single job's `payload` list and this
    set must match exactly (each listed name is on disk, and no on-disk
    file is left unlisted).

    Returns the parsed manifest dict on success -- schema_version==1,
    with exactly one job at jobs[0]. Raises ManifestError(reason) with
    reason drawn from the fixed error enum otherwise.
    """
    if len(raw) > config.CAPS["manifest_bytes"]:
        raise ManifestError("oversize")

    try:
        manifest = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        # RecursionError is a RuntimeError, not a ValueError, so it is NOT
        # covered by the JSONDecodeError/ValueError arm. json.loads recurses
        # once per nesting level, so a deeply-nested-but-under-cap bomb
        # (e.g. "[" * 32000 + "]" * 32000) would otherwise blow the stack
        # and escape as an uncaught RecursionError -- fail closed instead.
        raise ManifestError("bad_manifest")

    if not isinstance(manifest, dict):
        raise ManifestError("bad_manifest")

    schema_version = manifest.get("schema_version")
    if not _is_strict_int(schema_version) or schema_version != 1:
        raise ManifestError("bad_manifest")

    if not isinstance(manifest.get("box"), str):
        raise ManifestError("bad_manifest")

    seq = manifest.get("seq")
    if not _is_strict_int(seq) or seq < 0:
        raise ManifestError("bad_manifest")

    jobs = manifest.get("jobs")
    if not isinstance(jobs, list):
        # A wrong-typed (or missing) jobs field is a schema violation like
        # any other field -> bad_manifest. jobs_gt_1 is reserved for an
        # actual list whose length isn't the cap.
        raise ManifestError("bad_manifest")
    if len(jobs) != config.CAPS["jobs"]:
        raise ManifestError("jobs_gt_1")

    job = jobs[0]
    if not isinstance(job, dict):
        raise ManifestError("bad_manifest")

    if not _is_uuid4(job.get("job_id")):
        raise ManifestError("bad_manifest")

    operation = job.get("operation")
    if not isinstance(operation, str):
        raise ManifestError("bad_manifest")

    payload = job.get("payload")
    if not isinstance(payload, list):
        raise ManifestError("bad_manifest")

    if len(payload) > config.CAPS["payload_files"]:
        raise ManifestError("cap_exceeded")

    for name in payload:
        if not isinstance(name, str):
            raise ManifestError("bad_manifest")
        if (
            "/" in name
            or name in (".", "..")
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name)
        ):
            # Reject "/", "."/"..", AND any control character (NUL, C0
            # 0x00-0x1f, DEL 0x7f). Without the control-char clause an
            # embedded-NUL name (e.g. "a\x00b") passes every other check
            # here, then -- once causb.dispatch joins it into a path and
            # hands it to Popen/os.path.isfile -- raises a RAW, uncaught
            # ValueError('embedded null byte'), escaping this module's
            # fixed error-enum contract downstream. A legitimate payload
            # basename never contains a control byte, so refusing the whole
            # class as path_traversal (same reason "/" is) costs nothing.
            raise ManifestError("path_traversal")
        if name not in payload_names:
            # A well-formed basename the manifest itself lists, but no
            # such file was actually extracted from payload/: the
            # manifest's claim doesn't match reality -- malformed
            # content, not a resource cap.
            raise ManifestError("bad_manifest")

    # S6 strict allowlist is symmetric: "any unlisted file in payload/ ->
    # reject the bundle." Since jobs==1, the single job's payload[] must
    # account for EVERY file actually extracted into payload/. A file present
    # on disk but absent from payload[] rejects the whole bundle.
    if set(payload_names) - set(payload):
        raise ManifestError("bad_manifest")

    if operation == "run-script":
        entrypoint = job.get("entrypoint")
        if not isinstance(entrypoint, str) or entrypoint not in payload:
            raise ManifestError("bad_manifest")

    return manifest
