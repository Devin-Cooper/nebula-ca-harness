"""Shared append-only forensic audit writer (design §4/§11).

**Why this module exists.** §4 mandates a per-job append-only `audit.log`
(`{STATE_DIR}/audit.log`, `0600` root): "job_id, op, signer principal, result,
timestamps; run-script logs script sha256+bytes". Two call sites write to it,
with DELIBERATELY DIFFERENT field sets:

  - `causb.dispatch._audit_privileged_run` -- the run-script IDENTITY record
    (`sha256`+`bytes` of a privileged script), written **fail-CLOSED** before
    the exec (an audit-write failure aborts the privileged run).
  - `box/bin/ca-usb-run` -- the per-job TERMINAL record (`job_id`/`operation`/
    signer `principal`/`status`/`seq`/`replayed`/`exit_code`/`cosigned`),
    written **fail-SAFE** at each lifecycle terminal (a lost audit line must
    never break the terminal/LED/unmount path).

What this module pins is the ONE thing both must share so their lines can never
drift: the SERIALIZATION (canonical `json.dumps(sort_keys=True)` + newline) and
the append-and-fsync MECHANISM (`O_APPEND|O_CREAT` `0600`, `os.write`,
`os.fsync`). The two field sets are §4's own distinction (the per-job line vs
run-script's extra sha256+bytes), not drift.

`append()` deliberately does NOT swallow errors -- each caller chooses its own
posture (dispatch lets it raise to fail closed; ca-usb-run wraps it to fail
safe). Box-only: never staged onto a redistributed recovery stick (install.sh
copies only `__init__`/`config`/`manifest` there).
"""

import json
import os

from causb import config


def _default_writer(path, line):
    """Append `line` (bytes) to `path`, creating it `0600` on first write,
    fsync'd. `O_APPEND` makes the write atomic w.r.t. concurrent appenders and
    is what makes the log append-ONLY in practice; `os.fsync` makes the line
    durable so a crash right after an audited event still leaves its record."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def append(entry, *, path=None, writer=None):
    """Append `entry` (a JSON-serializable dict) to the audit log as ONE
    canonical JSONL line (sorted keys, newline-terminated), fsync'd.

    `path` defaults to `config.AUDIT_LOG` (resolved at call time, so a test
    pointing `config.AUDIT_LOG` at a tmpdir takes effect); `writer` is a DI
    seam -- a callable taking the encoded `bytes` -- defaulting to the real
    `O_APPEND|O_CREAT 0600` + `os.write` + `os.fsync`. Raises whatever the
    writer raises (never swallows): the caller decides fail-closed vs
    fail-safe.
    """
    line = (json.dumps(entry, sort_keys=True) + "\n").encode()
    if writer is not None:
        writer(line)
        return
    effective_path = config.AUDIT_LOG if path is None else path
    _default_writer(effective_path, line)
