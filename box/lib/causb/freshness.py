"""Freshness / replay checks for the job wire contract (spec S7.5, D9, D22, R5, R7).

check() runs the freshness triple against a parsed manifest (the dict shape
causb.manifest.parse() returns): box identity, clock sanity (with the R5
set-time carve-out), seq monotonicity, and job_id idempotency (replay
detection). It is a pure read against causb.config.STATE_DIR/{seq,consumed-jobs}
-- it never writes or mutates state; committing a job (bumping seq, appending
consumed-jobs) is `commitlog.commit()`'s job (R7's atomic DONE-marker commit).
"""

from causb import config


def clock_sane(now_year: int) -> bool:
    """True iff `now_year` is plausible for this box's RTC (S7.5: year>=2026).

    The box has no NTP after air-gap (D9): its RTC is a soft, physically
    trusted clock that can drift or reset to an implausible past date.
    year>=2026 is the floor -- this harness cannot have been built or
    deployed before that year.
    """
    return now_year >= 2026


def is_consumed(job_id: str) -> bool:
    """True if `job_id` is already recorded in {STATE_DIR}/consumed-jobs.

    The file is a newline-separated set of job_ids appended to by
    `commitlog.commit()`; absent means no job has ever been committed on this box.
    """
    try:
        with open(f"{config.STATE_DIR}/consumed-jobs") as f:
            consumed = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return False
    return job_id in consumed


def _last_seq() -> int:
    """Read {STATE_DIR}/seq (default 0 if absent -- a box that has never
    committed a job has no seq history yet)."""
    try:
        with open(f"{config.STATE_DIR}/seq") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0


def check(manifest: dict, now_year: int, op: str) -> str:
    """Run the S7.5 freshness triple (box/clock/seq) plus D22 replay detection.

    `manifest` is assumed to already be causb.manifest.parse()'s validated
    return value (box is a str, seq a non-negative int, jobs[0].job_id a
    uuid4 string) -- check() does no independent schema validation of its own.

    Returns "fresh" (proceed), "replay" (job_id already committed --
    redeliver cached results, do not re-run), or one of the fixed error-enum
    strings (S19 R10a): "wrong_box", "clock_insane", "stale_seq".

    Order is significant and exact:
      1. box mismatch -> "wrong_box"
      2. clock insane, UNLESS op=="set-time" (R5 carve-out) -> "clock_insane"
      3. seq <= last committed seq -> "stale_seq"
      4. job_id already consumed -> "replay"
      5. else -> "fresh"

    Pure checks only -- reads causb.config.STATE_DIR but never writes it;
    committing (bumping seq, recording job_id) is `commitlog.commit()`'s job.
    """
    if manifest["box"] != config.BOX_NAME:
        return "wrong_box"

    if op != "set-time" and not clock_sane(now_year):
        return "clock_insane"

    if manifest["seq"] <= _last_seq():
        return "stale_seq"

    if is_consumed(manifest["jobs"][0]["job_id"]):
        return "replay"

    return "fresh"
