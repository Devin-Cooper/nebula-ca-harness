# Recovery-kit writer: integration notes

`causb.recovery.write(mp, confirm2, ...)` is **pure filesystem logic** — no
LED, no K1 button, no real block device. Every property the spec asks of the
WRITER itself (the strict `{ca.crt, registry.json}` allowlist that keeps
`ca.key` off the stick; the `confirm2` gate on `registry.json`; the paper-only
`OFFLINE-SECRETS-MAP`; `box-info.json`'s `seq`/`bootstrapped`; idempotent
rewrites; fail-closed `unsafe_dest`/`src_missing`/`write_failed`) is fully
exercised by **`tests/unit/test_recovery.py`** (17 cases) and does not need a
human, a stick, or a finger.

Two things were additionally proven **on the box** (Debian 13, python3.13.5,
`nebula-cert 1.10.3`, `age v1.3.1`), end-to-end, with no mocking:

1. **`ca.key` never leaves the box.** A real `ca.key` (0400) planted right
   beside `ca.crt` in a fake `ca_dir`; after `write(..., confirm2=True)`, the
   kit contained `ca.crt` + `registry.json` but **no file named `ca.key` and
   none of its bytes** — the strict allowlist holds against the exact on-box
   layout, not just a synthetic one.
2. **The kit is self-contained on a second machine.** From the freshly
   written `CA-RECOVERY/` alone, `python3 caj --help` and `python3 caj-recv
   --help` both import their `causb/` closure and exit 0 — i.e. the flat
   `caj` + `causb/` sibling layout resolves via Python's own script-directory
   `sys.path` entry, so a cold operator really can run `caj` from the kit.

## Genuinely deferred to the operator (physical / clean-room)

These need a real blank stick, the real `user_led`, a real finger on K1, and
a **second** machine — no loopback image or synthetic device can stand in.
They also depend on the orchestrator (`box/bin/ca-usb-run`), which owns the
LED **RECOVERY-OFFER / WRITE** choreography and resolves the K1 press(es)
into the `confirm2` boolean this module consumes. **Not run now.** Record
date/operator/result inline as each is performed.

### A. Single-K1 recovery (default, public-only)

- [ ] Insert a **blank/unlabeled vfat** stick (no `inbox/job.tar`) → the box
      takes the recovery branch and the LED shows the **RECOVERY-OFFER**
      pattern, distinct from READY.
- [ ] A **single** K1 press within the confirm window → LED shows
      **RECOVERY-WRITE**; the box writes `<stick>/CA-RECOVERY/`.
- [ ] Pull the stick; on another machine inspect `CA-RECOVERY/`. Confirm it
      contains: `README-OPERATOR.md`, `README-AGENT.md`,
      `RECOVERY-CEREMONY.md`, `setup-new-stick.sh`, `caj`, `caj-recv`,
      `causb/{__init__,config,manifest}.py`, `allowed_signers`,
      `breakglass_signers`, `box-info.json`, `TOOL-VERSIONS.md`, and (iff the
      box is bootstrapped) `ca.crt`.
- [ ] Confirm it does **NOT** contain `registry.json`, does **NOT** contain
      `OFFLINE-SECRETS-MAP.md`, and does **NOT** contain `ca.key` or any
      `*.key` (`find CA-RECOVERY -name '*.key'` is empty).

### B. Clean-room rebuild from the kit alone

- [ ] On a **fresh machine / account with zero prior context**, using ONLY
      the kit: `chmod +x caj caj-recv setup-new-stick.sh`.
- [ ] `sudo ./setup-new-stick.sh /dev/sdX` on a second raw USB stick →
      creates an MSDOS partition table + one vfat partition (`sdX1`) +
      `inbox/`, `outbox/`. Verify a **partition** was created (`lsblk` shows
      `sdX1`), not a superfloppy — otherwise the box's partition-scoped udev
      rule won't fire.
- [ ] Read `box-info.json`; seed `ca-state/last-seq` so the next job's `seq`
      = `box-info.seq + 1` (per `README-AGENT.md`).
- [ ] Build a real job with `caj build --spec … --stick <mnt>` (signed by an
      authorised key), carry it to the box, and drive it to SAFE-TO-REMOVE →
      proves a cold operator can resume commanding the CA from the kit alone.

### C. Distinct double-K1 (registry opt-in)

- [ ] Repeat A, but give the **distinct second** K1 confirmation (long/double
      press or two separate presses, surfaced by a distinct LED).
- [ ] Confirm `CA-RECOVERY/registry.json` **is** now present, and that
      `OFFLINE-SECRETS-MAP.md` and `ca.key` are **still absent**.

### D. Discoverability breadcrumb (out-of-kit)

- [ ] Confirm the "blank stick → K1 → kit" trigger is documented both in the
      project git README and on the **physical card kept with the box**
      (nothing on the box can announce it after total loss).
