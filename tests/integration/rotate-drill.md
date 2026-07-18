# `rotate-job-signers` (break-glass rotation drill): integration notes

No hardware dependency (no LED/K1/USB stick). This handler's only real-world
surfaces are (a) the box's real `ssh-keygen` (via `causb.verify._key_blobs`
for anchor parsing / disjointness and `causb.verify.verify()` for the
round-trip proof) and (b) the box's atomic-file-install syscalls on the real
Debian 13 / py3.13 filesystem. This drill exercises the **co-signed
rotation** end-to-end against those real surfaces, in a throwaway `/tmp`
workdir — **never** the real `/etc/nebula-ca` or `/var/lib/nebula-ca` (which
do not even exist on this pre-air-gap box yet).

`rotate-job-signers` is the harness's most security-sensitive handler: it
rewrites the two trust anchors that decide **who may command the CA**
(`allowed_signers`, operational) and **who may co-authorize a break-glass
change** (`breakglass_signers`). The properties this drill proves on real
hardware, beyond the unit suite:

1. A **co-signed** simultaneous rotation of BOTH the operator (primary) key
   and the break-glass key is applied, at the correct modes (`0644`/`0444`).
2. The freshly-installed operator anchor genuinely **authenticates the new
   key** — a real `ssh-keygen -Y verify` (through `causb.verify.verify()`)
   accepts a job signed by the new primary and **rejects** one signed by the
   now-retired old primary.
3. A break-glass change **without** a co-signature is refused
   (`cosign_required`, exit 3) with the on-disk anchors **byte-unchanged** and
   no receipt emitted.
4. The co-sign gate is the strict `cosigned is True` — a truthy non-bool
   (`cosigned="True"`, a string) is **refused**, not accepted.

## What was run

Non-root, over SSH, on `<operator>@<box>` (no passwordless sudo
available — itself a useful proof point: nothing below needed root). The
handler under test and a driver were streamed into a
`mktemp -d /tmp/rotate-integration.XXXXXX` workdir and run with
`PYTHONPATH=/opt/nebula-ca/src/box/lib` (the box's deployed `causb`), then the
workdir was `rm -rf`'d. The real `/etc/nebula-ca` was never referenced —
`allowed_path`/`breakglass_path` were explicit tmpdir paths passed to
`run()`'s injectable keyword arguments throughout.

The driver does, using the
box's real `ssh-keygen` for every keypair and signature:

```text
# Fresh ephemeral ed25519 keys: op1, op2 (operator); bg1, bg2 (break-glass).
# Initial installed anchors: allowed_signers={op1} 0644, breakglass_signers={bg1} 0444.

Drill A — co-signed simultaneous rotation:
  payload/allowed_signers   = {op2}      (rotate the operator key)
  payload/breakglass_signers = {bg2}     (rotate the break-glass key)
  run(job, payload, out, allowed_path=..., breakglass_path=..., cosigned=True)
    -> assert EXIT_OK; installed allowed=={op2}, breakglass=={bg2}; modes 0644/0444
    -> sign a job.tar with the NEW op2 key; verify.verify(...) MUST return "nebula-ca-operator"
    -> sign a job.tar with the OLD op1 key; verify.verify(...) MUST raise VerifyError

Drill B — break-glass change WITHOUT co-sign is refused, anchors untouched:
  reset anchors to {op1}/{bg1}; payload allowed={op1}, breakglass={bg2}
  run(..., cosigned=False)
    -> assert EXIT_COSIGN_REQUIRED (3); allowed & breakglass BYTE-UNCHANGED; no receipt

Drill C — strict co-sign gate: a truthy non-bool is NOT a co-signature:
  payload allowed={op1}, breakglass={bg2}
  run(..., cosigned="True")   # the STRING "True", not the bool
    -> assert EXIT_COSIGN_REQUIRED (3)
```

## Real output (verbatim, this run — box py3.13.5, real ssh-keygen)

```
verify has _key_blobs: True
python: 3.13.5
A: cosigned=True simultaneous rotate rc = 0 (expect 0 )
A: allowed mode 0o644 breakglass mode 0o444
A: receipt {   "allowed_changed": true,   "allowed_principals": 1,   "breakglass_changed": true,   "breakglass_principals": 1,   "cosigned": true,   "job_id": "drill-13.2" }
A: NEW primary (op2) verify() -> nebula-ca-operator (expect nebula-ca-operator)
A: OLD primary (op1) correctly REJECTED after rotation
B: cosigned=False break-glass change rc = 3 (expect 3 )
B: anchors BYTE-UNCHANGED, no receipt on refusal
C: cosigned='True' (string) rc = 3 (expect 3 )
ALL-INTEGRATION-CHECKS-PASSED
CLEANED-UP=YES
```

Every assertion in the driver would have raised `AssertionError` (aborting
before `ALL-INTEGRATION-CHECKS-PASSED`) had any property not held; it printed,
so all held. The `verify.verify()` line is the load-bearing one: it is the box's
REAL `ssh-keygen -Y find-principals`/`-Y verify` accepting a signature from the
just-installed `op2` anchor and rejecting the retired `op1` — i.e. the rotation
genuinely changed *who the CA trusts*, not just the file bytes. Modes
`0644`/`0444` were set by a genuinely non-root session (the best-effort `chown
root:root` step silently no-ops here — see the handler docstring — since it
ran without root; the explicit `chmod` modes are the real gate and are
proven above). The workdir was removed and independently confirmed absent
(`CLEANED-UP=YES`); no `/tmp/rotate-integration.*` dir and no driver process
was left behind.

## Operator runbook (the co-signed path this handler implements)

On the operator's Mac, to rotate the primary signing key (e.g. a FIDO2/YubiKey
upgrade) and/or the break-glass set:

1. Prepare the COMPLETE proposed new anchor file(s):
   - `allowed_signers` (required) — the full new operational signer set.
   - `breakglass_signers` (optional) — include ONLY if changing break-glass;
     omit to leave break-glass untouched.
2. Build a `rotate-job-signers` job whose `payload[]` carries those file(s),
   and **sign the job.tar with the current PRIMARY key** (`caj`).
3. If the job touches `breakglass_signers`, **also co-sign the same job.tar
   with a current BREAK-GLASS key**. The orchestrator
   computes `cosigned=True` only when that break-glass co-signature verifies
   against `breakglass_signers` AND is from a key disjoint from
   `allowed_signers` (enforced in `causb.verify.verify_cosign`).
4. Carry the signed job to the box on the USB stick; the harness verifies,
   extracts, and dispatches it. `dispatch` sets `CA_USB_COSIGNED=1` iff the
   co-signature verified, which this handler reads.
5. Confirm from the returned `out/rotate-receipt.json`
   (`allowed_changed`/`breakglass_changed`/`allowed_principals`/…), then
   verify a subsequent ordinary job signed by the NEW primary is accepted.

Rollback / lockout safety net baked into the handler: `allowed_signers` can
never be emptied (`would_lockout`), the two sets can never overlap (`overlap`,
checked against the union of the old and new break-glass so even a partial
write is disjoint), and a break-glass change without a co-signature changes
nothing (`cosign_required`).

## Scope / what this does NOT cover

- **The pure break-glass-ALONE lockout-recovery path** is **now implemented**
  — see the "Addendum: break-glass-ALONE lockout recovery" section below for
  the bg-ALONE drill. The **co-signed**
  variant (primary + break-glass → `cosigned=True`), proven above, is unchanged.

- **Root ownership (`chown root:root`).** Without passwordless
  sudo available, the best-effort `os.chown` step no-ops (by design). The explicit
  `chmod` modes (`0644`/`0444`) are the real access gate and are proven; root
  ownership is deferred to the operator's real air-gap finalization, alongside
  every other root-owned-file expectation this project defers the same way
  (e.g. `/etc/nebula-ca`'s `0750 root:root`).

- **The real `/etc/nebula-ca` anchors.** Never touched — this box is
  pre-air-gap and `/etc/nebula-ca` does not exist yet. The real
  rotation is an operator-run, on-box action; this drill only proves the
  handler's logic against the box's real `ssh-keygen`/filesystem in a
  throwaway tree.

- **`caj`/`caj-recv` USB delivery.** Out of scope — the existing
  `causb.collect`/`commitlog`/`mac/caj-recv` pipeline owns
  moving `out_dir`'s receipt back to the operator's Mac.

## Addendum: `caj --breakglass` implements the runbook's step 3

The "Operator runbook" step 3 above ("also co-sign the same job.tar with a
current BREAK-GLASS key") was, when this drill ran, still a manual/future
step — `caj` had no dedicated flag for it yet. This addendum closes that gap:
`caj build --spec … --stick … --breakglass <breakglass_key_path>` now
produces that second detached signature itself, as `inbox/job.tar.bg.sig`,
via the same `ssh-keygen -Y sign -n nebula-ca-job` invocation the primary
signature uses (just a different key), alongside the ordinary `job.tar` +
`job.tar.sig`. Delivery order is `job.tar` → `job.tar.bg.sig` → `job.tar.sig`
(primary always LAST — the box's completeness signal — so an interrupted
delivery still fails closed exactly as the no-breakglass case does). Without
`--breakglass`, `caj` is entirely unchanged: no `job.tar.bg.sig` is produced,
and a job that actually needed a co-signature correctly hits the box's
`cosign_required` gate. This is Mac-side tooling only (unit-tested against a
throwaway ed25519 keypair in `tests/unit/test_caj.py`, no hardware/box
dependency) — it supplies the wire-format artifact this drill's Drill A
already proves the box accepts; it does not change anything about the
recorded box-side run above.

## Addendum: break-glass-ALONE lockout recovery now works end-to-end

The follow-on the "Scope" section tracked — the operator has LOST their PRIMARY
key entirely and must recover with a **break-glass-ALONE** signature — is now
implemented across the orchestrator/verify layer, scoped razor-tight to the one
recovery operation. The pieces:

- `causb.verify.verify_breakglass_primary(tar, sig, breakglass_path)` —
  `verify()` pointed at the break-glass anchor. It authenticates the SAME
  primary-slot signature (`job.tar.sig`, NOT the co-sign `job.tar.bg.sig`)
  against `breakglass_signers` instead of `allowed_signers`. Same flow/rigor:
  find-principals (exactly one) → `-Y verify -n nebula-ca-job` → exit 0.
- `box/bin/ca-usb-run` — after the normal `verify()` against `allowed_signers`
  FAILS, it tries `verify_breakglass_primary` against `breakglass_signers`. If
  that also fails, no anchor vouches for the bytes → `verify_failed`, nothing
  extracted. If it passes, `bg_authorized=True` is only PROVISIONAL: the job is
  honored ONLY if its parsed `operation` is exactly `rotate-job-signers`; ANY
  other operation → `verify_failed`, nothing runs. Co-sign is never computed for
  a bg-authorized job (`cosigned=False`). Every other gate (box/clock/seq/replay/
  K1/jobs==1) fires identically.
- `causb.dispatch` sets `CA_USB_BG_AUTHORIZED=1` iff `bg_authorized is True`
  (strict, independent of `CA_USB_COSIGNED`).
- `box/handlers/rotate-job-signers` — reads `CA_USB_BG_AUTHORIZED == "1"`. In
  bg-authorized mode it PERMITS an `allowed_signers`-only change (installing the
  fresh primary IS the recovery) but REFUSES any `breakglass_signers` key-set
  change (`bg_cannot_change_breakglass`, checked before the cosign gate).

### Drill D — break-glass-ALONE recovery (design for the on-box run)

No hardware surface beyond `ssh-keygen` + the filesystem, same throwaway-tmpdir
posture as Drills A–C (never the real `/etc/nebula-ca`). Ephemeral keys `op1`,
`op2` (operator) and `bg1` (break-glass); initial anchors `allowed={op1}`,
`breakglass={bg1}`:

```text
D1 — bg-ALONE authorizes an allowed-only rotate (the recovery):
  Build a rotate-job-signers job whose payload/allowed_signers = {op2}, and
  sign job.tar.sig with the BREAK-GLASS key bg1 (the lost-primary shape: the
  break-glass sig is in the PRIMARY slot; there is NO job.tar.bg.sig).
    ca-usb-run: verify(ALLOWED) fails (bg1 ∉ allowed) -> verify_breakglass_primary
      (BREAKGLASS) succeeds (bg1 ∈ breakglass) -> bg_authorized=True; op is
      rotate-job-signers -> dispatched CA_USB_BG_AUTHORIZED=1, cosigned=False.
    handler: allowed-only change -> installs allowed={op2}, breakglass byte-
      unchanged.
    -> a job signed by the NEW primary op2 is now accepted by verify.verify()
       against the freshly installed allowed_signers; a job signed by the
       retired op1 is REJECTED. (This last step is the load-bearing proof — the
       box's trust genuinely moved to the recovered primary. It is exactly the
       assertion tests/unit/test_handler_rotate_job_signers.py::TestBgAuthorized
       .test_installed_new_primary_authenticates_after_bg_recovery pins.)

D2 — the SAME bg-ALONE sig on any OTHER operation is refused:
  Re-sign a sign-hosts / ca-bootstrap / run-script / rotate-ca / backup-ca /
  set-time / status job with bg1 in the primary slot.
    -> ca-usb-run: verify_failed (the break-glass-alone operation gate), NOTHING dispatched,
       no seq consumed. (unit: test_ca_usb_run.py::TestLifecycle
       .test_breakglass_alone_on_non_rotate_operations_is_verify_failed.)

D3 — a bg-ALONE rotate may NOT change break-glass:
  payload/allowed_signers = {op2}, payload/breakglass_signers = {bg2}, bg-alone
  signed.
    -> handler refuses bg_cannot_change_breakglass; BOTH anchors byte-unchanged.
       (unit: TestBgAuthorized.test_breakglass_change_is_refused_...)
```

Execution note: this addendum documents the break-glass-alone design and the
unit coverage that pins each property (`tests/unit/test_verify.py`,
`test_dispatch.py`, `test_handler_rotate_job_signers.py`,
`test_ca_usb_run.py`) — proven test-first. The on-box end-to-end bg-ALONE run
(`./run-tests.sh`, then an operator ssh drill mirroring Drills A–C) is the
operator's pre-air-gap gate to run.
Drills A–C above remain the recorded co-signed proof and are unaffected.
