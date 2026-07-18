# `airgap.sh` (Phase D): integration notes + operator checklist

No hardware dependency (no LED/K1/USB stick). `airgap.sh` is the operator-run
**last** step of Phase D: it severs this box from the network so it becomes
the air-gapped Nebula CA. Getting it wrong in either direction is bad:
masking too little leaves the box reachable after "air-gap"; masking the
**wrong thing** (the physical serial rescue console) strands the box
forever, with no network and no USB-shell way back in. This file is
both (a) a box-safe, fake-`PATH` test harness that exercises the real
script's logic without ever touching the box's real `systemctl`/`passwd`/
`timedatectl`, and (b) the operator's actual Phase-D runbook.

**`airgap.sh --confirm` must NEVER be run for real against this box's own
systemd from any automated session** — see "What this does NOT cover"
at the end. Every check below runs the script against fake stub
`systemctl`/`passwd`/`timedatectl` binaries placed first on `PATH` inside a
throwaway `mktemp -d` tree; the real network/NTP/login state of whatever
machine runs this is never touched.

## Why serial-getty@ttyFIQ0 is the one thing this script must never mask

`serial-getty@ttyFIQ0` is the login getty on this NanoPi's physical UART —
the serial console. Per `tests/integration/13-usbguard.md`'s own pre-flight
checklist, this is the box's designated break-glass path: *"a second
terminal on `serial-getty@ttyFIQ0` ... this is the rescue path if a rule
turns out to be wrong"*. Once `airgap.sh --confirm` has run and
USBGuard is enforcing, the serial console is the **only** way to reach this
box if anything about its post-air-gap state is ever wrong — there is no
network, and USBGuard's default posture rejects everything that isn't the
CA-XFER stick. This was **CONFIRMED by the operator (2026-07-12)**: retain
it, permanently. `box/airgap.sh` holds this two ways: the mask list is
defined in exactly one place with a loud comment, and a guard loop aborts
(before touching anything) if a serial-getty console ever appears in the
computed list — belt-and-suspenders against a future edit, not just a
one-time code review. Section 6 of the test below mutates a **copy** of the
script to inject `serial-getty@ttyFIQ0` into that list and proves the abort
actually fires.

## What was run

This box-safe harness was executed against `box/airgap.sh`, from a
throwaway `/tmp` tree, exactly as shown (no `--confirm` against anything
except fake stub binaries):

```bash
#!/bin/bash
# Box-safe, fake-PATH test harness for box/airgap.sh.
# RUN FROM THE REPO ROOT:  bash <(awk '/^```bash$/{f=1;next} /^```$/{f=0} f' tests/integration/airgap.md)
# or extract this fenced block to a file and run it directly. Mirrors
# tests/integration/reconcile_unit_install.sh's pattern: everything happens
# against FAKE systemctl/passwd/timedatectl stub scripts placed FIRST on
# PATH inside a throwaway tmpdir. The REAL systemctl/passwd/timedatectl (and
# thus the real network/NTP/login state of whatever machine runs this) are
# NEVER invoked. airgap.sh --confirm is never run against a real systemd
# from this harness.
set -uo pipefail

REPO_ROOT="$(pwd)"
AIRGAP_SRC="$REPO_ROOT/box/airgap.sh"
[[ -f "$AIRGAP_SRC" ]] || {
    echo "error: $AIRGAP_SRC not found -- run this from the repo root" >&2
    exit 1
}

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "[PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $1"; }

TMPROOT="$(mktemp -d /tmp/causb-airgap-test.XXXXXX)"
FAKEBIN="$TMPROOT/fakebin"
FAKESTATE="$TMPROOT/state"
mkdir -p "$FAKEBIN" "$FAKESTATE"
LOG="$TMPROOT/calls.log"
: > "$LOG"
cleanup() { rm -rf "$TMPROOT"; }
trap cleanup EXIT

# --- fake systemctl: tracks masked units in $FAKESTATE/masked -------------
cat > "$FAKEBIN/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
case "$1" in
    is-enabled)
        unit="$2"
        if grep -qx "$unit" "$FAKE_STATE/masked" 2>/dev/null; then
            echo "masked"
            exit 1
        fi
        echo "enabled"
        exit 0
        ;;
    mask)
        unit="$2"
        echo "$unit" >> "$FAKE_STATE/masked"
        exit 0
        ;;
    *)
        echo "fake systemctl: unhandled args: $*" >&2
        exit 1
        ;;
esac
EOF

# --- fake timedatectl ------------------------------------------------------
cat > "$FAKEBIN/timedatectl" <<'EOF'
#!/bin/sh
echo "timedatectl $*" >> "$FAKE_LOG"
case "$1" in
    show)
        if [ -f "$FAKE_STATE/ntp_off" ]; then
            echo "no"
        else
            echo "yes"
        fi
        exit 0
        ;;
    set-ntp)
        if [ "$2" = "false" ]; then
            : > "$FAKE_STATE/ntp_off"
        fi
        exit 0
        ;;
    *)
        echo "fake timedatectl: unhandled args: $*" >&2
        exit 1
        ;;
esac
EOF

# --- fake passwd ------------------------------------------------------------
cat > "$FAKEBIN/passwd" <<'EOF'
#!/bin/sh
echo "passwd $*" >> "$FAKE_LOG"
case "$1" in
    -S)
        user="$2"
        if [ -f "$FAKE_STATE/pi_locked" ]; then
            echo "$user L 01/01/2026 0 99999 7 -1"
        else
            echo "$user P 01/01/2026 0 99999 7 -1"
        fi
        exit 0
        ;;
    -l)
        : > "$FAKE_STATE/pi_locked"
        exit 0
        ;;
    *)
        echo "fake passwd: unhandled args: $*" >&2
        exit 1
        ;;
esac
EOF

chmod +x "$FAKEBIN/systemctl" "$FAKEBIN/timedatectl" "$FAKEBIN/passwd"

export FAKE_LOG="$LOG"
export FAKE_STATE="$FAKESTATE"
export PATH="$FAKEBIN:$PATH"

run_airgap() {
    : > "$LOG"
    sh "$AIRGAP_SRC" "$@"
}

echo "== [1/6] bash -n syntax check =="
if bash -n "$AIRGAP_SRC" 2>"$TMPROOT/syntax_err"; then
    pass "bash -n clean"
else
    fail "bash -n reported a syntax error:"
    cat "$TMPROOT/syntax_err"
fi

echo
echo "== [2/6] no-args: prints plan, zero calls =="
out_noargs="$(run_airgap)"
rc_noargs=$?
if [[ "$rc_noargs" -eq 0 ]]; then pass "no-args exits 0"; else fail "no-args exited $rc_noargs"; fi
if [[ ! -s "$LOG" ]]; then
    pass "no-args made ZERO systemctl/passwd/timedatectl calls"
else
    fail "no-args made calls it shouldn't have:"; cat "$LOG"
fi
if grep -qi 'serial-getty' <<<"$out_noargs"; then
    fail "no-args output mentions serial-getty (R11 violation)"
else
    pass "no-args output never mentions serial-getty"
fi

echo
echo "== [3/6] --dry-run: identical posture to no-args =="
out_dryrun="$(run_airgap --dry-run)"
rc_dryrun=$?
if [[ "$rc_dryrun" -eq 0 ]]; then pass "--dry-run exits 0"; else fail "--dry-run exited $rc_dryrun"; fi
if [[ ! -s "$LOG" ]]; then
    pass "--dry-run made ZERO systemctl/passwd/timedatectl calls"
else
    fail "--dry-run made calls it shouldn't have:"; cat "$LOG"
fi
if grep -qi 'serial-getty\|ttyFIQ0' <<<"$out_dryrun"; then
    fail "--dry-run output mentions serial-getty/ttyFIQ0 (R11 violation)"
else
    pass "--dry-run output never mentions serial-getty/ttyFIQ0"
fi

echo
echo "== [4/6] --confirm (1st run): masks everything, skips serial-getty =="
rm -f "$FAKESTATE/masked" "$FAKESTATE/ntp_off" "$FAKESTATE/pi_locked"
out_confirm1="$(run_airgap --confirm)"
rc_confirm1=$?
if [[ "$rc_confirm1" -eq 0 ]]; then pass "--confirm (1st) exits 0"; else fail "--confirm (1st) exited $rc_confirm1"; fi

EXPECTED_UNITS="NetworkManager wpa_supplicant systemd-networkd systemd-networkd.socket networking systemd-timesyncd ssh"
all_masked=1
for u in $EXPECTED_UNITS; do
    grep -qx "$u" "$FAKESTATE/masked" 2>/dev/null || { all_masked=0; echo "  missing mask: $u"; }
done
[[ "$all_masked" -eq 1 ]] && pass "all 7 expected units were masked" || fail "not all expected units were masked"

mask_call_count="$(grep -c '^systemctl mask ' "$LOG" || true)"
[[ "$mask_call_count" -eq 7 ]] && pass "exactly 7 systemctl mask calls" || fail "expected 7 systemctl mask calls, got $mask_call_count"

[[ -f "$FAKESTATE/ntp_off" ]] && pass "NTP disabled" || fail "NTP not disabled"
[[ -f "$FAKESTATE/pi_locked" ]] && pass "pi locked" || fail "pi not locked"

if grep -qi 'serial-getty' "$LOG"; then
    fail "a serial-getty call appears in the confirm-run call log (R11 violation!)"
else
    pass "NO call in the confirm-run log mentions serial-getty"
fi

if grep -q 'pull the Ethernet cable' <<<"$out_confirm1"; then
    pass "final instruction to pull the Ethernet cable was printed"
else
    fail "final Ethernet-cable instruction was NOT printed"
fi

echo
echo "== [5/6] --confirm (2nd run): idempotent, zero further mutating calls =="
out_confirm2="$(run_airgap --confirm)"
rc_confirm2=$?
if [[ "$rc_confirm2" -eq 0 ]]; then pass "--confirm (2nd) exits 0"; else fail "--confirm (2nd) exited $rc_confirm2"; fi

mask2_count="$(grep -c '^systemctl mask ' "$LOG" || true)"
[[ "$mask2_count" -eq 0 ]] && pass "2nd confirm run masked NOTHING new (idempotent)" || fail "2nd confirm run issued $mask2_count new mask calls"
setntp2_count="$(grep -c '^timedatectl set-ntp ' "$LOG" || true)"
[[ "$setntp2_count" -eq 0 ]] && pass "2nd confirm run did not re-disable NTP" || fail "2nd confirm run re-invoked set-ntp"
lock2_count="$(grep -c '^passwd -l ' "$LOG" || true)"
[[ "$lock2_count" -eq 0 ]] && pass "2nd confirm run did not re-lock pi" || fail "2nd confirm run re-invoked passwd -l"

echo
echo "== [6/6] defensive abort: serial-getty@ttyFIQ0 injected into the mask list =="
MUTANT="$TMPROOT/airgap_mutant.sh"
sed -E 's/^(MASK_UNITS=".*)"$/\1 serial-getty@ttyFIQ0"/' "$AIRGAP_SRC" > "$MUTANT"
if ! diff -q "$AIRGAP_SRC" "$MUTANT" >/dev/null 2>&1; then
    pass "mutant script actually differs from the original (mutation applied)"
else
    fail "sed did not find/modify a MASK_UNITS= line -- mutation NOT applied, guard untested"
fi
: > "$LOG"
mutant_out="$(sh "$MUTANT" --confirm 2>&1)"
mutant_rc=$?
if [[ "$mutant_rc" -ne 0 ]]; then
    pass "mutant (serial-getty injected) --confirm ABORTS (nonzero exit)"
else
    fail "mutant (serial-getty injected) --confirm did NOT abort -- exit 0!"
fi
if [[ ! -s "$LOG" ]]; then
    pass "mutant run made ZERO systemctl/passwd/timedatectl calls before aborting"
else
    fail "mutant run made calls before aborting:"; cat "$LOG"
fi
# Also prove the guard fires in plan mode, not just --confirm.
mutant_plan_out="$(sh "$MUTANT" 2>&1)"
mutant_plan_rc=$?
[[ "$mutant_plan_rc" -ne 0 ]] && pass "mutant also aborts in plan/no-args mode" || fail "mutant did NOT abort in plan mode"

echo
echo "================================================================"
echo "airgap_test.sh: $PASS passed, $FAIL failed"
echo "================================================================"
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
```

## Real output (verbatim — macOS dev checkout, `sh`=bash-posix and separately re-run under real `dash`; box run pending, see "Execution status")

```
== [1/6] bash -n syntax check ==
[PASS] bash -n clean

== [2/6] no-args: prints plan, zero calls ==
[PASS] no-args exits 0
[PASS] no-args made ZERO systemctl/passwd/timedatectl calls
[PASS] no-args output never mentions serial-getty

== [3/6] --dry-run: identical posture to no-args ==
[PASS] --dry-run exits 0
[PASS] --dry-run made ZERO systemctl/passwd/timedatectl calls
[PASS] --dry-run output never mentions serial-getty/ttyFIQ0

== [4/6] --confirm (1st run): masks everything, skips serial-getty ==
[PASS] --confirm (1st) exits 0
[PASS] all 7 expected units were masked
[PASS] exactly 7 systemctl mask calls
[PASS] NTP disabled
[PASS] pi locked
[PASS] NO call in the confirm-run log mentions serial-getty
[PASS] final instruction to pull the Ethernet cable was printed

== [5/6] --confirm (2nd run): idempotent, zero further mutating calls ==
[PASS] --confirm (2nd) exits 0
[PASS] 2nd confirm run masked NOTHING new (idempotent)
[PASS] 2nd confirm run did not re-disable NTP
[PASS] 2nd confirm run did not re-lock pi

== [6/6] defensive abort: serial-getty@ttyFIQ0 injected into the mask list ==
[PASS] mutant script actually differs from the original (mutation applied)
[PASS] mutant (serial-getty injected) --confirm ABORTS (nonzero exit)
[PASS] mutant run made ZERO systemctl/passwd/timedatectl calls before aborting
[PASS] mutant also aborts in plan/no-args mode

================================================================
airgap_test.sh: 22 passed, 0 failed
================================================================
```

Separately, `box/airgap.sh` was also driven directly under the box's real
interpreter (`/bin/dash`, confirmed present at that path on this dev
machine too) against the same fake-`PATH` stubs — not just macOS's
`/bin/sh` (which is bash-in-POSIX-mode, a materially different
implementation from Debian's real `/bin/dash`) — to confirm no bash-only
construct (`[[`, arrays, `local`, etc.) is hiding in the script: identical
plan/confirm output, identical 7 masks + NTP-disable + pi-lock call
sequence, `rc=0`. `box/airgap.sh` uses only `set -eu`, `case`, POSIX
`for word in $list`, `[ ]`, `$(...)`, and heredocs — no bashism found.

## Execution status

Deploying and re-running this harness against the box's own real
`systemctl`/`passwd`/`timedatectl` is deliberately not done as an
unattended, automatic production-path write (per this project's
established posture — see e.g. `sign-hosts.md`'s identical note).
Everything above was run and verified on the local dev checkout (macOS,
both under its `/bin/sh` and explicitly under real `/bin/dash`) — pure
POSIX-shell logic against fake stub binaries, with no box/systemd
dependency, so this is not a diminished proof the way a
`nebula-cert`-dependent handler's local-only run would be. `./run-tests.sh`
additionally reproduces this exact harness against the real box's
shell/environment as the final gate.

**`airgap.sh --confirm` must never be run against a real
`systemctl`/`passwd`/`timedatectl` outside that gated operator step** —
every invocation above targeted fake stub binaries placed first
on `PATH` inside a throwaway `mktemp -d` tree that is removed (`trap
cleanup EXIT`) at the end of the harness, win or lose.

---

# Operator Phase-D checklist (run this once, physically present, serial console open)

This is the actual runbook for severing the box from the network. Do this
**after** the hard-gate test pass (USBGuard enabled and verified,
real anchors installed, a real `ca-bootstrap` run) and only when the mesh
is genuinely ready to go fully offline.

## Before running `--confirm`

- [ ] **Physical/serial access confirmed available and OPEN** — a second
      terminal on `serial-getty@ttyFIQ0`, logged in, *before* running
      `airgap.sh --confirm` — this is the rescue path if anything about the
      box's post-air-gap state ever turns out wrong (same pre-flight
      discipline `13-usbguard.md` already established for enabling
      USBGuard). Re-confirm this is a serial session, not an SSH session —
      SSH itself is one of the things this script is about to mask.
- [ ] Everything from Phase C (the USBGuard hard-gate) is done: USBGuard
      enabled and verified against the CA-XFER stick, real trust anchors
      installed (not the bring-up/dummy ones), a real `ca-bootstrap` has
      run, and the operator is satisfied the mesh doesn't need further
      network-dependent setup on this box.
- [ ] Run `bash box/airgap.sh` (no flag) or `bash box/airgap.sh --dry-run`
      first and read the printed plan. Confirm the 7 listed units match
      what you expect, and that nothing about a serial console appears
      anywhere in the output (it shouldn't — the script's guard also runs in
      this mode and would abort loudly if it ever did).

## Running it

- [ ] From the serial console session (root): `sudo bash box/airgap.sh --confirm`
      (or run as root directly if already root).
- [ ] Confirm the transcript shows all 7 units masked (or "already masked"
      on a re-run), NTP disabled, `pi` locked, and ends with **"Now
      physically pull the Ethernet cable."**
- [ ] **Physically pull the Ethernet cable now.** This is the actual
      air-gap step; `airgap.sh` only prepares the box's own software
      posture so a re-plugged cable or a future boot can't silently
      re-establish connectivity.
- [ ] From the serial console, confirm `ip addr` (or equivalent) shows no
      reachable route once the cable is pulled, and that the serial
      session itself is unaffected (it's a local UART, not network- or
      SSH-dependent — masking `ssh`/`NetworkManager`/etc. does not touch
      it).
- [ ] Re-run `bash box/airgap.sh --confirm` once more (idempotency check) —
      expect every line to read "already masked"/"already disabled"/
      "already locked", never a fresh action, and the same final
      Ethernet-cable instruction.

## After air-gapping

- [ ] Confirm `sudo systemctl is-enabled serial-getty@ttyFIQ0` still shows
      the console enabled/active — this script never touches it, but
      this is the cheap live confirmation an operator should make a habit
      of, exactly like `13-usbguard.md`'s own pre-flight check.
- [ ] From this point on, all CA operations happen exclusively via the
      signed-job USB workflow (`caj`/the physical stick) — there is no
      other way in, by design.

## What this does NOT cover

- **Physically pulling the Ethernet cable.** `airgap.sh` cannot do this
  itself — it prepares the software posture (masked units, disabled NTP,
  locked login) and prints the instruction; the physical disconnection is
  the operator's own last manual act, deliberately kept as a distinct,
  visible, physical step rather than something a script silently claims to
  have done.
- **Enabling USBGuard.** That is Phase C's own deliberate, separately-gated
  operator step (`tests/integration/13-usbguard.md`) — assumed already done
  by the time `airgap.sh --confirm` is run, not repeated here.
- **`airgap.sh --confirm` against this box's REAL systemd.** Deliberately
  never run automatically — the real, one-time `--confirm` run is a
  physical, serial-console-attended operator action, not something proven
  live in this file; what IS proven live here is every piece of the
  script's *logic* (idempotent masking, the serial-console guard, the
  plan/confirm/dry-run modes) against faithful stand-ins for the real
  commands.
- **`rotate-ca`, mobile onboarding, and other deferred CA operations.** Out
  of scope here — deferred to a follow-on.
