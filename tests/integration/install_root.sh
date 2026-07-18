#!/bin/bash
# Root, on-box integration test for Task 11's box/install.sh.
#
# RUN AS ROOT, ON THE BOX ONLY:
#
#     sudo bash tests/integration/install_root.sh
#
# Exercises install.sh against REAL system state -- the real nebula-job
# user, the real /var/lib/nebula-ca + /etc/nebula-ca trees, the real
# /usr/local/lib/causb install, and the real /run/ca-usb tmpfiles.d entry --
# using EPHEMERAL, throwaway dummy keys generated fresh in a tempdir (never
# the real primary/break-glass signer keys). This is intentional: Task 11's
# brief is "testing runs it under sudo and asserts the resulting real system
# state," not a mocked/dry-run check.
#
# Covers:
#   1. install.sh run twice is idempotent: same resulting state, and the
#      2nd run's own output takes the "already exists" branch rather than
#      re-creating anything.
#   2. every directory/file install.sh manages has the owner:group:mode the
#      design calls for (S4/S12/S19 R2).
#   3. nebula-job exists, shell nologin, no home directory materialized.
#   4. /run/ca-usb exists, root 0700 (provisioned via tmpfiles.d).
#   5. install.sh REFUSES when --primary-pub and --breakglass-pub are the
#      SAME key (R6/D20), and touches no state when it does.
#   6. DAC proof: nebula-job cannot read a root:root 0400 file placed in
#      CA_DIR -- this is the actual privilege-separation property the whole
#      design rests on (S19 R2), not merely directory modes looking right
#      on paper.
#
# Leaves the box with the harness installed under DUMMY anchors when this
# script finishes -- by design (see Task 11 report): the operator re-runs
# install.sh with the REAL primary/break-glass pubkeys + real age recipient
# at finalization, before air-gapping (design doc S14).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (sudo bash $0)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/box/install.sh"
[[ -f "$INSTALL_SH" ]] || { echo "error: $INSTALL_SH not found" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Canonical paths -- read from the SAME causb.config module install.sh
# itself reads, so this test can never silently drift from what it's
# actually checking against.
# ---------------------------------------------------------------------------
eval "$(PYTHONPATH="$REPO_ROOT/box/lib" python3 -c '
from causb import config
print(f"STATE_DIR={config.STATE_DIR}")
print(f"CA_DIR={config.CA_DIR}")
print(f"RESULTS_DIR={config.RESULTS_DIR}")
print(f"ALLOWED={config.ALLOWED}")
print(f"BREAKGLASS={config.BREAKGLASS}")
print(f"BOX_NAME={config.BOX_NAME}")
print(f"BACKUP_RECIPIENT={config.BACKUP_RECIPIENT}")
print(f"AUDIT_LOG={config.AUDIT_LOG}")
')"
ETC_DIR="$(dirname "$ALLOWED")"
BOX_NAME_FILE="$STATE_DIR/box-name"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "[PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $1"; }

check_stat() {
    # check_stat <path> <expected "user group mode"> <label>
    local path="$1" want="$2" label="$3" got
    if ! got="$(stat -c '%U %G %a' "$path" 2>&1)"; then
        fail "$label: stat failed on $path ($got)"
        return
    fi
    if [[ "$got" == "$want" ]]; then
        pass "$label ($path = $got)"
    else
        fail "$label: $path = '$got', want '$want'"
    fi
}

WORKDIR="$(mktemp -d /tmp/causb-install-test.XXXXXX)"
DAC_TEST_FILE=""
cleanup() {
    [[ -n "$DAC_TEST_FILE" ]] && rm -f "$DAC_TEST_FILE"
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== generating ephemeral dummy anchors in $WORKDIR (never real keys) =="
ssh-keygen -t ed25519 -N '' -C 'install-root-test-primary' -f "$WORKDIR/primary" -q
ssh-keygen -t ed25519 -N '' -C 'install-root-test-breakglass' -f "$WORKDIR/breakglass" -q
age-keygen -o "$WORKDIR/age-identity.txt" >/dev/null 2>&1
age-keygen -y "$WORKDIR/age-identity.txt" > "$WORKDIR/age-recipient.txt"

PRIMARY_PUB="$WORKDIR/primary.pub"
BREAKGLASS_PUB="$WORKDIR/breakglass.pub"
AGE_RECIPIENT="$WORKDIR/age-recipient.txt"

echo
echo "== [1/8] first install.sh run =="
bash "$INSTALL_SH" --primary-pub "$PRIMARY_PUB" --breakglass-pub "$BREAKGLASS_PUB" --age-recipient "$AGE_RECIPIENT"

snapshot() {
    stat -c '%n %U %G %a' \
        "$STATE_DIR" "$CA_DIR" "$RESULTS_DIR" "$ETC_DIR" \
        "$ALLOWED" "$BREAKGLASS" "$BOX_NAME_FILE" "$BACKUP_RECIPIENT" \
        /run/ca-usb /etc/tmpfiles.d/ca-usb.conf 2>&1
    echo "--- content ---"
    cat "$ALLOWED" "$BREAKGLASS" "$BOX_NAME_FILE" "$BACKUP_RECIPIENT" 2>&1
    echo "--- causb package files ---"
    find /usr/local/lib/causb -type f -printf '%p %m\n' 2>&1 | sort
    echo "--- handlers dir ---"
    find /usr/local/lib/ca-usb/handlers 2>&1 | sort
    echo "--- nebula-job uid ---"
    id -u nebula-job
}
SNAP1="$(snapshot)"

echo
echo "== [2/8] second install.sh run (expect clean no-op) =="
RUN2_OUT="$(bash "$INSTALL_SH" --primary-pub "$PRIMARY_PUB" --breakglass-pub "$BREAKGLASS_PUB" --age-recipient "$AGE_RECIPIENT" 2>&1)"
echo "$RUN2_OUT"
SNAP2="$(snapshot)"

if [[ "$SNAP1" == "$SNAP2" ]]; then
    pass "idempotent: full state snapshot identical after 2nd run"
else
    fail "idempotent: state CHANGED on 2nd run"
    diff <(echo "$SNAP1") <(echo "$SNAP2") || true
fi

if grep -q "user nebula-job already exists" <<<"$RUN2_OUT" && ! grep -q "created system user" <<<"$RUN2_OUT"; then
    pass "idempotent: 2nd run took the 'already exists' branch for nebula-job (not re-created)"
else
    fail "idempotent: 2nd run's own output did not show the expected 'already exists' branch"
fi

echo
echo "== [3/8] perm/owner assertions =="
check_stat "$STATE_DIR" "root root 700" "STATE_DIR"
check_stat "$CA_DIR" "root root 700" "CA_DIR"
check_stat "$RESULTS_DIR" "root root 700" "RESULTS_DIR"
check_stat "$ETC_DIR" "root root 750" "/etc/nebula-ca"
check_stat "$ALLOWED" "root root 644" "ALLOWED"
check_stat "$BREAKGLASS" "root root 444" "BREAKGLASS"
check_stat "$BOX_NAME_FILE" "root root 644" "box-name"
check_stat "$BACKUP_RECIPIENT" "root root 644" "backup-recipient"

if grep -q '^nebula-ca-operator ' "$ALLOWED"; then
    pass "ALLOWED has nebula-ca-operator principal line"
else
    fail "ALLOWED missing nebula-ca-operator principal line: $(cat "$ALLOWED")"
fi
if grep -q '^nebula-ca-breakglass ' "$BREAKGLASS"; then
    pass "BREAKGLASS has nebula-ca-breakglass principal line"
else
    fail "BREAKGLASS missing nebula-ca-breakglass principal line: $(cat "$BREAKGLASS")"
fi
if [[ "$(cat "$BOX_NAME_FILE")" == "$BOX_NAME" ]]; then
    pass "box-name == $BOX_NAME"
else
    fail "box-name wrong: $(cat "$BOX_NAME_FILE")"
fi
if diff -q "$AGE_RECIPIENT" "$BACKUP_RECIPIENT" >/dev/null 2>&1; then
    pass "backup-recipient content matches --age-recipient input verbatim"
else
    fail "backup-recipient content does NOT match --age-recipient input"
fi

echo
echo "== [4/8] nebula-job system user =="
if id -u nebula-job >/dev/null 2>&1; then
    entry="$(getent passwd nebula-job)"
    shell="$(cut -d: -f7 <<<"$entry")"
    home="$(cut -d: -f6 <<<"$entry")"
    if [[ "$shell" == "/usr/sbin/nologin" ]]; then
        pass "nebula-job shell = $shell"
    else
        fail "nebula-job shell wrong: $shell"
    fi
    if [[ ! -d "$home" ]]; then
        pass "nebula-job has no materialized home directory (passwd home field: $home)"
    else
        fail "nebula-job home directory EXISTS on disk: $home"
    fi
    uid="$(id -u nebula-job)"
    if [[ "$uid" -lt 1000 ]]; then
        pass "nebula-job is a system account (uid=$uid < 1000)"
    else
        fail "nebula-job uid=$uid does not look like a system account (-r)"
    fi
else
    fail "nebula-job does not exist"
fi

echo
echo "== [5/8] /run/ca-usb (tmpfiles.d) =="
check_stat /run/ca-usb "root root 700" "/run/ca-usb"

echo
echo "== [6/8] identical-key refusal (R6/D20) =="
pre_allowed="$(cat "$ALLOWED")"
pre_breakglass="$(cat "$BREAKGLASS")"
if out="$(bash "$INSTALL_SH" --primary-pub "$PRIMARY_PUB" --breakglass-pub "$PRIMARY_PUB" --age-recipient "$AGE_RECIPIENT" 2>&1)"; then
    fail "install.sh ACCEPTED identical primary/breakglass keys (must refuse): $out"
else
    pass "install.sh refused identical primary/breakglass keys (non-zero exit)"
fi
post_allowed="$(cat "$ALLOWED")"
post_breakglass="$(cat "$BREAKGLASS")"
if [[ "$pre_allowed" == "$post_allowed" && "$pre_breakglass" == "$post_breakglass" ]]; then
    pass "identical-key refusal touched NO anchor state (validated before mutation)"
else
    fail "identical-key attempt CHANGED anchor state despite refusing"
fi

echo
echo "== [7/8] DAC proof: nebula-job must NOT read a root-only file in CA_DIR =="
DAC_TEST_FILE="$CA_DIR/.install-root-test-dac-proof"
echo "top-secret-canary-$$" > "$WORKDIR/dac-src"
install -m 0400 -o root -g root "$WORKDIR/dac-src" "$DAC_TEST_FILE"
check_stat "$DAC_TEST_FILE" "root root 400" "DAC test file"

if out="$(sudo -u nebula-job cat "$DAC_TEST_FILE" 2>&1)"; then
    fail "sudo -u nebula-job cat SUCCEEDED (DAC confinement BROKEN): $out"
else
    pass "sudo -u nebula-job cat correctly failed: $out"
fi

rm -f "$DAC_TEST_FILE"
DAC_TEST_FILE=""
echo "cleaned up $CA_DIR/.install-root-test-dac-proof"

echo
echo "== [8/8] directory-symlink refusal (install -d dereference gap) =="
# `install -d <path>` follows a pre-existing symlink at <path> and would
# retarget its VICTIM to root:root 0700. Prove install.sh refuses: stash the
# real (empty, root:root 0700) CA_DIR aside, plant a symlink at CA_DIR's path
# pointing at a distinctively-owned victim dir, and confirm install.sh exits
# non-zero WITHOUT chmod/chown-ing the victim through the link.
SYMTEST_VICTIM="$WORKDIR/symlink-victim"
mkdir -p "$SYMTEST_VICTIM"
chown nobody:nogroup "$SYMTEST_VICTIM"
chmod 0755 "$SYMTEST_VICTIM"
victim_before="$(stat -c '%U %G %a' "$SYMTEST_VICTIM")"

CA_DIR_STASH="${CA_DIR}.symtest-stash.$$"
mv "$CA_DIR" "$CA_DIR_STASH"
ln -s "$SYMTEST_VICTIM" "$CA_DIR"

if out="$(bash "$INSTALL_SH" --primary-pub "$PRIMARY_PUB" --breakglass-pub "$BREAKGLASS_PUB" --age-recipient "$AGE_RECIPIENT" 2>&1)"; then
    fail "install.sh SUCCEEDED with a symlink planted at CA_DIR's path (must refuse)"
else
    pass "install.sh refused a symlinked CA_DIR path (non-zero exit)"
fi

victim_after="$(stat -c '%U %G %a' "$SYMTEST_VICTIM")"
if [[ "$victim_before" == "$victim_after" ]]; then
    pass "symlink victim NOT retargeted (still '$victim_after' -- install.sh did not chown/chmod through the link)"
else
    fail "symlink victim WAS retargeted: before='$victim_before' after='$victim_after'"
fi
if [[ -L "$CA_DIR" ]]; then
    pass "CA_DIR path is still the planted symlink (install.sh replaced nothing)"
else
    fail "CA_DIR path is no longer a symlink after the refusal"
fi

# Restore the real CA_DIR so the box is left in the normal installed state.
rm -f "$CA_DIR"
mv "$CA_DIR_STASH" "$CA_DIR"
if [[ ! -L "$CA_DIR" && "$(stat -c '%U %G %a' "$CA_DIR")" == "root root 700" ]]; then
    pass "restored real CA_DIR (root root 700) after symlink test"
else
    fail "failed to restore real CA_DIR after symlink test"
fi

echo
echo "== [9/9] final-review F1/F2: audit.log + boot-reconcile unit =="
# F1: append-only audit.log pre-created 0600 root:root (§4/§11).
if [[ -f "$AUDIT_LOG" ]]; then
    check_stat "$AUDIT_LOG" "root root 600" "audit.log"
else
    fail "audit.log not pre-created at $AUDIT_LOG"
fi
# F2: ca-usb-reconcile.service installed 0644 + ENABLED (R7/D22 boot recovery;
# unlike usbguard, this unit IS meant to be enabled -- it only rebuilds on-box
# caches from DONE markers and touches no USB/network/mount state).
RECONCILE_UNIT="/etc/systemd/system/ca-usb-reconcile.service"
if [[ -f "$RECONCILE_UNIT" ]]; then
    check_stat "$RECONCILE_UNIT" "root root 644" "ca-usb-reconcile.service"
    if systemctl is-enabled ca-usb-reconcile.service >/dev/null 2>&1; then
        pass "ca-usb-reconcile.service is enabled (runs reconcile on every boot)"
    else
        fail "ca-usb-reconcile.service installed but NOT enabled"
    fi
else
    fail "ca-usb-reconcile.service not installed at $RECONCILE_UNIT"
fi

echo
echo "================================================================"
echo "install_root.sh: $PASS passed, $FAIL failed"
echo "================================================================"
echo
echo "NOTE: the box now has the harness installed with DUMMY (ephemeral,"
echo "discarded) anchors from this test run. The operator must re-run"
echo "install.sh with the REAL --primary-pub/--breakglass-pub/--age-recipient"
echo "before air-gapping (design doc S14)."

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
