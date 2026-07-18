#!/bin/bash
# Box-safe install/enable check for ca-usb-reconcile.service (final-review F2).
#
# RUN ON THE BOX (no root needed, touches NO real systemd state):
#
#     bash tests/integration/reconcile_unit_install.sh
#
# Validates the boot-reconcile unit WITHOUT mutating the box's real systemd
# state or /var/lib/nebula-ca: everything happens in a throwaway --root tree.
# The full real install+enable is exercised by the operator's install_root.sh
# finalization run; this is the gated, temp-path check the final review asked
# for so the wiring can be proven without enabling a unit that would run at the
# box's next boot.
#
# Covers:
#   1. `systemd-analyze verify` of the unit is clean (no diagnostics naming it).
#   2. install.sh actually wires BOTH the install and the `systemctl enable` of
#      the unit (grep the installer, so this can't silently un-wire).
#   3. The unit is ENABLE-ABLE offline: `systemctl --root=<tmp> enable` creates
#      the multi-user.target.wants/ca-usb-reconcile.service symlink in the temp
#      root -- proving [Install] WantedBy=multi-user.target is correct -- with
#      zero mutation of the box's real /etc/systemd.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_SRC="$REPO_ROOT/box/systemd/ca-usb-reconcile.service"
INSTALL_SH="$REPO_ROOT/box/install.sh"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "[PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $1"; }

[[ -f "$UNIT_SRC" ]] || { echo "error: $UNIT_SRC not found" >&2; exit 1; }

TMPROOT="$(mktemp -d /tmp/causb-reconcile-unit.XXXXXX)"
cleanup() { rm -rf "$TMPROOT"; }
trap cleanup EXIT

echo "== [1/3] systemd-analyze verify =="
# Filter to diagnostics that name THIS unit -- the box may carry unrelated
# pre-existing unit warnings (e.g. a legacy rc-local.service) that are not
# this unit's concern and must not fail this check.
verify_out="$(systemd-analyze verify "$UNIT_SRC" 2>&1)"
if grep -qi 'ca-usb-reconcile' <<<"$verify_out"; then
    fail "systemd-analyze verify flagged ca-usb-reconcile.service:"
    grep -i 'ca-usb-reconcile' <<<"$verify_out"
else
    pass "systemd-analyze verify clean for ca-usb-reconcile.service"
fi

echo
echo "== [2/3] install.sh wires install + enable =="
if grep -q 'ca-usb-reconcile.service' "$INSTALL_SH" \
   && grep -q 'systemctl enable ca-usb-reconcile.service' "$INSTALL_SH"; then
    pass "install.sh installs AND enables ca-usb-reconcile.service"
else
    fail "install.sh does not wire both install and enable of ca-usb-reconcile.service"
fi

echo
echo "== [3/3] offline enable into a throwaway --root (no real systemd touched) =="
install -d -m 0755 "$TMPROOT/etc/systemd/system"
# Mirror install.sh's own `install -m 0644` of the unit into the temp root.
install -m 0644 "$UNIT_SRC" "$TMPROOT/etc/systemd/system/ca-usb-reconcile.service"
mode="$(stat -c '%a' "$TMPROOT/etc/systemd/system/ca-usb-reconcile.service")"
[[ "$mode" == "644" ]] && pass "unit installs mode 0644" || fail "unit mode is $mode, want 644"

if systemctl --root="$TMPROOT" enable ca-usb-reconcile.service >/dev/null 2>&1; then
    WANT_LINK="$TMPROOT/etc/systemd/system/multi-user.target.wants/ca-usb-reconcile.service"
    if [[ -L "$WANT_LINK" ]]; then
        pass "offline enable created multi-user.target.wants symlink (WantedBy correct)"
    else
        fail "offline enable did not create the expected wants symlink"
    fi
else
    fail "systemctl --root enable of ca-usb-reconcile.service failed"
fi

# Prove we touched NO real systemd state.
if [[ ! -e /etc/systemd/system/multi-user.target.wants/ca-usb-reconcile.service ]]; then
    pass "box's REAL /etc/systemd was not mutated (offline --root only)"
else
    fail "a real multi-user.target.wants/ca-usb-reconcile.service symlink exists (unexpected)"
fi

echo
echo "================================================================"
echo "reconcile_unit_install.sh: $PASS passed, $FAIL failed"
echo "================================================================"
[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
