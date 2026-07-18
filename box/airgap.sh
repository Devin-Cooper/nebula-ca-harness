#!/bin/sh
# box/airgap.sh -- Phase D: the LAST step an
# operator runs to sever this box from the network before it becomes the
# air-gapped Nebula CA. Every earlier step (install.sh, the real trust
# anchors, a real ca-bootstrap) is redoable; this one is meant to be, in
# ordinary operation, effectively one-way -- so it is DELIBERATELY inert
# unless the operator passes --confirm, and it never touches the one path
# back in if something about the network posture ever turns out wrong.
#
# CRITICAL, CONFIRMED BY THE OPERATOR (2026-07-12):
# this script MUST NEVER mask serial-getty@ttyFIQ0, the physical serial
# console rescue login (the NanoPi's UART getty). Once the network is gone
# and USBGuard/K1 lock everything else down, that console is the box's
# ONLY break-glass path back in -- masking it would strand the box
# permanently, with no network and no USB-shell way back. See the
# MASK_UNITS assignment and the guard loop immediately below it: those are
# the two independent mechanisms (a fixed, reviewed list; and a live,
# self-checking abort) that hold this invariant.
#
# Usage:
#   airgap.sh                 -- print the plan, do nothing (default/safe)
#   airgap.sh --dry-run       -- identical to the above, explicit spelling
#   airgap.sh --confirm       -- ACTUALLY mask/disable/lock, then instruct
#                                 the operator to pull the Ethernet cable
#
# Idempotent: safe to run --confirm more than once. Every mutating action
# below is individually guarded by a query of its current state first, so
# a repeat run is a clean no-op (nothing re-masked/re-disabled/re-locked),
# not an error -- matching this project's install.sh precedent.
set -eu

usage() {
    cat <<'USAGE_EOF'
Usage: airgap.sh [--confirm]

Without any flag, or with --dry-run: prints the Phase-D plan and performs
NO action whatsoever -- safe to run as any user, any number of times.

With --confirm: masks the network-adjacent systemd units, disables NTP,
locks the "pi" account login, and instructs you to physically remove the
Ethernet cable. Requires the privilege systemctl/passwd/timedatectl
themselves require (root, in real use). Safe to re-run (idempotent).
USAGE_EOF
}

MODE="plan"
if [ "$#" -eq 0 ]; then
    MODE="plan"
elif [ "$#" -eq 1 ]; then
    case "$1" in
        --confirm)
            MODE="confirm"
            ;;
        --dry-run)
            MODE="plan"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "airgap.sh: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
else
    echo "airgap.sh: too many arguments" >&2
    usage >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# The ONE place this script's mask list is defined. Every unit here is
# network-adjacent (Wi-Fi/Ethernet/NTP/remote-login); masking them is what
# actually severs this box's reachability and stops any future boot from
# silently re-enabling it.
#
# serial-getty@ttyFIQ0 (the physical serial-console rescue login) is
# DELIBERATELY, PERMANENTLY ABSENT from this list -- CONFIRMED RETAINED by
# the operator. DO NOT ADD IT HERE. EVER. If this box's network posture is
# ever wrong post-air-gap, this console is the only way back in.
# ---------------------------------------------------------------------------
MASK_UNITS="NetworkManager wpa_supplicant systemd-networkd systemd-networkd.socket networking systemd-timesyncd ssh"

# Belt-and-suspenders: if a future edit to MASK_UNITS above ever
# re-introduces a serial-console rescue getty, ABORT here rather than mask
# it. Runs unconditionally, in EVERY mode (plan and confirm alike), before
# anything else below -- a live self-check of the list this run of the
# script actually computed, not just a one-time code review. Matches on the
# whole serial-getty@* family (not only the exact ttyFIQ0 instance): this
# box has exactly one physical serial console, so there is no legitimate
# reason for this script to ever name ANY serial-getty instance.
for _unit in $MASK_UNITS; do
    case "$_unit" in
        serial-getty@*)
            echo "airgap.sh: REFUSING to run: the computed mask list names a serial console rescue getty ($_unit, R11). This is a bug in this script -- aborting WITHOUT masking, disabling, or locking anything." >&2
            exit 1
            ;;
    esac
done

echo "=== airgap.sh -- Phase D plan ==="
echo "The following units would be masked (systemctl mask), so no future"
echo "boot can silently re-enable network connectivity:"
for _unit in $MASK_UNITS; do
    echo "  - $_unit"
done
echo "NTP would be disabled (timedatectl set-ntp false)."
echo "The 'pi' account login would be locked (passwd -l pi)."
echo

if [ "$MODE" = "plan" ]; then
    echo "Plan only -- NOTHING was changed. Re-run with --confirm to act."
    exit 0
fi

echo "=== --confirm: applying the plan now ==="

for _unit in $MASK_UNITS; do
    _state="$(systemctl is-enabled "$_unit" 2>/dev/null || true)"
    if [ "$_state" = "masked" ]; then
        echo "already masked: $_unit"
    else
        systemctl mask "$_unit"
        echo "masked: $_unit"
    fi
done

_ntp_state="$(timedatectl show -p NTP --value 2>/dev/null || true)"
if [ "$_ntp_state" = "no" ]; then
    echo "NTP already disabled"
else
    # timedatectl set-ntp can report "NTP not supported" once
    # systemd-timesyncd is masked above (no NTP service is left to toggle);
    # NTP is off regardless, so tolerate a failure here rather than let
    # `set -e` abort the run before the pi-lock step below.
    if timedatectl set-ntp false 2>/dev/null; then
        echo "NTP disabled"
    else
        echo "NTP off (timesyncd masked; set-ntp not applicable)"
    fi
fi

_pi_state="$(passwd -S pi 2>/dev/null || true)"
_pi_flag="$(echo "$_pi_state" | awk '{print $2}')"
if [ "$_pi_flag" = "L" ]; then
    echo "pi already locked"
else
    passwd -l pi
    echo "pi locked"
fi

echo
echo "=================================================================="
echo "Air-gap steps complete."
echo "Now physically pull the Ethernet cable."
echo "=================================================================="
