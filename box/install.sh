#!/bin/bash
# Idempotent installer for the air-gapped Nebula CA USB job harness.
#
# Provisions, all idempotently (safe to re-run any number of times):
#   - the "nebula-job" system user (no login, no key/anchor access -- the
#     confinement target for un-vetted run-script jobs).
#   - STATE_DIR/CA_DIR/RESULTS_DIR (root:root 0700) and /etc/nebula-ca
#     (root:root 0755). NOTE: there is NO "nebula-ca" user and this
#     script does NOT create ca.key -- that happens later, as root, via the
#     ca-bootstrap handler (a follow-on deliverable).
#   - the trust anchors: allowed_signers (0644, operational) and
#     breakglass_signers (0444, immutable-by-policy -- protected by
#     the co-sign rule, not a chattr(1) flag) from caller-supplied
#     pubkeys. Refuses to install if the two pubkeys are the same key
#     (the operational and break-glass signers MUST be distinct).
#   - the fixed box-name pin and the box-pinned age backup-ca recipient.
#   - the causb Python package (box/lib/causb -> /usr/local/lib/causb, so
#     "import causb" works from the installed copy) and, if present in the
#     source tree yet, box/handlers -> /usr/local/lib/ca-usb/handlers
#     (handlers are a follow-on deliverable; installs whatever exists so
#     this script does not need to change again once they land).
#   - /etc/tmpfiles.d/ca-usb.conf, applied immediately, provisioning the
#     /run/ca-usb flock directory the (future) systemd unit needs under
#     ProtectSystem=strict.
#   - the ca-usb-job@.service unit + 99-ca-usb-job.rules udev trigger
#     and box/bin/ca-usb-run -> /usr/local/sbin/
#     ca-usb-run (the full mount->verify->K1->dispatch->commit->deliver
#     lifecycle orchestrator). Reloads systemd + udev rules so
#     the updated unit/rule/binary become authoritative for the NEXT insert
#     (or a reboot's coldplug); each reload/trigger step is guarded (skipped
#     with a warning, not a hard failure) if systemctl/udevadm aren't on
#     PATH, so this script stays safe to exercise in a minimal test
#     environment that lacks a running systemd/udev. NOTE: a post-install
#     `udevadm trigger` does NOT re-fire ca-usb-job@<dev> for a stick that
#     is ALREADY plugged in (its .device unit is already active) -- only a
#     physical reinsert or a reboot does; the script prints a reminder to
#     that effect at the end (see the reload block near the bottom).
#
# Usage:
#   sudo ./install.sh --primary-pub <file> --breakglass-pub <file> \
#       --age-recipient <file> [--src <repo-box-dir>]
#
# --src defaults to this script's own directory (i.e. running it straight
# out of a deployed checkout, e.g. /opt/nebula-ca/src/box/install.sh, "just
# works"). Re-running later with the REAL primary/break-glass pubkeys and
# the real age recipient replaces whatever (e.g. dummy bring-up) anchors
# were installed before -- that is the intended finalization path, not a
# special case.
set -euo pipefail

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR"

PRIMARY_PUB=""
BREAKGLASS_PUB=""
AGE_RECIPIENT=""

usage() {
    cat >&2 <<EOF
Usage: $0 --primary-pub <file> --breakglass-pub <file> --age-recipient <file> [--src <repo-box-dir>]

  --primary-pub      SSH ed25519 public key file for the operational signer
                      (principal "nebula-ca-operator" in allowed_signers).
  --breakglass-pub    SSH ed25519 public key file for the break-glass signer
                      (principal "nebula-ca-breakglass" in breakglass_signers).
                      MUST differ from --primary-pub.
  --age-recipient     File containing the box-pinned age backup recipient
                      (contents copied verbatim; used later by backup-ca).
  --src               Repo "box/" directory to install from. Defaults to
                      the directory this script lives in.
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --primary-pub)
            [[ $# -ge 2 ]] || usage
            PRIMARY_PUB="$2"; shift 2 ;;
        --breakglass-pub)
            [[ $# -ge 2 ]] || usage
            BREAKGLASS_PUB="$2"; shift 2 ;;
        --age-recipient)
            [[ $# -ge 2 ]] || usage
            AGE_RECIPIENT="$2"; shift 2 ;;
        --src)
            [[ $# -ge 2 ]] || usage
            SRC="$2"; shift 2 ;;
        -h|--help)
            usage ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage ;;
    esac
done

[[ -n "$PRIMARY_PUB" ]] || { echo "error: --primary-pub is required" >&2; usage; }
[[ -n "$BREAKGLASS_PUB" ]] || { echo "error: --breakglass-pub is required" >&2; usage; }
[[ -n "$AGE_RECIPIENT" ]] || { echo "error: --age-recipient is required" >&2; usage; }

if [[ $EUID -ne 0 ]]; then
    echo "error: install.sh must be run as root (sudo)" >&2
    exit 1
fi

for f in "$PRIMARY_PUB" "$BREAKGLASS_PUB" "$AGE_RECIPIENT"; do
    [[ -f "$f" && -r "$f" ]] || { echo "error: not a readable file: $f" >&2; exit 1; }
done

[[ -d "$SRC" ]] || { echo "error: --src is not a directory: $SRC" >&2; exit 1; }
SRC="$(cd "$SRC" && pwd)"
[[ -f "$SRC/lib/causb/config.py" ]] || {
    echo "error: $SRC does not look like the box/ source tree (no lib/causb/config.py under it)" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Canonical paths -- read from box/lib/causb/config.py (the single source of
# truth shared with the Python harness) rather than duplicated as literals,
# so this script and the code can never drift apart.
# ---------------------------------------------------------------------------
if ! CONFIG_OUT="$(PYTHONPATH="$SRC/lib" python3 -c '
from causb import config
print(config.STATE_DIR)
print(config.CA_DIR)
print(config.RESULTS_DIR)
print(config.ALLOWED)
print(config.BREAKGLASS)
print(config.BOX_NAME)
print(config.BACKUP_RECIPIENT)
print(config.AUDIT_LOG)
print(config.REGISTRY)
print(config.OVERLAY_CIDR)
' 2>&1)"; then
    echo "error: failed to read canonical paths from $SRC/lib/causb/config.py:" >&2
    echo "$CONFIG_OUT" >&2
    exit 1
fi
# Read the fixed-order lines into vars WITHOUT eval: eval-ing NAME=value text
# printed by a subprocess is a fragile habit (shell-injection-shaped even when
# the source is trusted). A filesystem path never contains a newline, so a
# line-by-line read is exact and safe. The `: "${VAR:?}"` guards below still
# fail-closed if config.py ever prints fewer/renamed lines.
{
    read -r STATE_DIR
    read -r CA_DIR
    read -r RESULTS_DIR
    read -r ALLOWED
    read -r BREAKGLASS
    read -r BOX_NAME
    read -r BACKUP_RECIPIENT
    read -r AUDIT_LOG
    read -r REGISTRY
    read -r OVERLAY_CIDR
} <<< "$CONFIG_OUT"
: "${STATE_DIR:?missing STATE_DIR from config.py}"
: "${CA_DIR:?missing CA_DIR from config.py}"
: "${RESULTS_DIR:?missing RESULTS_DIR from config.py}"
: "${ALLOWED:?missing ALLOWED from config.py}"
: "${BREAKGLASS:?missing BREAKGLASS from config.py}"
: "${BOX_NAME:?missing BOX_NAME from config.py}"
: "${BACKUP_RECIPIENT:?missing BACKUP_RECIPIENT from config.py}"
: "${AUDIT_LOG:?missing AUDIT_LOG from config.py}"
: "${REGISTRY:?missing REGISTRY from config.py}"
: "${OVERLAY_CIDR:?missing OVERLAY_CIDR from config.py}"

ETC_DIR="$(dirname "$ALLOWED")"

# ---------------------------------------------------------------------------
# Validate the supplied pubkeys BEFORE touching any system state: a bad
# invocation (garbage file, or primary==breakglass) must leave the box
# completely untouched, not half-provisioned.
# ---------------------------------------------------------------------------

# First non-blank line only -- guards against a trailing-blank-line pubkey
# file breaking the "exactly one line" anchors-file contract.
_first_pubkey_line() {
    grep -m1 -v '^[[:space:]]*$' "$1" 2>/dev/null || true
}

primary_line="$(_first_pubkey_line "$PRIMARY_PUB")"
breakglass_line="$(_first_pubkey_line "$BREAKGLASS_PUB")"

[[ -n "$primary_line" ]] || { echo "error: --primary-pub is empty: $PRIMARY_PUB" >&2; exit 1; }
[[ -n "$breakglass_line" ]] || { echo "error: --breakglass-pub is empty: $BREAKGLASS_PUB" >&2; exit 1; }

if ! ssh-keygen -l -f "$PRIMARY_PUB" >/dev/null 2>&1; then
    echo "error: --primary-pub does not look like a valid SSH public key: $PRIMARY_PUB" >&2
    exit 1
fi
if ! ssh-keygen -l -f "$BREAKGLASS_PUB" >/dev/null 2>&1; then
    echo "error: --breakglass-pub does not look like a valid SSH public key: $BREAKGLASS_PUB" >&2
    exit 1
fi

# Disjointness sanity: compare (keytype, base64) only -- the same
# rule causb.verify._key_blobs() uses for the box's own cosign disjointness
# check -- so a differing comment field can never mask an actually-identical
# key, and an identical comment on two different keys never causes a false
# refusal.
primary_blob="$(awk '{print $1, $2}' <<<"$primary_line")"
breakglass_blob="$(awk '{print $1, $2}' <<<"$breakglass_line")"
if [[ -z "$(awk '{print $2}' <<<"$primary_line")" ]]; then
    echo "error: --primary-pub does not look like '<keytype> <base64> [comment]': $PRIMARY_PUB" >&2
    exit 1
fi
if [[ -z "$(awk '{print $2}' <<<"$breakglass_line")" ]]; then
    echo "error: --breakglass-pub does not look like '<keytype> <base64> [comment]': $BREAKGLASS_PUB" >&2
    exit 1
fi
if [[ "$primary_blob" == "$breakglass_blob" ]]; then
    echo "error: --primary-pub and --breakglass-pub are the SAME key -- refusing to install." >&2
    echo "       The operational (allowed_signers) and break-glass (breakglass_signers) signers" >&2
    echo "       must be distinct keys (R6/D20: a compromised primary must never be able to" >&2
    echo "       forge break-glass co-signatures, e.g. to evict itself)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Mutations begin here. Nothing above this line writes anything.
# ---------------------------------------------------------------------------

# --- system user: nebula-job (no login, no home, no key/anchor access) -----
if id -u nebula-job >/dev/null 2>&1; then
    echo "user nebula-job already exists -- skipping"
else
    useradd -r -M -s /usr/sbin/nologin nebula-job
    echo "created system user nebula-job (no login, no home)"
fi

# --- directories -------------------------------------------------------------
# `install -d <path>` FOLLOWS a symlink sitting at <path>: if someone with
# write access to /var/lib or /etc pre-plants a symlink at (e.g.) the ca.key
# dir pointing at a victim directory, install -d silently retargets that
# victim to root:root 0700 instead of creating a real dir. Refuse a
# pre-existing symlink at any managed dir path before creating it. (The FILE
# writes further down are already symlink-safe via mktemp + rename.) Checked
# parent-before-child so a symlinked STATE_DIR is caught before its children
# are even considered. A fresh install has none of these as symlinks; a re-run
# has them as the real dirs it made last time.
_ensure_dir() {
    local dir="$1" mode="$2"
    if [[ -L "$dir" ]]; then
        echo "error: refusing to provision $dir -- it is a symlink" >&2
        echo "       (install -d would follow it and retarget its target to root:root $mode)" >&2
        exit 1
    fi
    install -d -m "$mode" -o root -g root "$dir"
}
_ensure_dir "$STATE_DIR" 0700
_ensure_dir "$CA_DIR" 0700
_ensure_dir "$RESULTS_DIR" 0700
# /etc/nebula-ca is 0750 (root:root), NOT world-traversable: the posture is
# "nebula-job cannot traverse /etc/nebula-ca". nebula-job never needs the
# anchors (they are read by the root harness during verify), and although
# the anchor FILES are public keys, matching the stated no-traverse posture
# costs nothing. (0750 still lets root -- the harness -- traverse freely.)
_ensure_dir "$ETC_DIR" 0750
echo "ensured $STATE_DIR (0700), $CA_DIR (0700), $RESULTS_DIR (0700), $ETC_DIR (0750)"

# --- atomic-write helpers ----------------------------------------------------
# Write-to-tmp + chmod + chown + rename(2) so a reader (or a concurrent
# re-run) never observes a partially-written anchor/state file -- same
# tmp->rename pattern this project's Python side already uses (commitlog.py,
# mac/caj, mac/caj-recv).
_atomic_write() {
    local dest="$1" content="$2" mode="$3"
    local tmp
    tmp="$(mktemp "${dest}.XXXXXX")"
    printf '%s' "$content" > "$tmp"
    chmod "$mode" "$tmp"
    chown root:root "$tmp"
    mv -f "$tmp" "$dest"
}

_atomic_copy_file() {
    local src="$1" dest="$2" mode="$3"
    local tmp
    tmp="$(mktemp "${dest}.XXXXXX")"
    cp -f "$src" "$tmp"
    chmod "$mode" "$tmp"
    chown root:root "$tmp"
    mv -f "$tmp" "$dest"
}

# --- trust anchors ------------------------------------------------------------
printf -v allowed_content 'nebula-ca-operator %s\n' "$primary_line"
_atomic_write "$ALLOWED" "$allowed_content" 0644
echo "wrote $ALLOWED (0644, principal nebula-ca-operator)"

printf -v breakglass_content 'nebula-ca-breakglass %s\n' "$breakglass_line"
_atomic_write "$BREAKGLASS" "$breakglass_content" 0444
echo "wrote $BREAKGLASS (0444, principal nebula-ca-breakglass)"

# --- box-name pin ---------------------------------------------------------
BOX_NAME_FILE="$STATE_DIR/box-name"
printf -v box_name_content '%s\n' "$BOX_NAME"
_atomic_write "$BOX_NAME_FILE" "$box_name_content" 0644
echo "wrote $BOX_NAME_FILE (0644) = $BOX_NAME"

# --- audit.log: append-only forensic log ----------
# Pre-create empty at config.AUDIT_LOG (0600 root:root) so the harness's first
# audited event appends to an already-correct file. Idempotent AND
# content-PRESERVING: an existing audit.log is NEVER truncated (it is
# append-only forensic history -- re-running install.sh must not wipe it), only
# its perms/owner are re-asserted. No `chattr +a` (kept portable, matching the
# breakglass anchor's append-only-by-policy posture rather than an fs flag).
if [[ ! -e "$AUDIT_LOG" ]]; then
    install -m 0600 -o root -g root /dev/null "$AUDIT_LOG"
    echo "created $AUDIT_LOG (0600 root:root, append-only)"
else
    chmod 0600 "$AUDIT_LOG"
    chown root:root "$AUDIT_LOG"
    echo "$AUDIT_LOG present -- content preserved, perms re-asserted (0600 root:root)"
fi

# --- registry.json: pre-create EMPTY if absent -----------------
# registry.json is a REBUILDABLE CACHE (causb.registry's own module
# docstring), never authoritative -- the committed results/<job_id>/
# allocation records are. `causb.registry.load()` already treats an absent
# file as an empty registry, and `causb.registry.save()` already creates
# CA_DIR on demand -- so this pre-create is not functionally required. It
# exists so that whichever of {the boot-time ca-usb-reconcile.service,
# a real ca-bootstrap job} is first to ever touch this box gets a
# well-formed 0644 root:root file to read/overwrite from the start, the
# same provisioning-consistency reasoning as the AUDIT_LOG block above.
# Idempotent AND content-PRESERVING: an EXISTING registry.json (real host
# allocations) is NEVER reset -- only perms/owner are re-asserted, mirroring
# AUDIT_LOG's identical posture. (Whichever code path next calls
# registry.save() against this file re-tightens its mode to 0600 anyway --
# harmless, and moot either way since CA_DIR itself is root:root 0700.)
if [[ ! -e "$REGISTRY" ]]; then
    printf -v registry_content '{\n  "overlay_cidr": "%s",\n  "hosts": {}\n}\n' "$OVERLAY_CIDR"
    _atomic_write "$REGISTRY" "$registry_content" 0644
    echo "created $REGISTRY (0644 root:root, empty, overlay_cidr=$OVERLAY_CIDR)"
else
    chmod 0644 "$REGISTRY"
    chown root:root "$REGISTRY"
    echo "$REGISTRY present -- content preserved, perms re-asserted (0644 root:root)"
fi

# --- box-pinned age backup recipient -----------------------------------------
_atomic_copy_file "$AGE_RECIPIENT" "$BACKUP_RECIPIENT" 0644
echo "wrote $BACKUP_RECIPIENT (0644) from $AGE_RECIPIENT"

# --- causb Python package -> /usr/local/lib/causb ----------------------------
LIB_DEST="/usr/local/lib/causb"
mkdir -p "$LIB_DEST"
rsync -a --delete --exclude='__pycache__' "$SRC/lib/causb/" "$LIB_DEST/"
find "$LIB_DEST" -type d -exec chmod 0755 {} +
find "$LIB_DEST" -type f -exec chmod 0644 {} +
chown -R root:root "$LIB_DEST"
echo "installed causb package -> $LIB_DEST (import causb works with PYTHONPATH=/usr/local/lib)"

# --- handlers -> /usr/local/lib/ca-usb/handlers (forward-compatible) --------
HANDLERS_DEST="/usr/local/lib/ca-usb/handlers"
mkdir -p "$HANDLERS_DEST"
if [[ -d "$SRC/handlers" ]]; then
    rsync -a --delete --exclude='__pycache__' "$SRC/handlers/" "$HANDLERS_DEST/"
    find "$HANDLERS_DEST" -type d -exec chmod 0755 {} +
    find "$HANDLERS_DEST" -type f -exec chmod 0755 {} +
    chown -R root:root "$HANDLERS_DEST"
    echo "installed handlers -> $HANDLERS_DEST"
else
    echo "no $SRC/handlers yet (follow-on deliverable) -- left $HANDLERS_DEST empty"
fi

# --- recovery-kit source tree -> /usr/local/share/ca-usb/recovery -----------
# Assemble the TRUSTED source that causb.recovery.write() copies from when an
# operator inserts a BLANK stick: the redistributable Mac tooling
# (caj/caj-recv), the EXACT causb import-closure those two need
# (__init__/config/manifest -- NOT the whole box-only package), and the
# recovery-kit/ doc + script templates. This path is causb.recovery's
# RECOVERY_SRC constant. The tooling + templates live at the repo ROOT
# (mac/, recovery-kit/) -- a sibling of the box/ dir SRC normally points at --
# so they are staged relative to REPO_ROOT rather than SRC. Guarded
# (warn-and-skip) if a source is absent, mirroring the handlers block's
# forward-compatible style, so a --src that isn't a full checkout still
# provisions everything else. Rebuilt from scratch each run so a re-run leaves
# no stale files (idempotent), matching the rsync --delete posture above.
RECOVERY_DEST="/usr/local/share/ca-usb/recovery"
REPO_ROOT="$(dirname "$SRC")"
CAJ_SRC="$REPO_ROOT/mac/caj"
CAJ_RECV_SRC="$REPO_ROOT/mac/caj-recv"
RECOVERY_KIT_SRC="$REPO_ROOT/recovery-kit"
if [[ -f "$CAJ_SRC" && -f "$CAJ_RECV_SRC" && -d "$RECOVERY_KIT_SRC" ]]; then
    rm -rf "$RECOVERY_DEST"
    install -d -m 0755 -o root -g root "$RECOVERY_DEST"
    install -d -m 0755 -o root -g root "$RECOVERY_DEST/causb"
    install -d -m 0755 -o root -g root "$RECOVERY_DEST/recovery-kit"
    # Redistributable tooling (executable so a rebuilt kit can run it).
    install -m 0755 -o root -g root "$CAJ_SRC" "$RECOVERY_DEST/caj"
    install -m 0755 -o root -g root "$CAJ_RECV_SRC" "$RECOVERY_DEST/caj-recv"
    # Exactly the causb modules caj/caj-recv import -- config + manifest (+ the
    # package __init__) -- copied from the same box/lib/causb this install
    # validated at the top. NOT the whole package (led/mountctl/extract/... are
    # box-only and have no business on a redistributed stick).
    for _m in __init__.py config.py manifest.py; do
        install -m 0644 -o root -g root "$SRC/lib/causb/$_m" "$RECOVERY_DEST/causb/$_m"
    done
    # Templates: shell scripts 0755, docs 0644.
    for _t in "$RECOVERY_KIT_SRC"/*; do
        [[ -f "$_t" ]] || continue
        case "$_t" in
            *.sh) install -m 0755 -o root -g root "$_t" "$RECOVERY_DEST/recovery-kit/$(basename "$_t")" ;;
            *)    install -m 0644 -o root -g root "$_t" "$RECOVERY_DEST/recovery-kit/$(basename "$_t")" ;;
        esac
    done
    echo "installed recovery source -> $RECOVERY_DEST (caj/caj-recv + causb closure + templates)"
else
    echo "warning: recovery sources not all present (need $CAJ_SRC, $CAJ_RECV_SRC, $RECOVERY_KIT_SRC/) -- skipped recovery staging" >&2
fi

# --- tmpfiles.d: /run/ca-usb for the harness flock ---------------------------
TMPFILES_SRC="$SRC/tmpfiles.d/ca-usb.conf"
TMPFILES_DEST="/etc/tmpfiles.d/ca-usb.conf"
if [[ -f "$TMPFILES_SRC" ]]; then
    install -m 0644 -o root -g root "$TMPFILES_SRC" "$TMPFILES_DEST"
    systemd-tmpfiles --create "$TMPFILES_DEST"
    echo "installed $TMPFILES_DEST and created /run/ca-usb"
else
    echo "warning: $TMPFILES_SRC not found -- skipped tmpfiles.d install" >&2
fi

# --- ca-usb-run -> /usr/local/sbin (the lifecycle orchestrator) ----------
RUN_SRC="$SRC/bin/ca-usb-run"
RUN_DEST="/usr/local/sbin/ca-usb-run"
if [[ -f "$RUN_SRC" ]]; then
    install -m 0755 -o root -g root "$RUN_SRC" "$RUN_DEST"
    echo "installed $RUN_DEST"
else
    echo "warning: $RUN_SRC not found -- skipped ca-usb-run install" >&2
fi

# --- systemd unit: ca-usb-job@.service ----------
UNIT_SRC="$SRC/systemd/ca-usb-job@.service"
UNIT_DEST="/etc/systemd/system/ca-usb-job@.service"
if [[ -f "$UNIT_SRC" ]]; then
    install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DEST"
    echo "installed $UNIT_DEST"
else
    echo "warning: $UNIT_SRC not found -- skipped ca-usb-job@.service install" >&2
fi

# --- systemd unit: ca-usb-reconcile.service (boot recovery) -------
# Boot-time restart-recovery oneshot (ca-usb-run --reconcile). Unlike usbguard
# (a deliberate later operator step), this IS enabled below: it only rebuilds
# the on-box results caches from DONE markers + purges pre-DONE partials, and
# touches no USB/network/mount state, so enabling it to run on every boot is
# safe and is exactly the "FS recovers, seq consistent" gate.
RECONCILE_UNIT_SRC="$SRC/systemd/ca-usb-reconcile.service"
RECONCILE_UNIT_DEST="/etc/systemd/system/ca-usb-reconcile.service"
if [[ -f "$RECONCILE_UNIT_SRC" ]]; then
    install -m 0644 -o root -g root "$RECONCILE_UNIT_SRC" "$RECONCILE_UNIT_DEST"
    echo "installed $RECONCILE_UNIT_DEST"
else
    echo "warning: $RECONCILE_UNIT_SRC not found -- skipped ca-usb-reconcile.service install" >&2
fi

# --- udev rule: 99-ca-usb-job.rules --------------------
UDEV_SRC="$SRC/udev/99-ca-usb-job.rules"
UDEV_DEST="/etc/udev/rules.d/99-ca-usb-job.rules"
if [[ -f "$UDEV_SRC" ]]; then
    install -m 0644 -o root -g root "$UDEV_SRC" "$UDEV_DEST"
    echo "installed $UDEV_DEST"
else
    echo "warning: $UDEV_SRC not found -- skipped 99-ca-usb-job.rules install" >&2
fi

# --- USBGuard: package + policy + daemon.conf + early ordering -------------
# Installs and configures USBGuard but LEAVES IT DISABLED/STOPPED: enabling
# it (systemctl enable --now usbguard) is a DELIBERATE, later operator step
# taken with the serial console available as a fallback, never
# something this script does. A wrong policy could strand the box's only
# I/O (the CA-XFER transfer stick) -- see box/usbguard/rules.conf's
# provenance comment and tests/integration/13-usbguard.md for the full
# reasoning and the deferred enable/verify checklist.
if command -v apt-get >/dev/null 2>&1; then
    # Debian's usbguard postinst unconditionally tries to START the daemon
    # on a first install (an automatically-added dh_installsystemd
    # `deb-systemd-invoke start usbguard-dbus.service usbguard.service`
    # block), REGARDLESS of what rules.conf ends up containing -- and,
    # separately, ALWAYS enables it (`deb-systemd-helper enable`, which is
    # not gated by invoke-rc.d/policy-rc.d at all). Block the START with a
    # temporary policy-rc.d shim -- the sanctioned Debian mechanism for
    # "install this service package without letting it start" -- then
    # explicitly force both units disabled+stopped afterward regardless of
    # what the postinst did. Verified empirically on this box:
    # without the shim, a fresh install starts the daemon with
    # whatever rules.conf happens to exist at that exact moment (the
    # package's own postinst auto-generates one via `usbguard
    # generate-policy` if none exists yet) -- harmless for currently
    # attached devices in practice (generate-policy allows everything
    # present), but not a guarantee this script should rely on, and not
    # "leave it disabled" either way.
    POLICY_RC_D=/usr/sbin/policy-rc.d
    _POLICY_RC_D_OURS=0
    if [[ ! -e "$POLICY_RC_D" ]]; then
        printf '%s\n' '#!/bin/sh' 'exit 101' > "$POLICY_RC_D"
        chmod 0755 "$POLICY_RC_D"
        _POLICY_RC_D_OURS=1
    fi
    _cleanup_policy_rc_d() {
        if [[ "$_POLICY_RC_D_OURS" -eq 1 && -e "$POLICY_RC_D" ]]; then
            rm -f "$POLICY_RC_D"
        fi
    }
    trap _cleanup_policy_rc_d EXIT

    apt-get install -y usbguard
    echo "usbguard package present (installed or already up to date)"

    _cleanup_policy_rc_d
    trap - EXIT

    # Belt-and-suspenders: whatever the package's postinst did (enable +
    # attempted start), force the end state to disabled+stopped every time
    # this script runs. Safe/idempotent -- disabling an already-disabled,
    # already-stopped unit is a no-op.
    # NOTE: if the operator has since deliberately enabled usbguard (the
    # documented later step), RE-RUNNING install.sh WILL
    # re-disable it -- re-enable it again afterward if so. This script does
    # not try to distinguish "never enabled" from "operator enabled it
    # deliberately"; it deliberately errs toward "never leave usbguard
    # running as a side effect of re-running the installer."
    systemctl disable --now usbguard.service >/dev/null 2>&1 || true
    systemctl disable --now usbguard-dbus.service >/dev/null 2>&1 || true
    echo "usbguard.service + usbguard-dbus.service forced disabled+stopped"

    # --- rules.conf + usbguard-daemon.conf -------------------------
    USBGUARD_RULES_SRC="$SRC/usbguard/rules.conf"
    USBGUARD_DAEMON_CONF_SRC="$SRC/usbguard/usbguard-daemon.conf"
    if [[ -f "$USBGUARD_RULES_SRC" && -f "$USBGUARD_DAEMON_CONF_SRC" ]]; then
        install -d -m 0755 -o root -g root /etc/usbguard
        install -m 0600 -o root -g root "$USBGUARD_RULES_SRC" /etc/usbguard/rules.conf
        install -m 0600 -o root -g root "$USBGUARD_DAEMON_CONF_SRC" /etc/usbguard/usbguard-daemon.conf
        echo "installed /etc/usbguard/rules.conf + usbguard-daemon.conf (0600, root:root)"
    else
        echo "warning: $USBGUARD_RULES_SRC or $USBGUARD_DAEMON_CONF_SRC not found -- skipped usbguard policy install" >&2
    fi

    # --- early-ordering override: Before=basic.target ("order early") ---
    USBGUARD_OVERRIDE_SRC="$SRC/usbguard/usbguard.service.d/10-ca-usb-early.conf"
    if [[ -f "$USBGUARD_OVERRIDE_SRC" ]]; then
        install -d -m 0755 -o root -g root /etc/systemd/system/usbguard.service.d
        install -m 0644 -o root -g root "$USBGUARD_OVERRIDE_SRC" /etc/systemd/system/usbguard.service.d/10-ca-usb-early.conf
        echo "installed /etc/systemd/system/usbguard.service.d/10-ca-usb-early.conf (Before=basic.target)"
    else
        echo "warning: $USBGUARD_OVERRIDE_SRC not found -- skipped usbguard early-ordering override" >&2
    fi
else
    echo "warning: apt-get not found on PATH -- skipped usbguard install entirely" >&2
fi

# --- modprobe.d: FS parser blacklist for genuinely =m modules ----
MODPROBE_SRC="$SRC/modprobe.d/ca-usb-blacklist.conf"
if [[ -f "$MODPROBE_SRC" ]]; then
    install -d -m 0755 -o root -g root /etc/modprobe.d
    install -m 0644 -o root -g root "$MODPROBE_SRC" /etc/modprobe.d/ca-usb-blacklist.conf
    echo "installed /etc/modprobe.d/ca-usb-blacklist.conf"
else
    echo "warning: $MODPROBE_SRC not found -- skipped modprobe.d blacklist install" >&2
fi

# --- reload systemd + udev so the NEXT insert uses the updated rule/unit ----
# Guarded (warn-and-continue, not `set -e`-fatal): a re-run of this script in
# a minimal/non-systemd test environment must not abort the anchor/dir/
# package provisioning above just because systemctl/udevadm aren't present.
#
# IMPORTANT / what these two reloads do and DON'T do: they make the updated
# unit + rule authoritative for the NEXT device-`add` event (a fresh insert
# or a reboot's coldplug). `udevadm control --reload-rules` reloads the rule
# file into the running udevd; `udevadm trigger` re-emits synthetic uevents
# for existing devices so DEVICE ATTRIBUTES/tags get reapplied. But `udevadm
# trigger` does NOT (re)start `ca-usb-job@<dev>` for a stick that is ALREADY
# inserted: its `dev-<dev>.device` unit is already active, so the
# SYSTEMD_WANTS dependency has nothing new to pull in, and the default
# action=change (even `--action=add`) won't re-activate an already-active
# device unit. Only a physical reinsert (or reboot) actually fires the job
# for a currently-plugged stick. This is fine for the normal flow (rule/unit
# are installed while nothing is inserted), but matters for the documented
# real-anchors re-run before air-gap -- hence the end-of-run reminder below.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    echo "systemctl daemon-reload done"
    # Enable the boot-reconcile oneshot so restart recovery runs on
    # every boot (idempotent -- enabling an already-enabled unit is a no-op).
    # Guarded so a minimal/chroot env (or a systemctl that refuses to enable
    # offline) warns rather than aborts the whole install, matching the
    # warn-and-continue posture of the reload steps.
    if [[ -f "$RECONCILE_UNIT_DEST" ]]; then
        if systemctl enable ca-usb-reconcile.service >/dev/null 2>&1; then
            echo "enabled ca-usb-reconcile.service (runs reconcile on every boot)"
        else
            echo "warning: could not enable ca-usb-reconcile.service (enable it manually)" >&2
        fi
    fi
else
    echo "warning: systemctl not found on PATH -- skipped daemon-reload" >&2
fi

if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules
    udevadm trigger
    echo "udevadm control --reload-rules && udevadm trigger done"
else
    echo "warning: udevadm not found on PATH -- skipped udev reload/trigger" >&2
fi

echo
echo "install.sh complete."
echo "  box-name:          $BOX_NAME"
echo "  state/ca/results:  $STATE_DIR, $CA_DIR, $RESULTS_DIR (root:root 0700)"
echo "  audit log:         $AUDIT_LOG (0600 root:root, append-only)"
echo "  registry.json:     $REGISTRY (0644 root:root if just created; content preserved if present)"
echo "  anchors:           $ALLOWED (0644) / $BREAKGLASS (0444)"
echo "  backup recipient:  $BACKUP_RECIPIENT"
echo "  causb package:     $LIB_DEST"
echo "  handlers:          $HANDLERS_DEST"
echo "  recovery source:   $RECOVERY_DEST (caj/caj-recv + causb closure + templates)"
echo "  flock dir:         /run/ca-usb (0700, via tmpfiles.d)"
echo "  ca-usb-run:        $RUN_DEST (S7 lifecycle orchestrator)"
echo "  systemd unit:      $UNIT_DEST"
echo "  reconcile unit:    $RECONCILE_UNIT_DEST (enabled; R7/D22 boot recovery)"
echo "  udev rule:         $UDEV_DEST"
echo "  usbguard policy:   /etc/usbguard/rules.conf + usbguard-daemon.conf (0600)"
echo "  usbguard ordering: /etc/systemd/system/usbguard.service.d/10-ca-usb-early.conf"
echo "  fs blacklist:      /etc/modprobe.d/ca-usb-blacklist.conf"
echo
echo "NOTE: if a USB stick is currently inserted, reinsert it (or reboot) for"
echo "the updated udev rule / systemd unit / ca-usb-run binary to take effect."
echo "A post-install 'udevadm trigger' canNOT re-fire ca-usb-job@<dev> for an"
echo "already-plugged device -- only a fresh insert or a reboot's coldplug does."
echo
echo "REMINDER: if the anchors just installed are bring-up/dummy keys, re-run"
echo "this script with the REAL --primary-pub/--breakglass-pub/--age-recipient"
echo "before air-gapping the box (design doc S14)."
echo
# `systemctl is-enabled`/`is-active` exit non-zero for "disabled"/"inactive"
# (that's the expected, desired result here) -- `|| true` only neutralizes
# the exit code for `set -e`'s sake; it must NOT also print a fallback
# string, since the command already printed the real state word to stdout
# before returning that non-zero code (an earlier version of this line used
# `|| echo 'disabled'`, which double-printed both words concatenated).
USBGUARD_ENABLED_STATE="$(systemctl is-enabled usbguard 2>/dev/null || true)"
USBGUARD_ACTIVE_STATE="$(systemctl is-active usbguard 2>/dev/null || true)"
echo "NOTE: usbguard.service and usbguard-dbus.service are installed but LEFT"
echo "DISABLED/STOPPED (${USBGUARD_ENABLED_STATE:-disabled}/${USBGUARD_ACTIVE_STATE:-inactive})."
echo "Enabling USBGuard is a DELIBERATE operator step, taken only with the"
echo "serial console available as a fallback (design doc S19 R11) -- a wrong"
echo "policy could strand the box's only I/O. See"
echo "box/usbguard/README-authorized-default.md and"
echo "tests/integration/13-usbguard.md before running:"
echo "    sudo systemctl enable --now usbguard"
