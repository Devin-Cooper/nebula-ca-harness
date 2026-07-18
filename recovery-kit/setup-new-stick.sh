#!/bin/sh
# setup-new-stick.sh -- turn a raw USB stick into a Nebula CA job stick.
#
# Creates an MSDOS (MBR) partition table + ONE primary vfat partition on the
# target block device, then makes inbox/ and outbox/ on it.
#
# The partition table is REQUIRED: the box's udev rule triggers on a
# PARTITION (e.g. /dev/sda1), so a raw "superfloppy" (mkfs written straight
# onto /dev/sda with no partition table) will NOT be picked up by the box.
#
# LINUX ONLY. Needs: parted, mkfs.vfat (dosfstools), mount. Run as root.
# THIS DESTROYS ALL DATA on the target device.
#
# Usage:  sudo ./setup-new-stick.sh /dev/sdX
#
# There is NO default device: naming the wrong device destroys it, so you
# MUST pass the target explicitly.
set -eu

PROG="$(basename "$0")"

die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 1; }

DEV="${1:-}"
[ -n "$DEV" ] || die "no target device given.
Usage: sudo $PROG /dev/sdX   (names YOUR stick; there is no default)."

[ "$(id -u)" = "0" ] || die "must run as root:  sudo $PROG $DEV"
[ -b "$DEV" ]        || die "$DEV is not a block device."

command -v parted    >/dev/null 2>&1 || die "parted not found (install 'parted')."
command -v mkfs.vfat >/dev/null 2>&1 || die "mkfs.vfat not found (install 'dosfstools')."

# Derive the partition node name: a disk name ending in a digit needs a 'p'
# separator (mmcblk0 -> mmcblk0p1, nvme0n1 -> nvme0n1p1); otherwise just
# append 1 (sdb -> sdb1). Never hardcodes a device.
case "$DEV" in
    *[0-9]) PART="${DEV}p1" ;;
    *)      PART="${DEV}1"  ;;
esac

printf '\n'
printf '  !!  WARNING: THIS WILL DESTROY ALL DATA ON  %s  !!\n' "$DEV"
printf '\n'
if command -v lsblk >/dev/null 2>&1; then
    lsblk -o NAME,SIZE,MODEL,MOUNTPOINT "$DEV" 2>/dev/null || true
    printf '\n'
fi
printf 'This creates an MBR partition table + one vfat partition (%s)\n' "$PART"
printf 'with inbox/ and outbox/. Everything on %s will be ERASED.\n\n' "$DEV"
printf 'Type  ERASE  (all caps) to continue, anything else to abort: '
read -r CONFIRM
[ "$CONFIRM" = "ERASE" ] || die "aborted (you did not type ERASE)."

printf '\n==> unmounting any existing partitions on %s (best effort)\n' "$DEV"
for p in "$DEV"*; do
    [ -b "$p" ] || continue
    umount "$p" 2>/dev/null || true
done

printf '==> writing MSDOS partition table + one primary vfat partition\n'
parted -s "$DEV" mklabel msdos
parted -s "$DEV" mkpart primary fat32 1MiB 100%

# Let the kernel/udev create the partition node before we format it.
command -v partprobe >/dev/null 2>&1 && partprobe "$DEV" 2>/dev/null || true
command -v udevadm   >/dev/null 2>&1 && udevadm settle 2>/dev/null   || true

i=0
while [ ! -b "$PART" ] && [ "$i" -lt 10 ]; do
    sleep 1
    i=$((i + 1))
done
[ -b "$PART" ] || die "partition $PART did not appear after partitioning $DEV."

printf '==> formatting %s as vfat (FAT32), label CA-XFER\n' "$PART"
mkfs.vfat -F 32 -n CA-XFER "$PART"

printf '==> creating inbox/ and outbox/\n'
MNT="$(mktemp -d)"
trap 'umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true' EXIT
mount "$PART" "$MNT"
mkdir -p "$MNT/inbox" "$MNT/outbox"
sync
umount "$MNT"
rmdir "$MNT"
trap - EXIT

printf '\n==> done. %s now has a vfat partition %s with inbox/ and outbox/.\n' "$DEV" "$PART"
printf '    Build a job onto it:  ./caj build --spec <spec> --stick <mountpoint>\n'
