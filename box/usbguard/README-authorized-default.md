# `usbcore.authorized_default=0` — OPTIONAL, NOT applied

**Status: documented only. Not installed, not attempted, no partition on
this box has been touched.** This note exists so the operator can make an
informed decision later; this project deliberately stops short of doing this.

## What it would do

`usbcore.authorized_default=0` on the kernel command line makes newly
enumerated USB devices start **deauthorized** at the kernel level — nothing
talks to a new device (no driver binds, no block/input node appears) until
something explicitly authorizes it. This was originally considered as
a second layer under USBGuard.

## Why this box makes it hard: no extlinux, no uEnv.txt

Most Debian-on-ARM boards take a kernel cmdline edit via a plain text file
(`/boot/extlinux/extlinux.conf`, `/boot/uEnv.txt`, or similar) that a normal
`sudo $EDITOR` handles safely, with the old file trivially recoverable from
a backup copy. **This board is not that.** Verified directly on
`nebula-ca`:

```
$ ls -la /boot
total 12
drwxr-xr-x 2 root root 4096 ... .
drwxr-xr-x 1 root root 4096 ... ..
```

`/boot` is completely empty — there is no extlinux/uEnv file to edit at
all. The live cmdline (`cat /proc/cmdline`, captured 2026-07-13):

```
storagemedia=emmc androidboot.storagemedia=emmc androidboot.mode=normal
androidboot.dtbo_idx=0 androidboot.verifiedbootstate=orange
earlycon=uart8250,mmio32,0xff9f0000 console=ttyFIQ0 coherent_pool=1m rw
root=/dev/mmcblk2p8 rootfstype=ext4 rootflags=discard data=/dev/mmcblk2p9
consoleblank=0 cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory
swapaccount=1 androidboot.fwver=ddr-v1.10-...
```

This is a FriendlyELEC/Rockchip **Android-style GPT eMMC layout**, not a
generic Debian boot layout — confirmed partitions on `/dev/mmcblk2`:

```
mmcblk2     58.2G disk
|-mmcblk2p1    4M  uboot
|-mmcblk2p2    4M  misc
|-mmcblk2p3    4M  dtbo
|-mmcblk2p4   16M  resource
|-mmcblk2p5   40M  kernel
|-mmcblk2p6   32M  boot
|-mmcblk2p7   32M  recovery
|-mmcblk2p8  1.7G  rootfs
`-mmcblk2p9 56.4G  userdata
```

The `androidboot.*` args and the `console=ttyFIQ0`/`earlycon=...` values are
signatures of Rockchip's U-Boot reading a fixed boot configuration early in
boot, from either (a) a dedicated Rockchip **`parameter`** region (a
proprietary partition-table-plus-cmdline blob U-Boot parses before Linux
even starts, historically manipulated with `rkdeveloptool`/`upgrade_tool`'s
`pl`/parameter read-write commands or community `mkimage`/parameter-editing
scripts), or (b) a cmdline string baked into the **Android boot image
header** on the `kernel`/`boot` partition (unpacked/repacked with
`unpack_bootimg`/`mkbootimg`/`abootimg`). **This has not been determined for
this specific FriendlyELEC image** — doing so needs
Rockchip vendor tooling this box doesn't have installed, and guessing
wrong means writing to the wrong raw region of eMMC. That determination is
exactly the first step of the procedure below, not something to skip.

## If an operator decides to do this anyway

1. **Identify the mechanism first, non-destructively.** Before writing
   anything: get FriendlyELEC's NanoPi NEO3 Plus firmware/BSP docs for this
   exact image build and confirm whether cmdline lives in a `parameter`
   region or the boot image header. Cross-reference against the partition
   table above (`kernel` vs `boot` as separate 40M/32M partitions is
   somewhat non-standard for a plain Android boot.img layout, which
   normally combines kernel+ramdisk+cmdline into one `boot` partition —
   this split is a hint, not a confirmation).
2. **Full offline backup before touching anything.** Image the *entire*
   eMMC (or at minimum every candidate partition: `uboot`, `misc`, `kernel`,
   `boot`, `resource`) to a file **on another machine**, e.g. via
   `dd if=/dev/mmcblk2 of=nebula-ca-emmc-full-backup.img bs=4M status=progress`
   copied off-box immediately (this box has no spare local storage to trust
   for its own backup). Verify the backup is readable before proceeding.
3. **Edit only the cmdline field**, appending `usbcore.authorized_default=0`
   to the existing string above (do not remove or reorder any existing
   argument — `root=`, `rootfstype=`, `data=`, and the `androidboot.*` args
   are all load-bearing for this board's boot process).
4. **Write back, then test with the serial console already connected and
   watched live** — do not reboot blind. `serial-getty@ttyFIQ0` is retained
   and NOT masked at air-gap specifically for this kind of recovery
   (confirmed on this box: `systemctl is-enabled serial-getty@ttyFIQ0`
   → `enabled-runtime`, `is-active` → `active`, 2026-07-13). If the board
   fails to boot, the fallback is Rockchip **Maskrom mode** + a full
   re-flash from the backup image in step 2 — have the FriendlyELEC
   flashing tool and cable ready *before* the reboot, not after.
5. **After a successful boot**, confirm `cat /proc/cmdline` shows the new
   argument, and confirm the CA-XFER stick still enumerates to `sda1`
   (root hubs are exempt from `authorized_default`, and USB-A on this board
   goes directly to a root hub with no on-board hub in between — so
   the stick itself shouldn't be affected either way, but confirm rather
   than assume).

## Why this is low-value here (do it only if you want belt-and-suspenders)

**USBGuard already closes the actual runtime threat this parameter targets,
the moment the operator enables it (a separate, deliberate step — see
`box/usbguard/rules.conf` / `usbguard-daemon.conf`).** The shipped
`usbguard-daemon.conf` this project installs ships with (unchanged from
upstream default) `AuthorizedDefault=none`: once `usbguard.service`
actually starts, USBGuard itself sets every USB controller's
`authorized_default` to "deauthorize new devices by default" — the exact
same kernel mechanism the `usbcore.authorized_default=0` boot parameter
would set, just applied by the running daemon instead of by the boot
loader — and (`RestoreControllerDeviceState=false`, also unchanged) does
**not** revert that on shutdown. Verified directly on this box: after a
brief live `usbguard-daemon` run, `cat
/sys/bus/usb/devices/usb{1,2,3,4}/authorized_default` read back `0` on all
four controllers (the immediate remediation was to set them back to `1`)
— concrete, on-box proof that
`AuthorizedDefault=none` really does flip this exact knob at runtime,
without any kernel cmdline parameter involved at all.

So the **only** gap the boot parameter would additionally close is the
narrow window between `usbcore` initializing early in boot and
`usbguard.service` actually starting later in the same boot — and only
matters for a device plugged in during that specific window, on a box that:

- has no keyboard/mouse/monitor attached in normal operation (headless,
  USB-A is the only I/O and it's reserved for the CA-XFER stick),
- is not rebooted routinely (this is an air-gapped CA appliance, not a
  desktop),
- already has the CA-XFER stick's own device authorized via its
  device-specific `rules.conf` baseline line regardless of when USBGuard
  starts relative to insertion (`PresentDevicePolicy=apply-policy`).

Given that, and given the real risk profile above (a raw eMMC boot-region
edit on a board with no extlinux/uEnv safety net, on the ONLY air-gapped CA
box), this is treated as **operator-optional, documented, not applied**.
If the operator later wants it
anyway (e.g. for defense against a threat model that includes "attacker
gets physical access during the specific boot window before usbguard
starts"), this file is the starting checklist; do it deliberately, with the
serial console open and watched, and the eMMC backup verified first.
