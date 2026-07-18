# Deferred: enabling USBGuard

The scope here is explicit: **write and validate only — do not enable
USBGuard or reboot.** Everything that can be proven safely (package
install, policy generation/syntax, the CA-XFER stick's ALLOW coverage,
which FS-parser modules are actually blacklistable, confirming
`usbguard.service` stays disabled) has been done. What's below is
specifically the part that requires *actually flipping the enforcement
switch* on the box's only I/O path — deliberately deferred to
the operator, done with the serial console open and watched, never
unattended.

Record date/operator/result inline as each item is run.

## Before enabling: pre-flight

- [ ] Physical/serial access confirmed available and OPEN (a second
      terminal on `serial-getty@ttyFIQ0`, logged in as `<operator>`)
      *before* running anything below — this is the rescue path if a rule
      turns out to be wrong. Confirmed present and NOT masked as
      of 2026-07-13 (`systemctl is-enabled/is-active serial-getty@ttyFIQ0`
      → `enabled-runtime` / `active`); re-confirm on the day, since
      air-gapping happens after this.
- [ ] The CA-XFER stick is inserted (so `PresentDevicePolicy=apply-policy`
      evaluates it against the installed baseline immediately on daemon
      start, per `box/usbguard/rules.conf`'s provenance comment) — or
      deliberately NOT inserted, if the operator wants to test cold-insert
      authorization instead of present-at-start authorization. Either is a
      valid drill; pick one knowingly rather than by accident.
- [ ] `systemctl cat usbguard.service` reviewed one more time immediately
      before enabling (confirms no unexpected drift from what
      `install.sh` last wrote) — cheap, and this is the point of no return
      for this box's enforcement posture.

## Enable + verify (the core enforcement gate)

- [ ] `sudo systemctl enable --now usbguard` — the one deliberate step this
      whole task exists to gate. Watch `journalctl -u usbguard -f` in a
      third terminal during this and the next few steps.
- [ ] **The CA-XFER stick still enumerates → `sda1` appears** (`lsblk`,
      `ls /dev/sda1`). This is the load-bearing assertion: the
      device-specific `allow id <VID:PID> serial "<...>" hash "<...>"` baseline
      line you pinned in `rules.conf` (or, if you pinned none, the class rule
      `allow with-interface equals { 08:*:* }`) must authorize it. If it does
      NOT appear: **do not
      reboot, do not unplug** — go straight to the serial console,
      `sudo systemctl disable --now usbguard`, and file a bug against
      `box/usbguard/rules.conf` before retrying.
- [ ] `sudo usbguard list-devices` shows the stick with target `allow` (not
      `block`, and definitely not absent/rejected).
- [ ] `mount -t vfat -o ro,noexec,nosuid,nodev /dev/sda1 <mp>` still
      succeeds (confirms USBGuard authorization and the pinned-mount
      path compose cleanly — this is the same mount step
      `causb.mountctl`/`ca-usb-run` will use).
- [ ] Plug in a USB keyboard (or mouse) → **REJECTED**. Confirm via
      `sudo usbguard list-devices` (device absent or shown rejected — a
      `reject` target removes it from the system entirely, so "not
      listed" is the expected positive result) and
      `journalctl -u usbguard` showing a reject decision matching either
      the `reject with-interface one-of { 03:*:* }` line or the
      `reject with-interface all-of { 08:*:* 03:*:* }` composite line if
      the test device is a combo. No input device node should appear
      (`ls /dev/input/by-id/` before/after comparison).
- [ ] Unplug the keyboard, re-plug it a second time → still rejected
      (confirms the rule, not a one-time race, is what's deciding this).
- [ ] **Re-confirm SuperSpeed enumeration is unaffected.** With the stick
      already proven working above at `5000M` (`lsusb -t` showing
      `Driver=usb-storage, 5000M`), re-run `lsusb -t` once more after the
      keyboard test to confirm the stick's own entry is untouched by the
      unrelated keyboard reject decision (no shared-bus side effects).
      This box's `uas` driver is confirmed BUILT-IN (kernel 6.1.141; see
      `box/modprobe.d/ca-usb-blacklist.conf`), so there is no UAS→BOT
      fallback question to separately test here — `usb-storage` binding
      the device (as already shown) is the only path that exists on this
      kernel.

## Boot-time coldplug (optional, needs a reboot)

Do this together with the `authorized_default=0` drill below, if that is
also being done, to save a reboot cycle.

- [ ] Reboot with the stick already inserted and `usbguard.service`
      enabled → confirm it comes up enabled (`systemctl is-enabled
      usbguard` → `enabled`) and the stick still authorizes to `sda1` on
      this fresh boot (not just "was already authorized before the
      daemon restarted" — a genuine coldplug-time policy evaluation).
      Serial console watched throughout, per the pre-flight item above.

## OPTIONAL, separate decision: `usbcore.authorized_default=0`

**Not part of the above gate.** See
`box/usbguard/README-authorized-default.md` in full before attempting —
this requires editing a Rockchip boot-configuration region on a board with
**no extlinux/uEnv safety net** (verified: `/boot` is empty), carries real
brick/strand risk, and — per that doc's own analysis, backed by an
on-box-verified finding that `AuthorizedDefault=none` in
`usbguard-daemon.conf` already makes the *running* daemon set every
controller's `authorized_default` to the same deauthorize-by-default state
at startup — only closes the narrow pre-`usbguard.service` boot window.
Treat as a separate, later, deliberate decision, not a follow-on to the
steps above.

- [ ] (If pursued) Full eMMC/candidate-partition backup taken and verified
      OFF-BOX first.
- [ ] (If pursued) Mechanism identified (parameter region vs boot image
      header) before any write.
- [ ] (If pursued) Cmdline edited, written back, and the FIRST reboot
      after the edit done with the serial console open and watched live,
      FriendlyELEC Maskrom recovery tooling staged and ready beforehand.
- [ ] (If pursued) Post-boot: `cat /proc/cmdline` shows the new argument;
      CA-XFER stick still enumerates to `sda1`.

## Out of scope for this checklist

Everything provable without enabling the daemon or rebooting (package
install, `generate-policy` baseline capture + the stick-match proof,
`rules.conf`/`usbguard-daemon.conf` static validation, the `=m`/`=y`/absent
module classification, confirming `usbguard.service` starts out
disabled) has already been done and is not repeated here. The
`authorized_default=none` / `RestoreControllerDeviceState=false`
live-daemon finding referenced above (and the immediate remediation back
to `authorized_default=1`) was found during that work — it's why this
checklist's pre-flight insists on the serial console being open before the
very first `enable --now`, not just before the optional cmdline drill.
