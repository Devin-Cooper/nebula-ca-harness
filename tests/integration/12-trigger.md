# Deferred physical confirmations — USB trigger, button, removal

These require a real USB stick and a human finger on K1 -- no loopback
image, synthetic device, or `systemd-run` transient sandbox can stand in
for either. They are **not** blocking: `tests/unit/` (173/173,
reproduced 3x on the box) proves `causb.led`/`causb.button`/`ca-usb-run`'s
own logic and exit-code contract; `systemd-analyze verify` proves the unit
file itself is well-formed; a `systemd-run` transient unit carrying the
EXACT sandbox properties proves mount(8)/`user_led`/evdev/`flock` all work
under that sandbox (plus three negative-control runs that independently
reproduce each of the three DO-NOT-USE failures the design warns about);
and, in place of a real stick, two REAL loopback partitions + the actual
installed `ca-usb-job@.service` + `ca-usb-run` were used to verify
`BindsTo=dev-%i.device` stopping mid-run, `ExecStopPost` resetting the LED
and releasing the flock, and two concurrent instances actually serializing
(second instance busy, first untouched). What remains below is specifically
the part none of that can stand in for: a human, a real stick, and a real
finger.

Record date/operator/result inline as each item is run.

## Trigger — real stick insertion

- [ ] Insert a real, blank (unlabeled) FAT32/vfat-formatted USB stick ->
      `ca-usb-job@<dev><partN>.service` auto-starts (`journalctl -u
      'ca-usb-job@*'` shows `Starting ...`) via the udev rule's
      `SYSTEMD_WANTS` -- this is the one link in the chain that could not be
      exercised at all without real USB hardware: `udevadm test` against
      this box's real, currently-plugged USB stick (`sda1`, real `SUBSYSTEMS
      =="usb"`, real `DEVTYPE=="partition"`) confirmed every OTHER clause in
      the rule matches for a genuine USB partition and the rule correctly
      does NOT fire because that stick happens to be exFAT, not vfat --
      i.e. the rule's discrimination logic is proven, but nothing exercised
      the actual `SYSTEMD_WANTS` firing end-to-end against a real USB+vfat
      combination (repartitioning/reformatting the box's already-plugged
      stick to prove that last step felt like the wrong call to make
      unilaterally -- it may hold operator data).
- [ ] LED -> READY (fast ~5 Hz) immediately after insertion.
- [ ] A SECOND real stick inserted while the first is still being handled ->
      its own instance sees the flock held -> BUSY LED, `journalctl` shows
      "busy; touching no state", first instance completely unaffected. (The
      serialization MECHANISM itself -- real flock, real concurrent
      `ca-usb-job@` instances, real LED/journal output -- was already
      verified above with two loopback partitions; this
      item is just confirming the same thing reads correctly with two
      actual sticks in actual USB ports.)

## Button — real K1 press against the real running unit

- [ ] Press-and-release K1 within 60 s of READY -> LED -> RUNNING (solid)
      briefly -> SAFE_REMOVE (held ~1 Hz even blink). This is the one
      button.await_press() outcome the deferred checklist in
      `tests/integration/10-hw.md` could not close either (a synthetic
      uinput press can't be given the production name `gpio-keys` without
      colliding with the box's real device, so `resolve_k1_path()`'s
      unfiltered, production name+capability check has only ever been
      exercised against the real device's IDENTITY, never a real live
      press-release transition all the way through `ca-usb-run`).
- [ ] No press within 60 s -> LED -> ERROR (rapid ~10 Hz), held until the
      stick is removed. (The TIMING/exit-code/hold mechanics of this path
      were fully verified without a real button by mocking
      `causb.button.await_press` to return `False` -- see
      `tests/unit/test_ca_usb_run.py`'s `test_timeout_path_...` -- what's
      left is only the real 60 s wait against a real unpressed K1.)

## Removal — BindsTo + ExecStopPost against a real stick

- [ ] Pull the stick after SAFE_REMOVE (held) -> unit stops (`BindsTo=
      dev-%i.device`) -> `ExecStopPost` resets LED to IDLE. The MECHANISM
      (device disappears -> BindsTo stops the unit -> ExecStopPost fires,
      resets LED, releases the flock) was already verified end-to-end on
      this box using a real loopback partition device (detached mid-run via
      `losetup -d`, confirmed via `journalctl` showing `code=killed,
      status=15/TERM` then the LED/flock reset).
      This item is confirming the same thing for a literal physical
      removal, where the "device disappears" signal comes from the real
      USB subsystem's disconnect path rather than `losetup -d`.
- [ ] A mid-run yank (pull before K1 press, or before SAFE_REMOVE) also
      stops the unit and cleans up (LED -> IDLE, tmpfs wiped) -- same
      caveat as above; the mechanism is proven, the literal physical yank
      is not yet.

## Boot-with-stick (coldplug)

- [ ] Insert a stick, then power-cycle/reboot the box with it still
      inserted -> udev's boot-time coldplug replay re-emits an "add" event
      for the already-present device -> `ca-usb-job@<dev>.service` fires
      without a fresh hotplug event. Genuinely untested by anything in this
      task (needs an actual reboot with actual hardware attached); the
      udev rule itself has no coldplug-specific logic (coldplug is a udev/
      kernel property of how boot-time device enumeration replays "add"
      events, not something the rule file has to opt into), so this is a
      confirmation that the general mechanism applies here, not a new code
      path.

## USBGuard interaction

- [ ] Confirm this box's `usbcore.authorized_default=0` + USBGuard config
      still lets an allowed storage stick reach `drivers_probe` -> `sda1`
      -> this udev rule, i.e. that USBGuard's authorization step and this
      rule's trigger don't race or shadow each other on a cold insert. Out
      of scope here to configure, but worth one confirmation pass together
      with a real stick.

## Operator notes (not test steps — behavior to be aware of)

- **Re-running `install.sh` does NOT re-arm an already-inserted stick.**
  The post-install `udevadm control --reload-rules && udevadm trigger`
  makes the updated rule/unit/`ca-usb-run` authoritative for the NEXT
  device-`add` event only. It canNOT (re)start `ca-usb-job@<dev>` for a
  stick that is already plugged in: that device's `dev-<dev>.device` unit
  is already active, so nothing new pulls in the `SYSTEMD_WANTS`
  dependency, and `udevadm trigger`'s default action=change (even
  `--action=add`) will not re-activate an already-active device unit.
  **So: after any `install.sh` re-run that changes the rule/unit/binary
  (notably the documented real-anchors re-run before air-gap),
  physically reinsert any currently-plugged stick — or reboot — for the
  change to apply to it.** `install.sh` prints this reminder at the end of
  its run.

## Out of scope for this checklist

`README-OPERATOR.md`'s cold-human LED test, the real mount/verify/dispatch/
commit/deliver pipeline (which replaces `ca-usb-run`'s stub body), and
cert-format-specific behavior all belong to later stages of the project --
listed here only where this unit/rule/stub is a direct dependency.
