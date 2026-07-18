"""Headless feedback via the kernel `timer` LED trigger (S7.9, S9, R4).

The design's original plan (S9/D13) called for the `ledtrig-pattern`
trigger so multi-pulse rhythms ("3 blinks then hold", SOS) could be driven
entirely kernel-side. **Verified absent on this box's kernel** (6.1.141):
`/sys/class/leds/user_led/trigger`'s list of available triggers has no
"pattern" entry. R4 is the authoritative fallback: drive `user_led` via the
`timer` trigger instead, using only symmetric on/off rates (`delay_on` ==
`delay_off` for every rhythm) since `timer` cannot express an asymmetric or
multi-pulse pattern. This module implements exactly R4's six states; the
richer states from the design's S9 table (SUCCESS's "3 pulses", ERROR's
"SOS group", BUSY, RECOVERY-OFFER/WRITE) are out of this task's scope --
R4 itself folds SUCCESS into the held SAFE_REMOVE rhythm, and the others
aren't in this module's required interface.

Per state, `set()` writes to `/sys/class/leds/user_led/{trigger,delay_on,
delay_off,brightness}` -- NEVER `sys_led` (left alone; it stays the
system's genuine "not hung" heartbeat, S9). Two state shapes:

- `trigger=timer` + `delay_on`/`delay_off` (both in milliseconds) for every
  rhythmic state (VERIFYING/READY/ERROR/SAFE_REMOVE) -- driven kernel-side,
  so the pattern persists even if the userspace process dies (D13's whole
  reason for choosing a kernel trigger over e.g. a Python thread that
  toggles `brightness` in a sleep loop).
- `trigger=none` + `brightness` (0 or 1) for the two non-rhythmic states,
  IDLE (off) and RUNNING (solid on) -- `timer`'s `delay_on`/`delay_off`
  sysfs files only EXIST while `trigger==timer` is selected, and manual
  `brightness` writes are only honored once the trigger is `none` -- so
  `trigger` must always be written FIRST, before any rate/brightness
  attribute, whenever it needs to change. `plan()` always orders it that
  way.

`plan(state)` is a pure function (no I/O) returning the ordered
`(attribute, value)` tuples for a state -- this is what unit tests exercise
directly, with no filesystem involved at all. `set()` applies a plan to a
real directory (`led_dir`, defaulting to the real sysfs path; injectable
for tests to point at a fake directory) via an injectable `writer` (for
tests to record call order without touching any filesystem, real or fake).
Real-hardware read-back (the actual LED visibly blinking at the right
rate) is exercised by `tests/integration/hw_root.py`, run as root on the
box.
"""

import os

LED_DIR = "/sys/class/leds/user_led"

IDLE = "IDLE"
VERIFYING = "VERIFYING"
READY = "READY"
RUNNING = "RUNNING"
ERROR = "ERROR"
SAFE_REMOVE = "SAFE_REMOVE"
BUSY = "BUSY"

# Recovery-branch states (S7A / S9's "RECOVERY-OFFER / WRITE" row / R8), added
# by the orchestrator (ca-usb-run) exactly as it added BUSY: the orchestrator's
# own state machine needed them, so they were out of scope until a caller
# actually drove them. `causb.recovery.write()` is pure filesystem logic and
# owns none of this; the orchestrator owns the LED/K1 choreography (see
# tests/integration/15-recovery.md, which explicitly defers these rhythms to
# the orchestrator). Same R4 mechanism (timer trigger, symmetric rate, no multi-pulse
# the absent `pattern` trigger would need): three MORE distinct rates so a
# human watching the single physical user_led can tell "blank stick, press to
# write the kit" (OFFER) from "press again NOW to also include the sensitive
# registry" (CONFIRM2, R8's "distinct second confirmation ... surfaced by a
# distinct LED") from "writing the kit" (WRITE) -- and every one of them from
# READY/ERROR/VERIFYING/SAFE_REMOVE/BUSY.
RECOVERY_OFFER = "RECOVERY_OFFER"
RECOVERY_CONFIRM2 = "RECOVERY_CONFIRM2"
RECOVERY_WRITE = "RECOVERY_WRITE"

# Rates (revised 2026-07-16 for human discernibility -- operators reliably read
# RHYTHM CONTRAST, not fine frequency differences, and this single physical LED
# can only do symmetric on/off rates since the kernel `pattern` trigger is
# absent). The two HELD terminals are pushed to OPPOSITE EXTREMES so success vs
# failure is unmistakable at a glance: SAFE_REMOVE a slow, calm 0.5 Hz (1000 ms)
# held blink ("done, pull it") vs ERROR a frantic 10 Hz (50 ms) flicker
# ("refused") -- ~20x apart. READY is a fast 4 Hz (125 ms) "act now, press K1"
# (clearly distinct from ERROR's flicker); VERIFYING a brief ~1.5 Hz (330 ms)
# "checking", deliberately moved OFF the old slow 0.5 Hz so it can never be
# mistaken for the held SAFE_REMOVE; RUNNING solid ("working"); IDLE off. The
# held states persist after ExecStart exits (via RemainAfterExit/BindsTo at the
# systemd-unit layer, S19 R3 -- out of this module's scope; this module only
# has to get the sysfs attributes right). "trigger" is always the FIRST tuple
# -- see module docstring for why the write order matters on real sysfs.
#
# BUSY (added later, ca-usb-run's flock-contention path): the design's
# S9 table lists BUSY ("2nd instance", flock contention) as its own row, but
# this module's original R4 scope deliberately implemented only
# the six states the harness's OWN state machine drives directly -- BUSY was
# out of scope until a caller (ca-usb-run) actually needed it. Same R4
# mechanism (timer trigger, symmetric rate, no multi-pulse) applies: 2 Hz
# (250 ms/250 ms) is a rate distinct from every other job-flow state above
# (VERIFYING 1.5 / READY 4 / ERROR 10 / SAFE_REMOVE 0.5 Hz) so a busy-contention
# blink can never be mistaken for them by a human watching the single physical
# user_led.
_PLANS = {
    IDLE: (("trigger", "none"), ("brightness", "0")),
    VERIFYING: (("trigger", "timer"), ("delay_on", "330"), ("delay_off", "330")),
    READY: (("trigger", "timer"), ("delay_on", "125"), ("delay_off", "125")),
    RUNNING: (("trigger", "none"), ("brightness", "1")),
    ERROR: (("trigger", "timer"), ("delay_on", "50"), ("delay_off", "50")),
    SAFE_REMOVE: (("trigger", "timer"), ("delay_on", "1000"), ("delay_off", "1000")),
    BUSY: (("trigger", "timer"), ("delay_on", "250"), ("delay_off", "250")),
    # Recovery rhythms, distinct from each other and (by exact value)
    # from every job-flow rate above; the recovery flow is a SEPARATE blank-stick
    # context never seen alongside a job, so a cross-context near-neighbour is
    # harmless. Left at these values this pass (2026-07-16 focused on the
    # job-flow states the operator hit); tune at the recovery gate step if the
    # three still blur. OFFER ~0.67 Hz (750), CONFIRM2 ~3.3 Hz (150), WRITE
    # ~1.4 Hz (350).
    RECOVERY_OFFER: (("trigger", "timer"), ("delay_on", "750"), ("delay_off", "750")),
    RECOVERY_CONFIRM2: (("trigger", "timer"), ("delay_on", "150"), ("delay_off", "150")),
    RECOVERY_WRITE: (("trigger", "timer"), ("delay_on", "350"), ("delay_off", "350")),
}


class LedError(Exception):
    """Writing a `user_led` sysfs attribute failed. `reason` is always
    "led_write_failed" -- a fixed, single value (unlike mountctl/verify's
    multi-reason enums) since there is exactly one way this module fails:
    an OSError from the underlying attribute write.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def plan(state):
    """Pure: return the ordered `(attribute, value)` tuples `set()` would
    write for `state`. Raises `ValueError` for an unrecognized state (a
    caller/typo bug, not a device failure -- mirrors
    `causb.verify._require_absolute`'s treatment of a bad anchor path).
    """
    if state not in _PLANS:
        raise ValueError(f"unknown LED state: {state!r}")
    return _PLANS[state]


def _default_writer(path, value):
    with open(path, "w") as f:
        f.write(value)


# NOTE: this module-level `set` intentionally shadows the builtin `set`
# (the collection type) for the REST OF THIS FILE -- the brief's specified
# interface is `led.set(state)`, called qualified by importers, so it never
# collides with the builtin at any call site outside this module. This
# module itself never needs the builtin collection type.
def set(state, led_dir=LED_DIR, writer=None):
    """Drive `user_led` into `state` (S7.9/S9/R4); `sys_led` is never
    touched. `led_dir`/`writer` are injectable purely for testing (a fake
    directory, and/or a call-recording stub) -- production callers use the
    defaults, which write to the real sysfs attribute files. Raises
    `LedError("led_write_failed")` if any attribute write fails. Returns
    None on success.
    """
    write = writer if writer is not None else _default_writer
    for name, value in plan(state):
        path = os.path.join(led_dir, name)
        try:
            write(path, value)
        except OSError as exc:
            raise LedError("led_write_failed") from exc
