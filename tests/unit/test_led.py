"""Tests for causb.led: kernel `timer`-trigger LED feedback (S7.9/S9, R4).

The `pattern` trigger is verified ABSENT on this box's kernel (see the
design doc's rev-3 note and the task brief); R4 mandates the `timer`
trigger with distinct symmetric on/off rates instead. All tests here write
to a temp directory standing in for `/sys/class/leds/user_led/`, never the
real sysfs tree -- real-hardware read-back (the actual LED visibly blinking
at the right rate) is exercised separately by `tests/integration/hw_root.py`
under sudo on the box.
"""

import os
import tempfile
import unittest

from causb import led


class TestPlan(unittest.TestCase):
    """`led.plan(state)` is pure: no filesystem I/O at all. This is the
    "computes the right {trigger,delay_on,delay_off,brightness} per state"
    check the brief asks for, independent of how it's later applied."""

    def test_idle_is_off_via_trigger_none(self):
        assert led.plan(led.IDLE) == (("trigger", "none"), ("brightness", "0"))

    def test_verifying_is_medium_timer(self):
        # ~1.5 Hz (330 ms) -- moved off the old slow 0.5 Hz so it can't be
        # mistaken for the held SAFE_REMOVE (2026-07-16 discernibility remap).
        assert led.plan(led.VERIFYING) == (
            ("trigger", "timer"), ("delay_on", "330"), ("delay_off", "330"),
        )

    def test_ready_is_fast_timer(self):
        # 4 Hz (125 ms) "act now, press K1" -- distinct from ERROR's 10 Hz flicker.
        assert led.plan(led.READY) == (
            ("trigger", "timer"), ("delay_on", "125"), ("delay_off", "125"),
        )

    def test_running_is_solid_via_trigger_none(self):
        assert led.plan(led.RUNNING) == (("trigger", "none"), ("brightness", "1"))

    def test_error_is_ten_hz_timer(self):
        assert led.plan(led.ERROR) == (
            ("trigger", "timer"), ("delay_on", "50"), ("delay_off", "50"),
        )

    def test_safe_remove_is_slow_held_timer(self):
        # 0.5 Hz (1000 ms) held, calm "done" -- ~20x slower than ERROR's frantic
        # flicker, so success vs failure is unmistakable at a glance.
        assert led.plan(led.SAFE_REMOVE) == (
            ("trigger", "timer"), ("delay_on", "1000"), ("delay_off", "1000"),
        )

    def test_busy_is_four_hz_timer(self):
        # task 12: flock-contention state, added to led.py's original R4
        # six -- must be a rate distinct from all of them (checked below).
        assert led.plan(led.BUSY) == (
            ("trigger", "timer"), ("delay_on", "250"), ("delay_off", "250"),
        )

    def test_busy_rate_is_distinct_from_every_other_timer_state(self):
        rated_states = (led.VERIFYING, led.READY, led.ERROR, led.SAFE_REMOVE, led.BUSY)
        rates = [led.plan(s)[1] for s in rated_states]  # each state's ("delay_on", N)
        assert len(rates) == len(set(rates)), f"duplicate on/off rate among {rated_states}: {rates}"

    def test_recovery_states_are_distinct_symmetric_timers(self):
        # task 16 (S7A/S9 "RECOVERY-OFFER / WRITE" + R8's distinct-second-
        # confirmation LED): OFFER 750, CONFIRM2 150, WRITE 350 -- each a timer
        # trigger, symmetric on==off (the absent `pattern` trigger can't do
        # multi-pulse), first tuple `trigger`.
        assert led.plan(led.RECOVERY_OFFER) == (
            ("trigger", "timer"), ("delay_on", "750"), ("delay_off", "750"),
        )
        assert led.plan(led.RECOVERY_CONFIRM2) == (
            ("trigger", "timer"), ("delay_on", "150"), ("delay_off", "150"),
        )
        assert led.plan(led.RECOVERY_WRITE) == (
            ("trigger", "timer"), ("delay_on", "350"), ("delay_off", "350"),
        )

    def test_every_timer_state_rate_is_distinct(self):
        # Now that task 16 added three recovery rhythms, the whole set of
        # rhythmic states must still have pairwise-distinct rates so a human
        # watching the single user_led can never confuse two of them.
        timer_states = (
            led.VERIFYING, led.READY, led.ERROR, led.SAFE_REMOVE, led.BUSY,
            led.RECOVERY_OFFER, led.RECOVERY_CONFIRM2, led.RECOVERY_WRITE,
        )
        rates = [led.plan(s)[1] for s in timer_states]
        assert len(rates) == len(set(rates)), f"duplicate rate among {timer_states}: {rates}"

    def test_unknown_state_raises_value_error(self):
        with self.assertRaises(ValueError):
            led.plan("NOT_A_REAL_STATE")

    def test_trigger_always_written_before_any_rate_attribute(self):
        # Writing delay_on/delay_off before trigger=timer would fail on
        # real sysfs (those files don't exist until the timer trigger is
        # selected) -- so "trigger" must always be the first tuple.
        for state in (led.VERIFYING, led.READY, led.RUNNING, led.ERROR, led.SAFE_REMOVE, led.BUSY):
            p = led.plan(state)
            assert p[0][0] == "trigger", f"{state}: trigger must be written first"


class TestSet(unittest.TestCase):
    """`led.set(state, led_dir=...)` applies a plan to a real directory of
    files; tests point `led_dir` at a temp dir standing in for sysfs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-led-test-")
        # Pre-seed sentinels so a test can prove an attribute this state's
        # plan does NOT mention (e.g. delay_on/off for a trigger=none
        # state) is left untouched, not just absent.
        for name in ("trigger", "brightness", "delay_on", "delay_off"):
            with open(os.path.join(self.tmp, name), "w") as f:
                f.write("SENTINEL")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _read(self, name):
        with open(os.path.join(self.tmp, name)) as f:
            return f.read()

    def test_ready_writes_timer_trigger_and_rates(self):
        led.set(led.READY, led_dir=self.tmp)
        assert self._read("trigger") == "timer"
        assert self._read("delay_on") == "125"
        assert self._read("delay_off") == "125"

    def test_idle_writes_trigger_none_and_brightness_zero_leaving_rates_untouched(self):
        led.set(led.IDLE, led_dir=self.tmp)
        assert self._read("trigger") == "none"
        assert self._read("brightness") == "0"
        # IDLE's plan never mentions delay_on/delay_off -- must not touch them.
        assert self._read("delay_on") == "SENTINEL"
        assert self._read("delay_off") == "SENTINEL"

    def test_running_writes_trigger_none_and_brightness_one(self):
        led.set(led.RUNNING, led_dir=self.tmp)
        assert self._read("trigger") == "none"
        assert self._read("brightness") == "1"
        assert self._read("delay_on") == "SENTINEL"

    def test_safe_remove_writes_held_slow_rate(self):
        led.set(led.SAFE_REMOVE, led_dir=self.tmp)
        assert self._read("trigger") == "timer"
        assert self._read("delay_on") == "1000"
        assert self._read("delay_off") == "1000"

    def test_busy_writes_four_hz_rate(self):
        led.set(led.BUSY, led_dir=self.tmp)
        assert self._read("trigger") == "timer"
        assert self._read("delay_on") == "250"
        assert self._read("delay_off") == "250"

    def test_writes_happen_in_plan_order_trigger_first(self):
        calls = []

        def recording_writer(path, value):
            calls.append((os.path.basename(path), value))

        led.set(led.ERROR, led_dir=self.tmp, writer=recording_writer)
        assert calls[0] == ("trigger", "timer")
        assert ("delay_on", "50") in calls[1:]
        assert ("delay_off", "50") in calls[1:]

    def test_write_failure_raises_led_error(self):
        def failing_writer(path, value):
            raise OSError("simulated sysfs write failure")

        with self.assertRaises(led.LedError) as cm:
            led.set(led.READY, led_dir=self.tmp, writer=failing_writer)
        assert cm.exception.reason == "led_write_failed"

    def test_never_targets_sys_led(self):
        assert "user_led" in led.LED_DIR
        assert "sys_led" not in led.LED_DIR


if __name__ == "__main__":
    unittest.main()
