"""Tests for causb.button: K1 identity resolution + anti-tamper live
press-release confirmation (S7.6, D2, R3's CLOCK_MONOTONIC note).

PURE LOGIC ONLY -- no real device, no root, no uinput. Three independent
pieces are exercised directly, exactly as the brief asks:

1. `resolve_k1_path()` / the `/proc/bus/input/devices` parser -- fed
   synthetic device-table TEXT (including the box's OWN real captured
   text, verified over SSH on <box>, kernel 6.1.141: `adc-keys`
   on event0 advertising ONLY code 158/KEY_BACK, `gpio-keys` on event1
   advertising ONLY code 257/BTN_1 -- see the module docstring in
   `causb/button.py` for the bit-decode arithmetic this was checked
   against).
2. `_PressWaiter`, the pure press->release state machine -- fed synthetic
   `input_event` bytes built with `struct.pack`, never a real fd.
3. `_wait_press_release_on_fd`, the select()/read() loop -- exercised
   against a REAL fd (an `os.pipe()`), so the actual select/read/timeout
   machinery runs for real; only the EVIOCGKEY anti-tamper ioctl (which a
   plain pipe cannot support -- ENOTTY) is stubbed via the `already_held`
   injection point `causb.button.await_press`'s internals expose for
   exactly this reason.

Real hardware (an actual gpio-keys press, a real uinput-injected press on
the box) is exercised separately by `tests/integration/hw_root.py`, run as
root on the box.
"""

import os
import struct
import threading
import time
import unittest

from causb.button import (
    K1_CODE,
    MASK_CODE,
    ButtonError,
    _PressWaiter,
    _key_bit_set,
    _wait_press_release_on_fd,
    resolve_k1_path,
)

EV_KEY = 1
EV_SYN = 0

# The box's REAL /proc/bus/input/devices, captured verbatim over SSH
# (<box>, kernel 6.1.141) -- adc-keys/event0 advertises ONLY
# KEY_BACK (158, MASK -- excluded), gpio-keys/event1 advertises ONLY BTN_1
# (257, K1). The H: lines' trailing space is real kernel output (the
# kernel's input core prints "Handlers=<name> " with a trailing space
# before the newline); it is written here as an explicit `" "` inside the
# string literal, not as invisible end-of-line whitespace, specifically so
# an editor/formatter can never silently strip it back out from under this
# regression coverage -- a parser that breaks on it would also break on
# the real box.
REAL_DEVICES_TEXT = "\n".join(
    [
        "I: Bus=0019 Vendor=0001 Product=0001 Version=0100",
        'N: Name="adc-keys"',
        "P: Phys=adc-keys/input0",
        "S: Sysfs=/devices/platform/adc-keys/input/input0",
        "U: Uniq=",
        "H: Handlers=kbd event0" + " ",
        "B: PROP=0",
        "B: EV=3",
        "B: KEY=40000000 0 0",
        "",
        "I: Bus=0019 Vendor=0001 Product=0001 Version=0100",
        'N: Name="gpio-keys"',
        "P: Phys=gpio-keys/input0",
        "S: Sysfs=/devices/platform/gpio-keys/input/input1",
        "U: Uniq=",
        "H: Handlers=event1" + " ",
        "B: PROP=0",
        "B: EV=3",
        "B: KEY=2 0 0 0 0",
        "",
        "",
    ]
)


def _inject_after_delay(fd, chunks, delay_s=0.1):
    """Write `chunks` to `fd` from a background thread after a short delay,
    so they arrive AFTER the caller's `_wait_press_release_on_fd` has
    already run its initial flush/anti-tamper check and is genuinely
    blocked in `select()` -- simulating a LIVE press, as opposed to data
    already queued before the call (which the flush step must discard;
    see `test_flushes_stale_events_queued_before_the_call`). Returns the
    Thread so the caller can join() it."""

    def _write():
        time.sleep(delay_s)
        for chunk in chunks:
            os.write(fd, chunk)

    t = threading.Thread(target=_write, daemon=True)
    t.start()
    return t


def _event_bytes(ev_type, code, value):
    """Pack one raw `input_event` (24 bytes on this 64-bit box: `llHHi`,
    i.e. a `timeval` `{tv_sec, tv_usec}` then type/code/value). The
    timestamp is never inspected by anything under test, so zeros are
    fine."""
    return struct.pack("llHHi", 0, 0, ev_type, code, value)


class TestResolveK1Path(unittest.TestCase):
    def test_resolves_real_box_devices_text_to_event1(self):
        assert resolve_k1_path(devices_text=REAL_DEVICES_TEXT) == "/dev/input/event1"

    def test_rejects_when_no_device_advertises_257(self):
        adc_keys_only = REAL_DEVICES_TEXT.split("\n\n")[0] + "\n\n"
        with self.assertRaises(ButtonError) as cm:
            resolve_k1_path(devices_text=adc_keys_only)
        assert cm.exception.reason == "device_not_found"

    def test_rejects_empty_devices_text(self):
        with self.assertRaises(ButtonError):
            resolve_k1_path(devices_text="")

    def test_rejects_when_multiple_gpio_keys_candidates_and_no_filter(self):
        # BOTH named "gpio-keys" AND advertising 257 -- so the name
        # requirement is satisfied by both and it is genuinely the ">1
        # candidate" arm (not the name check) that fails this closed.
        two_candidates = (
            "N: Name=\"gpio-keys\"\nH: Handlers=event5 \nB: KEY=2 0 0 0 0\n\n"
            "N: Name=\"gpio-keys\"\nH: Handlers=event6 \nB: KEY=2 0 0 0 0\n\n"
        )
        with self.assertRaises(ButtonError) as cm:
            resolve_k1_path(devices_text=two_candidates)
        assert cm.exception.reason == "device_not_found"

    def test_device_named_other_than_gpio_keys_is_not_selected_in_production(self):
        # HARDENING (item 1): a device advertising 257 but NOT named
        # "gpio-keys" -- e.g. a BadUSB HID that advertises BTN_1, or any
        # future 257-capable input -- must fail closed in production (no
        # name_filter). Capability alone must NOT be enough. This is the
        # exact regression the joint name+capability requirement closes:
        # under the old capability-only resolution this returned
        # "/dev/input/event7" instead of raising.
        impostor = "N: Name=\"evil-hid\"\nH: Handlers=event7 \nB: KEY=2 0 0 0 0\n\n"
        with self.assertRaises(ButtonError) as cm:
            resolve_k1_path(devices_text=impostor)
        assert cm.exception.reason == "device_not_found"

    def test_picks_real_gpio_keys_over_a_257_impostor(self):
        # HARDENING (item 1): with BOTH a 257-advertising impostor (wrong
        # name) AND the real gpio-keys device present, production
        # resolution selects gpio-keys (event1), never the impostor.
        impostor = "N: Name=\"evil-hid\"\nH: Handlers=event7 \nB: KEY=2 0 0 0 0\n\n"
        combined = impostor + REAL_DEVICES_TEXT
        assert resolve_k1_path(devices_text=combined) == "/dev/input/event1"

    def test_name_filter_seam_overrides_the_gpio_keys_default_for_tests(self):
        # The name_filter seam REPLACES the default gpio-keys predicate --
        # this is exactly how tests/integration/hw_root.py selects its
        # synthetic uinput device (a throwaway name, not "gpio-keys")
        # without weakening the production requirement.
        two_candidates = (
            "N: Name=\"devA\"\nH: Handlers=event5 \nB: KEY=2 0 0 0 0\n\n"
            "N: Name=\"devB\"\nH: Handlers=event6 \nB: KEY=2 0 0 0 0\n\n"
        )
        path = resolve_k1_path(
            devices_text=two_candidates, name_filter=lambda name: name == "devB"
        )
        assert path == "/dev/input/event6"

    def test_rejects_device_advertising_both_257_and_158_even_if_named_gpio_keys(self):
        # A hostile/malformed combo device must never be trusted as K1,
        # even when it IS named "gpio-keys" (so the ONLY thing rejecting it
        # is the 158-disjointness check, not the name). 5 space-separated
        # hex words, MSB-word-first (see causb.button's _parse_key_bits):
        # word4="2" (bit 1 -> 257), word2="40000000" (bit 30 -> 158).
        combo = "N: Name=\"gpio-keys\"\nH: Handlers=event9 \nB: KEY=2 0 40000000 0 0\n\n"
        with self.assertRaises(ButtonError) as cm:
            resolve_k1_path(devices_text=combo)
        assert cm.exception.reason == "device_not_found"

    def test_no_handlers_event_node_is_skipped(self):
        # Named "gpio-keys" with 257 but NO eventN handler -> skipped on the
        # missing event node alone (isolates that check from the name one).
        no_event = "N: Name=\"gpio-keys\"\nH: Handlers=kbd \nB: KEY=2 0 0 0 0\n\n"
        with self.assertRaises(ButtonError):
            resolve_k1_path(devices_text=no_event)


class TestKeyBitSet(unittest.TestCase):
    """HARDENING (item 3): the security-core EVIOCGKEY bit arithmetic, in
    isolation -- a hand-crafted key-bitmap buffer fed straight to the pure
    `_key_bit_set` decode, no fd/ioctl/hardware/root. This is the anti-
    tamper "is K1 currently held?" primitive; getting the byte/bit indexing
    wrong (e.g. big-endian, or off-by-one) would silently let a held button
    read as not-held, defeating the whole reject-if-held check."""

    _LEN = 96  # _EVIOCGKEY_LEN: (KEY_MAX+1)/8

    def test_code_257_bit_set_reads_as_held(self):
        buf = bytearray(self._LEN)
        # 257 -> byte 32, bit 1 (0x02). Set exactly that bit.
        buf[32] = 0x02
        assert _key_bit_set(bytes(buf), K1_CODE) is True

    def test_code_257_bit_clear_reads_as_not_held(self):
        buf = bytes(self._LEN)  # all zero
        assert _key_bit_set(buf, K1_CODE) is False

    def test_neighbouring_bits_do_not_leak_into_257(self):
        # Only bit 256 (byte 32, bit 0) and bit 258 (byte 32, bit 2) set --
        # 257 (bit 1) must still read clear, proving exact bit indexing.
        buf = bytearray(self._LEN)
        buf[32] = 0x01 | 0x04  # bits 0 and 2, NOT bit 1
        assert _key_bit_set(bytes(buf), K1_CODE) is False
        assert _key_bit_set(bytes(buf), 256) is True
        assert _key_bit_set(bytes(buf), 258) is True

    def test_mask_code_158_indexing(self):
        # 158 -> byte 19, bit 6 (0x40). Independent sanity on a second code.
        buf = bytearray(self._LEN)
        buf[19] = 0x40
        assert _key_bit_set(bytes(buf), MASK_CODE) is True
        assert _key_bit_set(bytes(buf), K1_CODE) is False

    def test_short_buffer_is_not_held_rather_than_indexerror(self):
        # A truncated/odd ioctl return must fail closed (not held), never
        # raise IndexError.
        assert _key_bit_set(b"", K1_CODE) is False
        assert _key_bit_set(bytes(4), K1_CODE) is False  # too short for byte 32


class TestPressWaiter(unittest.TestCase):
    def test_clean_press_release_returns_true(self):
        w = _PressWaiter(code=K1_CODE)
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is True

    def test_release_without_prior_press_is_ignored(self):
        w = _PressWaiter(code=K1_CODE)
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is False
        # A real press/release afterward still works.
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is True

    def test_wrong_code_events_never_fire_and_do_not_corrupt_state(self):
        w = _PressWaiter(code=K1_CODE)
        # A stray MASK (158) press+release on this same logical stream
        # must be ignored entirely.
        assert w.feed(_event_bytes(EV_KEY, MASK_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_KEY, MASK_CODE, 0)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is True

    def test_autorepeat_value_two_does_not_break_release_detection(self):
        w = _PressWaiter(code=K1_CODE)
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 2)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 2)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is True

    def test_syn_events_are_ignored(self):
        w = _PressWaiter(code=K1_CODE)
        assert w.feed(_event_bytes(EV_SYN, 0, 0)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_SYN, 0, 0)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is True

    def test_double_press_before_release_still_fires_exactly_once(self):
        w = _PressWaiter(code=K1_CODE)
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 1)) is False  # bouncy switch
        assert w.feed(_event_bytes(EV_KEY, K1_CODE, 0)) is True

    def test_partial_event_bytes_are_buffered_across_feeds(self):
        w = _PressWaiter(code=K1_CODE)
        press = _event_bytes(EV_KEY, K1_CODE, 1)
        release = _event_bytes(EV_KEY, K1_CODE, 0)
        assert w.feed(press[:10]) is False
        assert w.feed(press[10:]) is False
        assert w.feed(release[:5]) is False
        assert w.feed(release[5:]) is True

    def test_multiple_events_in_one_feed_call(self):
        w = _PressWaiter(code=K1_CODE)
        batch = _event_bytes(EV_KEY, K1_CODE, 1) + _event_bytes(EV_KEY, K1_CODE, 0)
        assert w.feed(batch) is True


class TestWaitPressReleaseOnFd(unittest.TestCase):
    """Exercises the real select()/os.read() loop against a real pipe fd;
    only the EVIOCGKEY-based `already_held` check is stubbed (a pipe
    cannot support that ioctl)."""

    def setUp(self):
        self.r, self.w = os.pipe()
        os.set_blocking(self.r, False)

    def tearDown(self):
        os.close(self.r)
        os.close(self.w)

    def test_detects_live_press_release_before_timeout(self):
        t = _inject_after_delay(
            self.w,
            [_event_bytes(EV_KEY, K1_CODE, 1), _event_bytes(EV_KEY, K1_CODE, 0)],
        )
        try:
            result = _wait_press_release_on_fd(
                self.r, window_s=2.0, code=K1_CODE, already_held=lambda fd, code: False
            )
        finally:
            t.join(timeout=2)
        assert result is True

    def test_flushes_stale_events_queued_before_the_call(self):
        # A complete press+release already sitting in the pipe when we
        # start must be discarded by the flush step, not counted as a
        # live press.
        os.write(self.w, _event_bytes(EV_KEY, K1_CODE, 1))
        os.write(self.w, _event_bytes(EV_KEY, K1_CODE, 0))

        start = time.monotonic()
        result = _wait_press_release_on_fd(
            self.r, window_s=0.3, code=K1_CODE, already_held=lambda fd, code: False
        )
        elapsed = time.monotonic() - start

        assert result is False
        assert elapsed >= 0.25  # genuinely waited out the window, didn't fire early

    def test_returns_false_on_timeout_with_no_data(self):
        start = time.monotonic()
        result = _wait_press_release_on_fd(
            self.r, window_s=0.3, code=K1_CODE, already_held=lambda fd, code: False
        )
        elapsed = time.monotonic() - start
        assert result is False
        assert elapsed >= 0.25

    def test_rejects_fast_when_already_held(self):
        start = time.monotonic()
        result = _wait_press_release_on_fd(
            self.r, window_s=5.0, code=K1_CODE, already_held=lambda fd, code: True
        )
        elapsed = time.monotonic() - start
        assert result is False
        assert elapsed < 0.2  # fast reject, did not wait out the 5s window

    def test_wrong_code_on_fd_is_ignored_until_real_press(self):
        t = _inject_after_delay(
            self.w,
            [
                _event_bytes(EV_KEY, MASK_CODE, 1),
                _event_bytes(EV_KEY, MASK_CODE, 0),
                _event_bytes(EV_KEY, K1_CODE, 1),
                _event_bytes(EV_KEY, K1_CODE, 0),
            ],
        )
        try:
            result = _wait_press_release_on_fd(
                self.r, window_s=2.0, code=K1_CODE, already_held=lambda fd, code: False
            )
        finally:
            t.join(timeout=2)
        assert result is True


if __name__ == "__main__":
    unittest.main()
