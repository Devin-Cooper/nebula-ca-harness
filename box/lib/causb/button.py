"""K1 anti-tamper live press-release confirmation (S7.6, D2, R3).

**Identity resolution, not `eventN` index (S0/S7.6).** The box exposes TWO
case-exposed buttons as ordinary evdev input devices: `gpio-keys`'s K1
(BTN_1, code 257 -- the confirm gate) and `adc-keys`'s "back" (KEY_BACK,
code 158 -- MASK/recovery, D2: "MASK excluded", must never be treated as a
confirmation). Which `/dev/input/eventN` node belongs to which is
PROBE-ORDER-FRAGILE (confirmed on-box: adc-keys enumerates first, as
event0; gpio-keys second, as event1 -- but nothing guarantees that order
survives a kernel/board revision), so `resolve_k1_path()` scans
`/proc/bus/input/devices` and selects the device by NAME **jointly with**
CAPABILITY: in production the device must BOTH be `N: Name="gpio-keys"`
(S0's verified identity of K1, hardcoded like every other verified-on-this-
box fact in this codebase) AND advertise code 257 in its `KEY=` bitmap AND
NOT advertise 158 (the last a belt-and-suspenders reject of a hypothetical
combo device that fused K1 with the do-not-use MASK/back key). Requiring
the name as well as the capability means a rogue/mislabeled input device
that merely advertises 257 (e.g. a BadUSB HID that slipped past USBGuard,
or a future board that grows a second 257-capable input) can never be
silently promoted to "the K1 button" -- it fails closed. Exactly one
device must satisfy all three; zero or more than one is a fail-closed
`ButtonError("device_not_found")` -- this function never guesses.

`/proc/bus/input/devices`' `B: KEY=` line is a kernel `bitmap_scnprintf`-
style dump: N space-separated 64-bit hex words, printed MOST-significant
WORD first (i.e. the LAST token is bits 0-63, the second-to-last is bits
64-127, and so on). `_parse_key_bits()` implements exactly that decode; it
was checked against this box's OWN real, captured `/proc/bus/input/devices`
(kernel 6.1.141, see `tests/unit/test_button.py`'s `REAL_DEVICES_TEXT`
fixture) BEFORE this module was written: adc-keys' `"40000000 0 0"` (3
words) decodes to exactly {158}, and gpio-keys' `"2 0 0 0 0"` (5 words)
decodes to exactly {257} -- matching the design doc's on-box facts exactly.

**Anti-tamper (D2/S7.6).** Before waiting for anything, `await_press()`
(a) flushes whatever is already queued on the resolved device's fd (a
non-blocking drain-to-EAGAIN loop) so a stale event from before this call
can never be mistaken for a live one, then (b) queries `EVIOCGKEY` for K1's
*current* held state and returns False IMMEDIATELY (no wait at all) if it
is already down -- catching a taped/held button before the operator's
"confirm" gesture is trusted. Only once both checks pass does it wait, via
`select()`, for a live press (`EV_KEY` code 257 value 1) followed by a
release (value 0) inside `window_s`; the deadline is computed from
`time.monotonic()` (S19 R3: CLOCK_MONOTONIC, immune to an operator
`set-time` clock jump shrinking or extending the window mid-wait).

**Testability seams (flagged explicitly, both no-ops for the real caller):**
`resolve_k1_path()`/`await_press()` accept an optional `name_filter`
callable that, WHEN PASSED, REPLACES the default production name predicate
(`name == "gpio-keys"`). It exists ONLY to disambiguate in a test
environment where a synthetic uinput device (advertising 257, for
`tests/integration/hw_root.py`) coexists on the SAME box as the real
gpio-keys device -- the test passes a filter matching the synthetic
device's throwaway name so the two don't collide. Production code NEVER
passes it, so the hardcoded `gpio-keys` name requirement is what actually
governs every real call (it is not "optional" in production -- the seam is
strictly a test override, and the capability + 158-disjointness checks
apply regardless of the name predicate). Similarly,
`_wait_press_release_on_fd()`'s `already_held` parameter defaults to the
real `EVIOCGKEY`-based check but can be stubbed so the select()/read()/
parse loop itself can be exercised for real against a plain pipe fd in
unit tests (a pipe cannot support `EVIOCGKEY` -- ENOTTY).

The `input_event` struct is parsed by hand (`llHHi`, verified 24 bytes on
this box's 64-bit kernel/libc: two native `long`s for a `timeval`
{tv_sec, tv_usec} + two `__u16` (type, code) + one `__s32` (value); see the
assertion right after `_EVENT_SIZE` below) -- no third-party evdev binding,
per this project's stdlib-only constraint.
"""

import fcntl
import os
import re
import select
import struct
import time

K1_CODE = 257  # BTN_1 (gpio-keys) -- the confirm gate.
MASK_CODE = 158  # KEY_BACK (adc-keys) -- recovery/MASK, D2: never a confirmation.
K1_NAME = "gpio-keys"  # S0: K1 IS the gpio-keys device; required jointly with K1_CODE.

EV_KEY = 1

_DEVICES_PATH = "/proc/bus/input/devices"

_EVENT_FMT = "llHHi"
_EVENT_SIZE = struct.calcsize(_EVENT_FMT)
assert _EVENT_SIZE == 24, (
    f"input_event size is {_EVENT_SIZE}, expected 24 -- this module's "
    "struct layout was verified only against this project's specific "
    "64-bit target box (kernel 6.1.141, aarch64) and must not silently "
    "misparse event bytes on a different layout"
)

# ioctl request-number arithmetic (linux/ioctl.h's generic _IOC() macro,
# stable ABI across arm64/x86_64): dir<<30 | type<<8 | nr | size<<16.
# Hardcoded rather than imported from a C header for the same reason
# causb.extract hardcodes __NR_openat2: no stdlib module exposes it, and
# this project takes verified-on-this-box constants over a fragile
# cross-libc lookup.
_IOC_READ = 2
_EVIOCGKEY_LEN = 96  # (KEY_MAX + 1) / 8 == (0x2ff + 1) / 8 == 768 / 8
_EVIOCGKEY = (_IOC_READ << 30) | (ord("E") << 8) | 0x18 | (_EVIOCGKEY_LEN << 16)


class ButtonError(Exception):
    """K1 device resolution failed. `reason` is "device_not_found": zero,
    or more than one, device in `/proc/bus/input/devices` is named
    "gpio-keys" AND advertises code 257 AND does not advertise 158 (or, in
    a test that overrides the name predicate via `name_filter`, matching
    that filter jointly with the same capability checks). This is distinct
    from the normal timeout/anti-tamper cases, which return False rather
    than raising (S7.6 gives those an explicit bool contract; a device that
    cannot even be found is an environment/setup fault, not a "no
    confirmation this time" outcome).
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _parse_key_bits(key_line_value):
    """Decode a `B: KEY=<tok> <tok> ...` line's value into the set of
    absolute key-code bits it advertises. Tokens are N space-separated
    64-bit hex words, kernel-printed MOST-significant WORD FIRST (i.e. the
    LAST token holds bits 0-63); see module docstring for the on-box
    values this was checked against.
    """
    tokens = key_line_value.split()
    n = len(tokens)
    bits = set()
    for i, tok in enumerate(tokens):
        word_index = n - 1 - i
        value = int(tok, 16)
        b = 0
        while value:
            if value & 1:
                bits.add(word_index * 64 + b)
            value >>= 1
            b += 1
    return bits


def _iter_device_blocks(text):
    """Yield each blank-line-separated device block (a list of lines) from
    `/proc/bus/input/devices`-format text."""
    block = []
    for line in text.splitlines():
        if line.strip() == "":
            if block:
                yield block
                block = []
        else:
            block.append(line)
    if block:
        yield block


_HANDLERS_EVENT_RE = re.compile(r"\bevent(\d+)\b")


def _parse_block(block_lines):
    """Parse one device block into {name, event_path, key_bits}.
    `event_path` is None if the block has no `eventN` handler at all (e.g.
    a device with only a `kbd` handler) -- such a block is never a valid
    K1 candidate regardless of its KEY bitmap."""
    name = None
    event_path = None
    key_bits = set()
    for line in block_lines:
        if line.startswith("N: Name="):
            name = line[len("N: Name="):].strip().strip('"')
        elif line.startswith("H: Handlers="):
            m = _HANDLERS_EVENT_RE.search(line[len("H: Handlers="):])
            if m:
                event_path = f"/dev/input/event{m.group(1)}"
        elif line.startswith("B: KEY="):
            key_bits = _parse_key_bits(line[len("B: KEY="):].strip())
    return {"name": name, "event_path": event_path, "key_bits": key_bits}


def _is_gpio_keys(name):
    """The production name predicate: K1 is `Name="gpio-keys"` (S0). This is
    the default `name_filter` -- a caller (only ever a test) may pass a
    different predicate, but production resolution always requires this
    exact name jointly with the K1_CODE capability."""
    return name == K1_NAME


def _candidates(devices_text, name_filter):
    result = []
    for block in _iter_device_blocks(devices_text):
        dev = _parse_block(block)
        if dev["event_path"] is None:
            continue
        if K1_CODE not in dev["key_bits"]:
            continue
        if MASK_CODE in dev["key_bits"]:
            continue  # never trust a device that also advertises MASK/back
        if not name_filter(dev["name"]):
            continue
        result.append(dev)
    return result


def resolve_k1_path(devices_text=None, devices_path=_DEVICES_PATH, name_filter=None):
    """Resolve K1's `/dev/input/eventN` path by IDENTITY (S0/S7.6): scan
    `/proc/bus/input/devices` (or `devices_text`, if given -- used by unit
    tests to avoid touching the real /proc file) for the single device that
    is `Name="gpio-keys"` AND advertises code 257 AND does not advertise
    158. The name requirement is jointly hardcoded with the capability in
    production (see module docstring): `name_filter`, when given, REPLACES
    the default `gpio-keys` name predicate and exists ONLY for tests --
    production code never passes it. Raises `ButtonError("device_not_found")`
    unless EXACTLY one device qualifies.
    """
    if devices_text is None:
        with open(devices_path) as f:
            devices_text = f.read()
    if name_filter is None:
        name_filter = _is_gpio_keys
    candidates = _candidates(devices_text, name_filter=name_filter)
    if len(candidates) != 1:
        raise ButtonError("device_not_found")
    return candidates[0]["event_path"]


def _key_bit_set(key_bitmap, code):
    """Pure bit-decode of an `EVIOCGKEY`-style byte bitmap: True iff `code`'s
    bit is set. Bit order is little-endian by byte -- code N lives in byte
    `N // 8`, bit `N % 8` (so K1's 257 -> byte 32, bit 1). A buffer too
    short to contain `code`'s byte is treated as "not set" rather than
    raising (defensive against a short/odd ioctl return). Split out from
    `_is_key_held` SO THIS SECURITY-CORE ARITHMETIC CAN BE UNIT TESTED
    against a hand-crafted buffer with no fd/ioctl/hardware/root."""
    byte_index, bit_index = divmod(code, 8)
    if byte_index >= len(key_bitmap):
        return False
    return bool(key_bitmap[byte_index] & (1 << bit_index))


def _is_key_held(fd, code):
    """True iff `code` is currently held, via `EVIOCGKEY` -- the anti-
    tamper check (S7.6): queried BEFORE waiting, so a button taped/held
    down ahead of time is rejected instantly rather than accepted as soon
    as the tape is removed (which would look like a normal release inside
    the window). The bit arithmetic is delegated to the pure `_key_bit_set`
    so it can be unit tested in isolation."""
    buf = fcntl.ioctl(fd, _EVIOCGKEY, bytes(_EVIOCGKEY_LEN))
    return _key_bit_set(buf, code)


class _PressWaiter:
    """Pure press(1) -> release(0) state machine for one key `code`. Feed
    it raw bytes (any chunking); `feed()` returns True the instant a clean
    press followed by a release is observed, buffering any partial
    trailing `input_event` across calls. Any event for a different code
    (EV_KEY or not), and EV_KEY value 2 (autorepeat), are ignored without
    disturbing the state -- so a stray key on the same logical stream (or
    key-repeat while held) can never falsely trigger or wedge detection.
    A release with no prior press is also ignored (state starts
    "not pressed"), so this cannot fire on a release-only stream.
    """

    def __init__(self, code=K1_CODE):
        self._code = code
        self._buf = b""
        self._pressed = False

    def feed(self, data):
        self._buf += data
        while len(self._buf) >= _EVENT_SIZE:
            chunk, self._buf = self._buf[:_EVENT_SIZE], self._buf[_EVENT_SIZE:]
            _sec, _usec, ev_type, code, value = struct.unpack(_EVENT_FMT, chunk)
            if ev_type == EV_KEY and code == self._code:
                if value == 1:
                    self._pressed = True
                elif value == 0 and self._pressed:
                    return True
        return False


def _drain_nonblocking(fd):
    """Discard whatever is already available on `fd` right now, without
    blocking (`fd` must be O_NONBLOCK) -- the S7.6 "flush any queued
    events" step, run before the anti-tamper check and the live wait, so a
    stale pre-existing event can never be mistaken for a live one."""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            return
        if not chunk:
            return


def _wait_press_release_on_fd(fd, window_s, code=K1_CODE, already_held=_is_key_held):
    """Flush, anti-tamper check, then wait up to `window_s` (measured via
    `time.monotonic()`, S19 R3) for a live press->release of `code` on
    `fd` (must be O_NONBLOCK). Returns True on a clean press-release,
    False on an immediate anti-tamper reject OR a timeout. `already_held`
    is injectable so this fd-level loop can be exercised against a plain
    pipe in unit tests (see module docstring).
    """
    _drain_nonblocking(fd)
    if already_held(fd, code):
        return False

    waiter = _PressWaiter(code=code)
    deadline = time.monotonic() + window_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            continue
        if not chunk:
            continue
        if waiter.feed(chunk):
            return True


def await_press(window_s, name_filter=None, devices_path=_DEVICES_PATH):
    """Wait up to `window_s` seconds for a live K1 press-release (S7.6/D2).
    Resolves K1 by identity (Name=="gpio-keys" jointly with the 257
    capability, never a hardcoded `eventN`), opens it O_NONBLOCK, flushes
    any queued events, rejects instantly if K1 is already held
    (anti-tamper), then waits for a genuine press(257,1) -> release(257,0)
    transition. Returns True on a clean press-release, False on an
    anti-tamper reject or a timeout. `name_filter`/`devices_path` are the
    testability seams documented in the module docstring -- real callers
    pass neither, so the hardcoded `gpio-keys` name requirement governs
    every production resolution.
    """
    path = resolve_k1_path(devices_path=devices_path, name_filter=name_filter)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        return _wait_press_release_on_fd(fd, window_s)
    finally:
        os.close(fd)
