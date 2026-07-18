#!/usr/bin/env python3
"""Root, on-box hardware integration checks for Task 10 (mountctl/led/button).

RUN AS ROOT, ON THE BOX ONLY:

    sudo python3 tests/integration/hw_root.py

Exercises the real Linux mechanisms `tests/unit/` cannot (no root, no
hardware there by design): loopback block devices + real `mount(8)`/
`umount(8)`, a real `/sys/class/leds/user_led`, and a synthetic `uinput`
device standing in for a physical K1 press (the REAL K1 button and the
REAL LED's visible rhythm are physical confirmations, deferred to
`tests/integration/10-hw.md` -- this script proves the CODE drives the
real kernel interfaces correctly, not that a human sees the right light).

Covers exactly the three Tier-2 groups from the task brief:
  (a) mountctl: a real vfat loop image mounts ro with the hardened opts,
      remounts rw keeping them, umounts cleanly; a real ext4 loop image is
      REFUSED by mount_ro (type != vfat).
  (b) button: a uinput device advertising KEY_1 (257) is created; a
      press->release makes await_press() return True; silence times out
      False; holding the key before calling makes it return False
      (anti-tamper) -- all against the REAL gpio-keys device ALSO present
      on this box simultaneously, disambiguated via await_press()'s
      documented `name_filter` testability seam (see causb/button.py).
  (c) led: each of the 6 states is set for real, then read back from the
      real /sys/class/leds/user_led/* files; sys_led is confirmed
      untouched throughout.

Cleans up every loop device / uinput device / mount / temp file it
creates, in `finally` blocks, even on failure. Prints PASS/FAIL per case
and a final summary; exits non-zero if anything failed.
"""

import ctypes
import fcntl
import os
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time

if os.geteuid() != 0:
    print("hw_root.py must be run as root (sudo) -- it uses losetup/mount/uinput.")
    sys.exit(1)

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "box", "lib"))

from causb import button, led  # noqa: E402
from causb.mountctl import MountError, mount_ro, mount_rw, umount  # noqa: E402

LOSETUP = "/usr/sbin/losetup"
MKFS_VFAT = "/sbin/mkfs.vfat"
MKFS_EXT4 = "/sbin/mkfs.ext4"

_IMAGE_BYTES = 32 * 1024 * 1024  # 32MB -- plenty for either fs, fast to create/format


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _run(argv, **kwargs):
    return subprocess.run(
        argv, check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs,
    )


def _mounts_entry(mp):
    """Return (fstype, options_set) for mountpoint `mp` from /proc/mounts,
    or None if not mounted."""
    with open("/proc/mounts") as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == mp:
                return fields[2], set(fields[3].split(","))
    return None


class _LoopImage:
    """Creates a blank sparse file, attaches it via losetup, and formats
    it with `mkfs_argv0` (e.g. "mkfs.vfat" or "mkfs.ext4"). `.dev` is the
    resulting /dev/loopN path. `cleanup()` detaches the loop device and
    removes the backing file -- safe to call multiple times / after a
    partial setup failure."""

    def __init__(self, mkfs_path, label):
        self.dev = None
        fd, self.image_path = tempfile.mkstemp(prefix=f"causb-{label}-")
        os.close(fd)
        with open(self.image_path, "wb") as f:
            f.truncate(_IMAGE_BYTES)
        result = _run([LOSETUP, "-f", "--show", self.image_path])
        self.dev = result.stdout.decode().strip()
        _run([mkfs_path, self.dev])

    def cleanup(self):
        if self.dev:
            subprocess.run([LOSETUP, "-d", self.dev],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.dev = None
        if os.path.exists(self.image_path):
            os.unlink(self.image_path)


# --------------------------------------------------------------------------
# (a) mountctl
# --------------------------------------------------------------------------

def case_mount_ro_vfat_hardened_and_umount_clean():
    img = _LoopImage(MKFS_VFAT, "vfat")
    mp = tempfile.mkdtemp(prefix="causb-mp-vfat-")
    try:
        mount_ro(img.dev, mp)
        entry = _mounts_entry(mp)
        assert entry is not None, "not mounted after mount_ro"
        fstype, opts = entry
        assert fstype == "vfat", f"fstype={fstype!r}"
        for flag in ("ro", "noexec", "nosuid", "nodev"):
            assert flag in opts, f"missing {flag!r} in ro opts {opts}"

        mount_rw(mp)
        fstype2, opts2 = _mounts_entry(mp)
        assert "rw" in opts2, f"not rw after mount_rw: {opts2}"
        for flag in ("noexec", "nosuid", "nodev"):
            assert flag in opts2, f"remount,rw lost {flag!r}: {opts2}"

        umount(mp)
        assert _mounts_entry(mp) is None, "still mounted after umount() returned"
        return True, "vfat mount_ro(hardened)->mount_rw(rw,flags kept)->umount(0) all OK"
    finally:
        subprocess.run(["umount", mp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.rmdir(mp)
        img.cleanup()


def case_mount_ro_refuses_ext4():
    img = _LoopImage(MKFS_EXT4, "ext4")
    mp = tempfile.mkdtemp(prefix="causb-mp-ext4-")
    try:
        try:
            mount_ro(img.dev, mp)
        except MountError as exc:
            assert exc.reason == "mount_failed", f"wrong reason {exc.reason!r}"
            assert _mounts_entry(mp) is None, "ext4 image got mounted despite refusal"
            return True, "ext4 image correctly refused by mount_ro (MountError mount_failed)"
        return False, "mount_ro did NOT raise for an ext4 image -- vfat pinning failed"
    finally:
        subprocess.run(["umount", mp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.rmdir(mp)
        img.cleanup()


# --------------------------------------------------------------------------
# (b) button, via a synthetic uinput device
# --------------------------------------------------------------------------

EV_KEY = 1
EV_SYN = 0
SYN_REPORT = 0
UINPUT_MAX_NAME_SIZE = 80
ABS_CNT = 64

_UI_STRUCT_FMT = f"<{UINPUT_MAX_NAME_SIZE}sHHHHI{ABS_CNT}i{ABS_CNT}i{ABS_CNT}i{ABS_CNT}i"


def _IOC(dir_, type_, nr, size):
    return (dir_ << 30) | (type_ << 8) | (nr << 0) | (size << 16)


_IOC_NONE, _IOC_WRITE = 0, 1
_UI_SET_EVBIT = _IOC(_IOC_WRITE, ord("U"), 100, ctypes.sizeof(ctypes.c_int))
_UI_SET_KEYBIT = _IOC(_IOC_WRITE, ord("U"), 101, ctypes.sizeof(ctypes.c_int))
_UI_DEV_CREATE = _IOC(_IOC_NONE, ord("U"), 1, 0)
_UI_DEV_DESTROY = _IOC(_IOC_NONE, ord("U"), 2, 0)


class _UinputDevice:
    """A synthetic evdev device advertising exactly one EV_KEY code, via
    the "old" /dev/uinput write() API. Used only to stand in for a live K1
    press during this root-only integration run -- production
    `causb.button` never creates devices, only reads them."""

    def __init__(self, name, code):
        self.name = name
        self.code = code
        self.fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
        fcntl.ioctl(self.fd, _UI_SET_EVBIT, EV_KEY)
        fcntl.ioctl(self.fd, _UI_SET_KEYBIT, code)
        payload = struct.pack(
            _UI_STRUCT_FMT,
            name.encode()[:UINPUT_MAX_NAME_SIZE - 1],
            0x06, 0x0001, 0x0001, 1,  # bustype(BUS_VIRTUAL), vendor, product, version
            0,  # ff_effects_max
            *([0] * ABS_CNT), *([0] * ABS_CNT), *([0] * ABS_CNT), *([0] * ABS_CNT),
        )
        os.write(self.fd, payload)
        fcntl.ioctl(self.fd, _UI_DEV_CREATE)
        self.event_path = self._wait_for_event_node()

    def _wait_for_event_node(self, timeout_s=3.0):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with open("/proc/bus/input/devices") as f:
                text = f.read()
            for block in text.split("\n\n"):
                if f'Name="{self.name}"' in block:
                    m = re.search(r"Handlers=.*?\bevent(\d+)\b", block)
                    if m:
                        return f"/dev/input/event{m.group(1)}"
            time.sleep(0.05)
        raise RuntimeError(f"uinput device {self.name!r} never appeared in /proc/bus/input/devices")

    def _emit(self, ev_type, code, value):
        os.write(self.fd, struct.pack("llHHi", 0, 0, ev_type, code, value))

    def press(self):
        self._emit(EV_KEY, self.code, 1)
        self._emit(EV_SYN, SYN_REPORT, 0)

    def release(self):
        self._emit(EV_KEY, self.code, 0)
        self._emit(EV_SYN, SYN_REPORT, 0)

    def cleanup(self):
        try:
            fcntl.ioctl(self.fd, _UI_DEV_DESTROY)
        except OSError:
            pass
        os.close(self.fd)


def _only_our_device(name):
    return lambda dev_name: dev_name == name


def case_button_press_release_returns_true():
    dev_name = f"causb-hwtest-{os.getpid()}"
    dev = _UinputDevice(dev_name, button.K1_CODE)
    try:
        result_holder = {}

        def _do_press_after_delay():
            time.sleep(0.2)
            dev.press()
            time.sleep(0.1)
            dev.release()

        t = threading.Thread(target=_do_press_after_delay, daemon=True)
        t.start()
        result = button.await_press(3.0, name_filter=_only_our_device(dev_name))
        t.join(timeout=3.0)
        assert result is True, "await_press did not detect the injected press-release"
        return True, "uinput press->release detected: await_press(3.0) returned True"
    finally:
        dev.cleanup()


def case_button_timeout_with_no_press_returns_false():
    dev_name = f"causb-hwtest-{os.getpid()}-b"
    dev = _UinputDevice(dev_name, button.K1_CODE)
    try:
        start = time.monotonic()
        result = button.await_press(1.0, name_filter=_only_our_device(dev_name))
        elapsed = time.monotonic() - start
        assert result is False, "await_press returned True with no press injected"
        assert elapsed >= 0.9, f"returned too early ({elapsed:.2f}s) for a 1.0s window"
        return True, f"no press -> False after timeout ({elapsed:.2f}s elapsed)"
    finally:
        dev.cleanup()


def case_button_held_before_call_returns_false_fast():
    dev_name = f"causb-hwtest-{os.getpid()}-c"
    dev = _UinputDevice(dev_name, button.K1_CODE)
    try:
        dev.press()  # held down, no release -- simulates tape/a stuck key
        time.sleep(0.1)  # let the kernel register the key-down state
        start = time.monotonic()
        result = button.await_press(5.0, name_filter=_only_our_device(dev_name))
        elapsed = time.monotonic() - start
        assert result is False, "await_press returned True despite K1 already held"
        assert elapsed < 1.0, f"anti-tamper reject was not fast ({elapsed:.2f}s)"
        return True, f"held-before-call -> False, fast reject ({elapsed:.3f}s, did not wait out 5s)"
    finally:
        dev.release()
        dev.cleanup()


# --------------------------------------------------------------------------
# (c) led
# --------------------------------------------------------------------------

def _active_trigger(led_dir):
    with open(os.path.join(led_dir, "trigger")) as f:
        text = f.read()
    m = re.search(r"\[(\w+)\]", text)
    return m.group(1) if m else None


def _read_attr(led_dir, name):
    with open(os.path.join(led_dir, name)) as f:
        return f.read().strip()


def case_led_states_readback():
    sys_led_dir = "/sys/class/leds/sys_led"
    sys_led_trigger_before = _active_trigger(sys_led_dir)

    expectations = [
        (led.IDLE, {"trigger": "none", "brightness": "0"}),
        (led.VERIFYING, {"trigger": "timer", "delay_on": "330", "delay_off": "330"}),
        (led.READY, {"trigger": "timer", "delay_on": "125", "delay_off": "125"}),
        (led.RUNNING, {"trigger": "none", "brightness": "1"}),
        (led.ERROR, {"trigger": "timer", "delay_on": "50", "delay_off": "50"}),
        (led.SAFE_REMOVE, {"trigger": "timer", "delay_on": "1000", "delay_off": "1000"}),
    ]
    details = []
    try:
        for state, expected in expectations:
            led.set(state)
            active = _active_trigger(led.LED_DIR)
            assert active == expected["trigger"], (
                f"{state}: trigger={active!r}, expected {expected['trigger']!r}"
            )
            if "brightness" in expected:
                got = _read_attr(led.LED_DIR, "brightness")
                assert got == expected["brightness"], f"{state}: brightness={got!r}"
            if "delay_on" in expected:
                got_on = _read_attr(led.LED_DIR, "delay_on")
                got_off = _read_attr(led.LED_DIR, "delay_off")
                assert got_on == expected["delay_on"], f"{state}: delay_on={got_on!r}"
                assert got_off == expected["delay_off"], f"{state}: delay_off={got_off!r}"
            details.append(f"{state}: OK ({expected})")
    finally:
        led.set(led.IDLE)  # leave the box in a clean state

    sys_led_trigger_after = _active_trigger(sys_led_dir)
    assert sys_led_trigger_after == sys_led_trigger_before, (
        f"sys_led trigger changed! before={sys_led_trigger_before!r} "
        f"after={sys_led_trigger_after!r} -- led.py must never touch sys_led"
    )
    details.append(f"sys_led trigger untouched throughout ({sys_led_trigger_before!r})")
    return True, "; ".join(details)


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

CASES = [
    ("(a) mount_ro vfat hardened + mount_rw + umount(0)", case_mount_ro_vfat_hardened_and_umount_clean),
    ("(a) mount_ro refuses ext4 (type != vfat)", case_mount_ro_refuses_ext4),
    ("(b) button: press->release -> True", case_button_press_release_returns_true),
    ("(b) button: no press -> False (timeout)", case_button_timeout_with_no_press_returns_false),
    ("(b) button: held before call -> False (anti-tamper)", case_button_held_before_call_returns_false_fast),
    ("(c) led: all 6 states read back correctly, sys_led untouched", case_led_states_readback),
]


def main():
    passed = 0
    failed = 0
    for name, fn in CASES:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- this is a top-level test runner
            ok, detail = False, f"EXCEPTION: {type(exc).__name__}: {exc}"
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        print(f"[{status}] {name}\n         {detail}")

    print(f"\n{passed}/{passed + failed} cases passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
