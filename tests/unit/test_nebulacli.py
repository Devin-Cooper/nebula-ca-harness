"""Tests for causb.nebulacli: tested wrapper over the `nebula-cert`
binary (Task 1, CA operation handlers plan).

Every test here runs WITHOUT ever invoking the real `nebula-cert` binary:
`ca()`/`sign()`/`print_json()`/`version()` all take an injectable
`runner` (mirrors `causb.mountctl`'s `runner=subprocess.run` seam), so a
`_RecordingRunner` stub stands in for the real subprocess call and every
test asserts on the EXACT argv nebula-cert would have been invoked with.

The one thing that cannot be exercised without a real binary -- that
these exact argv shapes genuinely round-trip through a real `nebula-cert
ca` -> `keygen` -> `sign` -> `print -json` pipeline, and that `print
-json` really does wrap its output in a one-element JSON array (the
reason print_json() unwraps it below) -- was verified manually against
the box's real v1.10.3 binary in a throwaway /tmp directory during
development; nothing from that session is committed here, and nothing it
did touched /etc/nebula-ca or /var/lib/nebula-ca.
"""

import json
import subprocess
import unittest

from causb.nebulacli import NebulaError, ca, print_json, sign, version


class _RecordingRunner:
    """Stands in for `subprocess.run`. `results` is a list where each
    entry is either an (returncode, stdout, stderr) tuple or an exception
    INSTANCE to raise, one per expected call, in order; the last entry
    repeats for any call beyond the list's length. Every call is recorded
    (argv + kwargs) and asserted, INLINE, to never use shell=True -- so
    any test built on this stub fails loudly if production code ever
    regresses that invariant, without needing a dedicated test for it.
    """

    def __init__(self, results):
        self._results = list(results)
        self.calls = []  # list of (argv, kwargs)

    def __call__(self, argv, **kwargs):
        assert kwargs.get("shell") is not True, "must never use shell=True"
        argv = list(argv)
        self.calls.append((argv, kwargs))
        idx = min(len(self.calls) - 1, len(self._results) - 1)
        outcome = self._results[idx]
        if isinstance(outcome, BaseException):
            raise outcome
        rc, stdout, stderr = outcome
        return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=stderr)


class TestCa(unittest.TestCase):
    KWARGS = dict(
        name="probe-ca", curve="25519", version="1", duration="8760h",
        out_crt="/tmp/ca.crt", out_key="/tmp/ca.key",
    )

    def test_builds_exact_argv_and_returns_none(self):
        runner = _RecordingRunner([(0, "", "")])
        result = ca(**self.KWARGS, runner=runner)

        assert result is None
        assert len(runner.calls) == 1
        argv, kwargs = runner.calls[0]
        assert argv == [
            "nebula-cert", "ca",
            "-name", "probe-ca",
            "-curve", "25519",
            "-version", "1",
            "-duration", "8760h",
            "-out-crt", "/tmp/ca.crt",
            "-out-key", "/tmp/ca.key",
        ]
        assert kwargs.get("shell") is not True
        assert kwargs.get("timeout") == 120  # documented default

    def test_custom_timeout_is_forwarded_to_runner(self):
        runner = _RecordingRunner([(0, "", "")])
        ca(**self.KWARGS, runner=runner, timeout=45)
        _, kwargs = runner.calls[0]
        assert kwargs.get("timeout") == 45


class TestSign(unittest.TestCase):
    KWARGS = dict(
        ca_crt="ca.crt", ca_key="ca.key", in_pub="host.pub", name="host1",
        networks="10.42.0.10/16", duration="8760h", out_crt="host1.crt",
    )

    @staticmethod
    def _expected_fixed_argv():
        return [
            "nebula-cert", "sign",
            "-ca-crt", "ca.crt",
            "-ca-key", "ca.key",
            "-in-pub", "host.pub",
            "-name", "host1",
            "-networks", "10.42.0.10/16",
            "-duration", "8760h",
            "-version", "1",
            "-out-crt", "host1.crt",
        ]

    def test_builds_exact_argv_without_optional_flags(self):
        runner = _RecordingRunner([(0, "", "")])
        result = sign(**self.KWARGS, runner=runner)

        assert result is None
        argv, kwargs = runner.calls[0]
        assert argv == self._expected_fixed_argv()
        assert "-groups" not in argv
        assert "-out-qr" not in argv
        assert kwargs.get("timeout") == 120  # documented default

    def test_omits_groups_when_none(self):
        runner = _RecordingRunner([(0, "", "")])
        sign(**self.KWARGS, groups=None, runner=runner)
        argv, _ = runner.calls[0]
        assert "-groups" not in argv

    def test_omits_groups_when_empty_list(self):
        runner = _RecordingRunner([(0, "", "")])
        sign(**self.KWARGS, groups=[], runner=runner)
        argv, _ = runner.calls[0]
        assert "-groups" not in argv

    def test_appends_groups_when_nonempty_list(self):
        runner = _RecordingRunner([(0, "", "")])
        sign(**self.KWARGS, groups=["a", "b"], runner=runner)
        argv, _ = runner.calls[0]
        assert argv == self._expected_fixed_argv() + ["-groups", "a,b"]

    def test_omits_out_qr_when_not_given(self):
        runner = _RecordingRunner([(0, "", "")])
        sign(**self.KWARGS, runner=runner)
        argv, _ = runner.calls[0]
        assert "-out-qr" not in argv

    def test_appends_out_qr_when_given(self):
        runner = _RecordingRunner([(0, "", "")])
        sign(**self.KWARGS, out_qr="host1.png", runner=runner)
        argv, _ = runner.calls[0]
        assert argv == self._expected_fixed_argv() + ["-out-qr", "host1.png"]

    def test_appends_groups_then_out_qr_together_in_that_order(self):
        runner = _RecordingRunner([(0, "", "")])
        sign(**self.KWARGS, groups=["a", "b"], out_qr="host1.png", runner=runner)
        argv, _ = runner.calls[0]
        assert argv == self._expected_fixed_argv() + [
            "-groups", "a,b", "-out-qr", "host1.png",
        ]


class TestPrintJson(unittest.TestCase):
    def test_builds_exact_argv(self):
        runner = _RecordingRunner([(0, json.dumps({"fingerprint": "abc"}), "")])
        print_json("/tmp/ca.crt", runner=runner)
        argv, kwargs = runner.calls[0]
        assert argv == ["nebula-cert", "print", "-json", "-path", "/tmp/ca.crt"]
        assert kwargs.get("timeout") == 30  # documented default

    def test_parses_bare_dict_stdout(self):
        # The brief's own fixture shape: a bare JSON object.
        fake = {"details": {"name": "probe-ca"}, "fingerprint": "abc"}
        runner = _RecordingRunner([(0, json.dumps(fake), "")])

        result = print_json("/tmp/ca.crt", runner=runner)

        assert result == fake

    def test_unwraps_single_element_json_array_stdout(self):
        # The REAL nebula-cert v1.10.3 shape (verified live against the
        # box): `print -json` always wraps its output in a JSON array,
        # even for a single certificate.
        fake_cert = {"details": {"name": "probe-ca"}, "fingerprint": "abc"}
        runner = _RecordingRunner([(0, json.dumps([fake_cert]), "")])

        result = print_json("/tmp/ca.crt", runner=runner)

        assert result == fake_cert

    def test_raises_nebula_failed_on_empty_array(self):
        runner = _RecordingRunner([(0, json.dumps([]), "")])
        with self.assertRaises(NebulaError) as cm:
            print_json("/tmp/ca.crt", runner=runner)
        assert cm.exception.reason == "nebula_failed"

    def test_raises_nebula_failed_on_multi_element_array(self):
        runner = _RecordingRunner([(0, json.dumps([{"a": 1}, {"b": 2}]), "")])
        with self.assertRaises(NebulaError) as cm:
            print_json("/tmp/ca.crt", runner=runner)
        assert cm.exception.reason == "nebula_failed"

    def test_raises_nebula_failed_on_malformed_json(self):
        runner = _RecordingRunner([(0, "not json", "")])
        with self.assertRaises(NebulaError) as cm:
            print_json("/tmp/ca.crt", runner=runner)
        assert cm.exception.reason == "nebula_failed"


class TestVersion(unittest.TestCase):
    def test_builds_exact_argv(self):
        runner = _RecordingRunner([(0, "Version: 1.10.3\n", "")])
        version(runner=runner)
        argv, kwargs = runner.calls[0]
        assert argv == ["nebula-cert", "-version"]
        assert kwargs.get("timeout") == 30  # documented default

    def test_returns_parsed_version_string(self):
        runner = _RecordingRunner([(0, "Version: 1.10.3\n", "")])
        result = version(runner=runner)
        assert result == "1.10.3"

    def test_raises_nebula_failed_on_blank_stdout(self):
        runner = _RecordingRunner([(0, "", "")])
        with self.assertRaises(NebulaError) as cm:
            version(runner=runner)
        assert cm.exception.reason == "nebula_failed"


class TestErrorMapping(unittest.TestCase):
    """The nonzero/timeout/missing-binary mapping is exercised fully
    against `ca()`, then cross-checked (nonzero only) against the other
    three entry points to prove none of them bypass the shared mapping."""

    CA_KWARGS = dict(
        name="probe-ca", curve="25519", version="1", duration="8760h",
        out_crt="/tmp/ca.crt", out_key="/tmp/ca.key",
    )

    def test_nonzero_returncode_maps_to_nebula_failed_and_hides_stderr(self):
        runner = _RecordingRunner([(1, "", "some sensitive diagnostic")])
        with self.assertRaises(NebulaError) as cm:
            ca(**self.CA_KWARGS, runner=runner)
        assert cm.exception.reason == "nebula_failed"
        assert "sensitive diagnostic" not in str(cm.exception)

    def test_timeout_expired_maps_to_timeout(self):
        runner = _RecordingRunner(
            [subprocess.TimeoutExpired(cmd="nebula-cert", timeout=120)]
        )
        with self.assertRaises(NebulaError) as cm:
            ca(**self.CA_KWARGS, runner=runner)
        assert cm.exception.reason == "timeout"

    def test_file_not_found_maps_to_tool_missing(self):
        runner = _RecordingRunner([FileNotFoundError()])
        with self.assertRaises(NebulaError) as cm:
            ca(**self.CA_KWARGS, runner=runner)
        assert cm.exception.reason == "tool_missing"

    def test_error_mapping_applies_to_sign(self):
        runner = _RecordingRunner([(1, "", "")])
        with self.assertRaises(NebulaError) as cm:
            sign(
                ca_crt="ca.crt", ca_key="ca.key", in_pub="host.pub",
                name="host1", networks="10.42.0.10/16", duration="8760h",
                out_crt="host1.crt", runner=runner,
            )
        assert cm.exception.reason == "nebula_failed"

    def test_error_mapping_applies_to_print_json(self):
        runner = _RecordingRunner([(1, "", "")])
        with self.assertRaises(NebulaError) as cm:
            print_json("/tmp/ca.crt", runner=runner)
        assert cm.exception.reason == "nebula_failed"

    def test_error_mapping_applies_to_version(self):
        runner = _RecordingRunner([(1, "", "")])
        with self.assertRaises(NebulaError) as cm:
            version(runner=runner)
        assert cm.exception.reason == "nebula_failed"


class TestControlCharRejection(unittest.TestCase):
    """A control character (NUL, any C0 byte, or DEL) in ANY argv element
    must be rejected BEFORE the runner is ever invoked -- proven here
    across several different functions/argument positions, not just one."""

    def test_ca_rejects_nul_in_name_before_exec(self):
        runner = _RecordingRunner([(0, "", "")])
        with self.assertRaises(ValueError):
            ca(
                name="a\x00b", curve="25519", version="1", duration="8760h",
                out_crt="/tmp/ca.crt", out_key="/tmp/ca.key", runner=runner,
            )
        assert runner.calls == []

    def test_ca_rejects_del_in_curve_before_exec(self):
        runner = _RecordingRunner([(0, "", "")])
        with self.assertRaises(ValueError):
            ca(
                name="probe-ca", curve="25519\x7f", version="1",
                duration="8760h", out_crt="/tmp/ca.crt",
                out_key="/tmp/ca.key", runner=runner,
            )
        assert runner.calls == []

    def test_sign_rejects_control_char_in_appended_out_qr_before_exec(self):
        runner = _RecordingRunner([(0, "", "")])
        with self.assertRaises(ValueError):
            sign(
                ca_crt="ca.crt", ca_key="ca.key", in_pub="host.pub",
                name="host1", networks="10.42.0.10/16", duration="8760h",
                out_crt="host1.crt", out_qr="host1\x01.png", runner=runner,
            )
        assert runner.calls == []

    def test_print_json_rejects_control_char_in_path_before_exec(self):
        runner = _RecordingRunner([(0, "{}", "")])
        with self.assertRaises(ValueError):
            print_json("cert\x1b.crt", runner=runner)
        assert runner.calls == []


if __name__ == "__main__":
    unittest.main()
