"""Tests for box/handlers/sign-hosts: the "sign-hosts" vetted handler (S8;
CA operation handlers plan, Task 4). This is the handler that actually makes
the box a CA in day-to-day use: for each mesh host pubkey the operator
submits, it assigns a STABLE overlay IP (by name, via causb.registry), signs
a v1 host cert against the box's own ca.key/ca.crt, records the allocation,
and returns the cert on the stick -- never the CA key.

box/handlers/sign-hosts is a standalone, extensionless script (like
box/handlers/ca-bootstrap and box/handlers/status before it) -- loaded
in-process via importlib exactly like test_handler_ca_bootstrap.py's
`_load_ca_bootstrap_module()` precedent, so its `sys.path.append
("/usr/local/lib")` + `from causb import ...` at module scope behave
identically to a real standalone invocation.

`nebula_sign`/`nebula_print` are injected as fake recorders (mirrors
test_nebulacli.py's _RecordingRunner and this project's established
`runner=`/DI-seam convention): neither ever shells out to the real
nebula-cert binary. `_FakeNebulaSign` records every call's bound arguments
and writes recognizable fake bytes to out_crt (and out_qr, if given).
`_FakeNebulaPrint` returns a fingerprint/notAfter shaped EXACTLY like the
real nebula-cert v1.10.3 binary's `print -json` output, verified live
against the box (see the task report): a top-level "fingerprint" and a
"notAfter" nested one level down under "details" -- NOT a flat dict. Every
test uses a fresh tempfile.mkdtemp() tree for ca_dir/registry/out_dir/
payload_dir, never the real /var/lib/nebula-ca.

**A note on `job["seq"]`.** The brief this suite implements assumes
`sign-hosts` can read the manifest's own monotonic `seq` straight off the
`job` dict it is handed. As of this task, `causb.dispatch._write_job_json`
serializes only `{job_id, operation, args, payload}` (confirmed by reading
`causb.dispatch.py` and `box/bin/ca-usb-run`'s `job = parsed["jobs"][0]`) --
the outer manifest's `seq` is tracked separately by the orchestrator and is
NOT threaded into job.json today. `run()` therefore reads `job.get("seq",
0)`: a job dict that (like real production job.json today) omits "seq"
degrades safely to base seq 0 rather than crashing or bricking the handler;
a job dict that DOES carry a "seq" (as a future dispatch.py fix, or these
tests, may supply) uses it directly with no code change needed here. See
the module docstring in box/handlers/sign-hosts and the task report for the
full analysis of why this is a safe default and what it would take to close
the gap (a one-line, out-of-this-task's-scope addition to
`causb.dispatch._write_job_json`).
"""

import base64
import json
import os
import shutil
import tempfile
import unittest
import importlib.machinery
import importlib.util

from causb import config, registry

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIGN_HOSTS_HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "sign-hosts")

FAKE_CA_KEY_BYTES = b"FAKE-CA-PRIVATE-KEY-SECRET-MATERIAL-DO-NOT-LEAK-9c71a"
FAKE_CA_CRT_BYTES = b"FAKE-CA-PUBLIC-CERT-PEM-BYTES"


def _load_sign_hosts_module():
    loader = importlib.machinery.SourceFileLoader("sign_hosts_handler_under_test", SIGN_HOSTS_HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _job(args=None, seq=0, job_id="11111111-1111-4111-8111-111111111111"):
    return {
        "job_id": job_id,
        "operation": "sign-hosts",
        "args": {} if args is None else args,
        "payload": [],
        "seq": seq,
    }


class _FakeNebulaSign:
    """Stands in for causb.nebulacli.sign(). Records every call's bound
    arguments (matching sign()'s real parameter list, so a call asserted
    against e.g. `self.calls[0]["groups"]` is correct regardless of
    positional/keyword style) and writes recognizable fake cert (and,
    if out_qr is given, fake QR PNG) bytes to the paths it's given."""

    def __init__(self, raise_exc=None):
        self.calls = []
        self.raise_exc = raise_exc

    def __call__(self, ca_crt, ca_key, in_pub, name, networks, duration, out_crt,
                 *, groups=None, out_qr=None):
        self.calls.append({
            "ca_crt": ca_crt, "ca_key": ca_key, "in_pub": in_pub, "name": name,
            "networks": networks, "duration": duration, "out_crt": out_crt,
            "groups": groups, "out_qr": out_qr,
        })
        if self.raise_exc is not None:
            raise self.raise_exc
        with open(out_crt, "wb") as f:
            f.write(b"FAKE-HOST-CERT-BYTES-" + name.encode())
        if out_qr is not None:
            with open(out_qr, "wb") as f:
                f.write(b"FAKE-QR-PNG-BYTES-" + name.encode())


class _FakeNebulaPrint:
    """Stands in for causb.nebulacli.print_json(). Shaped EXACTLY like the
    real nebula-cert v1.10.3 binary's unwrapped `print -json` dict, verified
    live against the box: a top-level "fingerprint" plus a "notAfter" nested
    under "details" (real output for a signed host cert looks like
    `{"details": {..., "notAfter": "...", "notBefore": "...", ...},
    "fingerprint": "...", "signature": "...", "version": 1}` before
    nebulacli.print_json unwraps the outer one-element array). Defaults to a
    per-call fingerprint/name derived from the cert path's filename stem
    (so a multi-host job gets distinct fingerprints for free); a fixed
    `fingerprint=`/`not_after=` can be forced for re-key tests."""

    def __init__(self, raise_exc=None, fingerprint=None, not_after="2027-01-01T00:00:00Z"):
        self.calls = []
        self.raise_exc = raise_exc
        self.fingerprint = fingerprint
        self.not_after = not_after

    def __call__(self, cert_path):
        self.calls.append(cert_path)
        if self.raise_exc is not None:
            raise self.raise_exc
        stem = os.path.splitext(os.path.basename(cert_path))[0]
        fingerprint = self.fingerprint if self.fingerprint is not None else f"fp-{stem}"
        return {
            "details": {"name": stem, "notAfter": self.not_after, "notBefore": "2026-01-01T00:00:00Z"},
            "fingerprint": fingerprint,
            "version": 1,
        }


class _SignHostsTestBase(unittest.TestCase):
    def setUp(self):
        self.mod = _load_sign_hosts_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-sign-hosts-test-")
        self.ca_dir = os.path.join(self.tmp, "ca")
        os.makedirs(self.ca_dir)
        self.registry_path = os.path.join(self.ca_dir, "registry.json")
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)
        self.payload_dir = os.path.join(self.tmp, "payload")
        os.makedirs(self.payload_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _bootstrap_ca(self, key_bytes=FAKE_CA_KEY_BYTES, crt_bytes=FAKE_CA_CRT_BYTES):
        with open(os.path.join(self.ca_dir, "ca.key"), "wb") as f:
            f.write(key_bytes)
        with open(os.path.join(self.ca_dir, "ca.crt"), "wb") as f:
            f.write(crt_bytes)

    def _write_pub(self, filename, content=b"FAKE-PUBKEY-BYTES"):
        path = os.path.join(self.payload_dir, filename)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def _run(self, job=None, sign=None, pjson=None, out_dir=None, **overrides):
        sign = sign if sign is not None else _FakeNebulaSign()
        pjson = pjson if pjson is not None else _FakeNebulaPrint()
        kwargs = dict(ca_dir=self.ca_dir, registry_path=self.registry_path,
                      nebula_sign=sign, nebula_print=pjson)
        kwargs.update(overrides)
        rc = self.mod.run(job or _job(), self.payload_dir, out_dir or self.out_dir, **kwargs)
        return rc, sign, pjson


# ---------------------------------------------------------------------------
# 1. Happy path, single host.
# ---------------------------------------------------------------------------

class TestHappyPathSingleHost(_SignHostsTestBase):
    def test_signs_web1_with_stable_ip_default_duration_and_writes_artifacts(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})

        rc, sign, pjson = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(sign.calls), 1)
        call = sign.calls[0]
        self.assertEqual(call["name"], "web1")
        self.assertEqual(call["networks"], "10.66.0.10/16")
        self.assertEqual(call["duration"], config.HOST_CERT_DURATION)
        self.assertEqual(call["duration"], "43800h")  # ~5y operator default
        self.assertEqual(call["ca_crt"], os.path.join(self.ca_dir, "ca.crt"))
        self.assertEqual(call["ca_key"], os.path.join(self.ca_dir, "ca.key"))
        self.assertEqual(call["in_pub"], os.path.join(self.payload_dir, "web1.pub"))
        self.assertEqual(call["groups"], [])
        self.assertIsNone(call["out_qr"])

        self.assertEqual(len(pjson.calls), 1)
        self.assertEqual(pjson.calls[0], os.path.join(self.out_dir, "web1.crt"))

        crt_path = os.path.join(self.out_dir, "web1.crt")
        self.assertTrue(os.path.isfile(crt_path))

        alloc_path = os.path.join(self.out_dir, "alloc-web1.json")
        self.assertTrue(os.path.isfile(alloc_path))
        with open(alloc_path) as f:
            alloc = json.load(f)
        self.assertEqual(alloc["name"], "web1")
        self.assertEqual(alloc["ip"], "10.66.0.10")
        self.assertEqual(alloc["fingerprint"], "fp-web1")
        self.assertEqual(alloc["not_after"], "2027-01-01T00:00:00Z")
        self.assertEqual(alloc["seq"], 0)

        out_registry_path = os.path.join(self.out_dir, "registry.json")
        self.assertTrue(os.path.isfile(out_registry_path))
        with open(out_registry_path) as f:
            out_reg = json.load(f)
        self.assertEqual(out_reg["hosts"]["web1"]["ip"], "10.66.0.10")

        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web1"]["ip"], "10.66.0.10")
        self.assertEqual(reg["hosts"]["web1"]["fingerprint"], "fp-web1")
        self.assertEqual(reg["hosts"]["web1"]["not_after"], "2027-01-01T00:00:00Z")


# ---------------------------------------------------------------------------
# 1b. rotate-ca plan Task 1: the full pubkey (not just its hash) is persisted
# into both the on-disk registry and the committed alloc-<name>.json, so a
# future rotate-ca can re-sign every host without the original .pub files.
# ---------------------------------------------------------------------------

class TestPubkeyPersistence(_SignHostsTestBase):
    def test_registry_and_alloc_record_carry_base64_pubkey_of_payload_pub_bytes(self):
        self._bootstrap_ca()
        pub_bytes = b"PAYLOAD-PUBKEY-BYTES-FOR-WEB1"
        self._write_pub("web1.pub", pub_bytes)
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        expected_pubkey_b64 = base64.b64encode(pub_bytes).decode("ascii")

        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web1"]["pubkey"], expected_pubkey_b64)
        # decodes back to the exact original bytes read from the payload
        self.assertEqual(base64.b64decode(reg["hosts"]["web1"]["pubkey"]), pub_bytes)

        with open(os.path.join(self.out_dir, "alloc-web1.json")) as f:
            alloc = json.load(f)
        self.assertEqual(alloc["pubkey"], expected_pubkey_b64)


# ---------------------------------------------------------------------------
# 2. A second host (in a later job) gets the next sequential IP.
# ---------------------------------------------------------------------------

class TestSecondHostGetsNextIp(_SignHostsTestBase):
    def test_second_host_in_a_later_job_gets_next_ip_first_keeps_its_own(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        rc1, _, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc1, self.mod.EXIT_OK)

        self._write_pub("web2.pub", b"PUBKEY-WEB2")
        job2 = _job(job_id="22222222-2222-4222-8222-222222222222",
                     args={"hosts": [{"pub": "web2.pub", "name": "web2"}]})
        rc2, sign2, _ = self._run(job=job2)

        self.assertEqual(rc2, self.mod.EXIT_OK)
        self.assertEqual(sign2.calls[0]["networks"], "10.66.0.11/16")

        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web2"]["ip"], "10.66.0.11")
        self.assertEqual(reg["hosts"]["web1"]["ip"], "10.66.0.10")  # unchanged


# ---------------------------------------------------------------------------
# 3. Re-signing an existing name with a NEW pubkey keeps the IP, updates
#    fingerprint (registry.record's re-key path).
# ---------------------------------------------------------------------------

class TestRekey(_SignHostsTestBase):
    def test_resigning_with_new_pubkey_keeps_ip_and_updates_fingerprint(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1-ORIGINAL")
        rc1, _, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc1, self.mod.EXIT_OK)

        # Re-key: overwrite web1.pub with different bytes, sign again under a
        # NEW job_id (a real re-key happens in a distinct later job).
        self._write_pub("web1.pub", b"PUBKEY-WEB1-REKEYED")
        rekey_print = _FakeNebulaPrint(fingerprint="fp-web1-rekeyed", not_after="2028-06-01T00:00:00Z")
        job2 = _job(job_id="22222222-2222-4222-8222-222222222222",
                     args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc2, sign2, _ = self._run(job=job2, pjson=rekey_print)

        self.assertEqual(rc2, self.mod.EXIT_OK)
        self.assertEqual(sign2.calls[0]["networks"], "10.66.0.10/16")  # same IP re-used

        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web1"]["ip"], "10.66.0.10")  # stable across re-key
        self.assertEqual(reg["hosts"]["web1"]["fingerprint"], "fp-web1-rekeyed")
        self.assertEqual(reg["hosts"]["web1"]["not_after"], "2028-06-01T00:00:00Z")


# ---------------------------------------------------------------------------
# 4. A /32 (or any non-/16) overlay request is rejected: bad_prefix, nothing
#    signed.
# ---------------------------------------------------------------------------

class TestBadPrefix(_SignHostsTestBase):
    def test_32_bit_overlay_override_is_rejected_nothing_signed(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={
            "overlay": "10.42.0.5/32",
            "hosts": [{"pub": "web1.pub", "name": "web1"}],
        })

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_BAD_PREFIX)
        self.assertEqual(sign.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])
        self.assertFalse(os.path.exists(self.registry_path))

    def test_24_bit_overlay_override_is_also_rejected(self):
        # The brief is explicit: ANY non-/16 prefix rejects, not just /32.
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={
            "overlay": "10.42.0.0/24",
            "hosts": [{"pub": "web1.pub", "name": "web1"}],
        })

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_BAD_PREFIX)
        self.assertEqual(sign.calls, [])

    def test_unparseable_overlay_is_bad_manifest_not_bad_prefix(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={
            "overlay": "not-a-cidr-at-all",
            "hosts": [{"pub": "web1.pub", "name": "web1"}],
        })

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# 5. Two .pub files in ONE job: both signed, both allocation records, with a
#    distinct within-job seq tiebreak.
# ---------------------------------------------------------------------------

class TestTwoHostsOneJob(_SignHostsTestBase):
    def test_two_hosts_in_one_job_both_signed_with_distinct_seq_tiebreak(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        self._write_pub("web2.pub", b"PUBKEY-WEB2")
        job = _job(seq=7, args={"hosts": [
            {"pub": "web1.pub", "name": "web1"},
            {"pub": "web2.pub", "name": "web2"},
        ]})

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(sign.calls), 2)
        self.assertEqual({c["name"] for c in sign.calls}, {"web1", "web2"})

        with open(os.path.join(self.out_dir, "alloc-web1.json")) as f:
            alloc1 = json.load(f)
        with open(os.path.join(self.out_dir, "alloc-web2.json")) as f:
            alloc2 = json.load(f)

        self.assertNotEqual(alloc1["seq"], alloc2["seq"])
        # Documented scheme (see module docstring): seq = job_seq * 1000 +
        # within-job index, hosts processed in sorted-by-name order.
        self.assertEqual(alloc1["seq"], 7000)
        self.assertEqual(alloc2["seq"], 7001)

        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web1"]["ip"], "10.66.0.10")
        self.assertEqual(reg["hosts"]["web2"]["ip"], "10.66.0.11")


# ---------------------------------------------------------------------------
# 6. not_bootstrapped when ca.key/ca.crt absent.
# ---------------------------------------------------------------------------

class TestNotBootstrapped(_SignHostsTestBase):
    def test_missing_ca_key_and_crt_returns_not_bootstrapped(self):
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)
        self.assertEqual(sign.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_ca_crt_present_but_ca_key_missing_still_not_bootstrapped(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "wb") as f:
            f.write(FAKE_CA_CRT_BYTES)
        self._write_pub("web1.pub")
        rc, sign, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)
        self.assertEqual(sign.calls, [])

    def test_ca_key_present_but_ca_crt_missing_still_not_bootstrapped(self):
        with open(os.path.join(self.ca_dir, "ca.key"), "wb") as f:
            f.write(FAKE_CA_KEY_BYTES)
        self._write_pub("web1.pub")
        rc, sign, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# 7. ca.key never reaches out_dir (mutation-proof), and ca.crt is never
#    re-delivered here either (already delivered at bootstrap).
# ---------------------------------------------------------------------------

class TestCaKeyNeverInOutDir(_SignHostsTestBase):
    def test_ca_key_bytes_never_appear_anywhere_under_out_dir(self):
        """Mutation-proof: a `shutil.copytree(ca_dir, out_dir)`-style bug
        (copy everything instead of an explicit allowlist) would plant
        ca.key -- and its bytes -- somewhere under out_dir. This walks the
        ENTIRE out_dir tree and checks both filename and byte content, so
        it fails under that exact mutation."""
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        self._write_pub("web2.pub", b"PUBKEY-WEB2")
        job = _job(args={"hosts": [
            {"pub": "web1.pub", "name": "web1", "mobile": True},
            {"pub": "web2.pub", "name": "web2"},
        ]})

        rc, _, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)

        found_files = []
        for root, _dirs, files in os.walk(self.out_dir):
            for name in files:
                found_files.append(os.path.join(root, name))

        self.assertTrue(found_files, "expected out_dir to contain the public artifacts")

        for path in found_files:
            self.assertNotEqual(os.path.basename(path), "ca.key")
            with open(path, "rb") as f:
                content = f.read()
            self.assertNotIn(FAKE_CA_KEY_BYTES, content)

    def test_ca_crt_is_never_copied_into_out_dir_by_sign_hosts(self):
        # ca.crt is delivered once, at ca-bootstrap time -- sign-hosts must
        # not re-deliver it.
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertFalse(os.path.isfile(os.path.join(self.out_dir, "ca.crt")))


# ---------------------------------------------------------------------------
# 8. groups honored; mobile -> QR path requested (and omitted otherwise).
# ---------------------------------------------------------------------------

class TestGroupsAndMobile(_SignHostsTestBase):
    def test_groups_passed_through_to_nebula_sign_and_recorded(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1", "groups": ["web", "prod"]}]})

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["groups"], ["web", "prod"])
        with open(os.path.join(self.out_dir, "alloc-web1.json")) as f:
            alloc = json.load(f)
        self.assertEqual(alloc["groups"], ["web", "prod"])
        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web1"]["groups"], ["web", "prod"])

    def test_mobile_true_requests_qr_output_path_and_writes_it(self):
        self._bootstrap_ca()
        self._write_pub("phone1.pub")
        job = _job(args={"hosts": [{"pub": "phone1.pub", "name": "phone1", "mobile": True}]})

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["out_qr"], os.path.join(self.out_dir, "phone1.png"))
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "phone1.png")))

    def test_mobile_false_or_absent_omits_qr(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})  # mobile absent
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertIsNone(sign.calls[0]["out_qr"])
        self.assertFalse(os.path.isfile(os.path.join(self.out_dir, "web1.png")))


# ---------------------------------------------------------------------------
# 9. A nebula_sign failure mid-job aborts the WHOLE job; the on-disk
#    registry is left completely, byte-for-byte unchanged (reserve-then-
#    commit: no partial update).
# ---------------------------------------------------------------------------

class TestNebulaSignFailureMidJob(_SignHostsTestBase):
    def test_failure_on_second_host_leaves_on_disk_registry_byte_identical(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        rc1, _, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc1, self.mod.EXIT_OK)
        with open(self.registry_path, "rb") as f:
            snapshot = f.read()

        self._write_pub("web2.pub", b"PUBKEY-WEB2")
        self._write_pub("web3.pub", b"PUBKEY-WEB3")

        from causb.nebulacli import NebulaError

        class _FailsOnWeb3:
            def __init__(self):
                self.calls = []

            def __call__(self, ca_crt, ca_key, in_pub, name, networks, duration, out_crt,
                         *, groups=None, out_qr=None):
                self.calls.append(name)
                if name == "web3":
                    raise NebulaError("nebula_failed")
                with open(out_crt, "wb") as f:
                    f.write(b"FAKE-" + name.encode())

        flaky = _FailsOnWeb3()
        job2 = _job(job_id="33333333-3333-4333-8333-333333333333", args={"hosts": [
            {"pub": "web2.pub", "name": "web2"},
            {"pub": "web3.pub", "name": "web3"},
        ]})

        rc2, _, _ = self._run(job=job2, sign=flaky)

        self.assertEqual(rc2, self.mod.EXIT_NEBULA_FAILED)
        self.assertEqual(flaky.calls, ["web2", "web3"])  # web2 processed (sorted first), then web3 raised

        with open(self.registry_path, "rb") as f:
            after = f.read()
        self.assertEqual(after, snapshot)  # byte-identical: web2 never made it in either

        reg = registry.load(self.registry_path)
        self.assertEqual(set(reg["hosts"].keys()), {"web1"})


# ---------------------------------------------------------------------------
# Additional coverage: manifest validation edge cases.
# ---------------------------------------------------------------------------

class TestBadHostEntries(_SignHostsTestBase):
    def test_missing_pub_file_rejected_as_bad_manifest(self):
        self._bootstrap_ca()
        job = _job(args={"hosts": [{"pub": "does-not-exist.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_pub_containing_path_separator_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "../payload/web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_pub_of_dotdot_rejected(self):
        self._bootstrap_ca()
        job = _job(args={"hosts": [{"pub": "..", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_name_containing_path_separator_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "../evil"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_control_char_in_name_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "evil\x00name"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_duplicate_name_in_hosts_list_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        self._write_pub("web1b.pub", b"OTHER-BYTES")
        job = _job(args={"hosts": [
            {"pub": "web1.pub", "name": "web1"},
            {"pub": "web1b.pub", "name": "web1"},
        ]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_empty_hosts_list_rejected(self):
        self._bootstrap_ca()
        job = _job(args={"hosts": []})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_hosts_not_a_list_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": {"pub": "web1.pub", "name": "web1"}})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_host_entry_not_a_dict_rejected(self):
        self._bootstrap_ca()
        job = _job(args={"hosts": ["web1.pub"]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_non_string_groups_entry_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1", "groups": ["ok", 5]}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_non_bool_mobile_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1", "mobile": "yes"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_non_dict_args_falls_back_to_payload_glob(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = {"job_id": "44444444-4444-4444-8444-444444444444", "operation": "sign-hosts",
               "args": ["not", "a", "dict"], "payload": [], "seq": 0}
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["name"], "web1")


# ---------------------------------------------------------------------------
# Fallback: no args.hosts -> every payload/*.pub, name = filename stem.
# ---------------------------------------------------------------------------

class TestFallbackToPayloadGlob(_SignHostsTestBase):
    def test_no_args_hosts_falls_back_to_every_payload_pub_file(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        self._write_pub("web2.pub", b"PUBKEY-WEB2")
        job = _job()  # args={} entirely -- no "hosts" key at all

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual({c["name"] for c in sign.calls}, {"web1", "web2"})
        for c in sign.calls:
            self.assertEqual(c["groups"], [])
            self.assertIsNone(c["out_qr"])
        reg = registry.load(self.registry_path)
        self.assertEqual(set(reg["hosts"].keys()), {"web1", "web2"})

    def test_fallback_ignores_non_pub_files_in_payload_dir(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"PUBKEY-WEB1")
        with open(os.path.join(self.payload_dir, "README.txt"), "w") as f:
            f.write("not a pubkey")
        job = _job()

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual({c["name"] for c in sign.calls}, {"web1"})

    def test_empty_payload_dir_with_no_args_hosts_rejected(self):
        self._bootstrap_ca()
        job = _job()  # no hosts key, no *.pub files either
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# Duration validation.
# ---------------------------------------------------------------------------

class TestDurationValidation(_SignHostsTestBase):
    def test_duration_override_passed_through(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": "24h", "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["duration"], "24h")

    def test_zero_duration_rejected_as_bad_manifest(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": "0h", "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_bare_zero_duration_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": "0", "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_empty_duration_rejected_as_bad_manifest(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": "", "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_non_string_duration_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": 8760, "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_negative_duration_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": "-5h", "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_control_char_in_duration_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"duration": "8760h\x00", "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# job["seq"] validation / defaulting.
# ---------------------------------------------------------------------------

class TestSeqHandling(_SignHostsTestBase):
    def test_missing_seq_key_is_rejected_as_bad_manifest(self):
        # Option A seq-threading (task 4 review): seq is now REQUIRED on the
        # job dict -- box/bin/ca-usb-run stamps it from the manifest's own
        # monotonic seq immediately before dispatch. A job dict WITHOUT seq
        # (a dispatch/orchestrator that failed to thread it) is a wiring bug,
        # NOT a silent seq-0 default (the old, now-removed fallback).
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = {"job_id": "55555555-5555-4555-8555-555555555555", "operation": "sign-hosts",
               "args": {"hosts": [{"pub": "web1.pub", "name": "web1"}]}, "payload": []}
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_stamped_seq_lands_in_alloc_record_with_within_job_tiebreak(self):
        # The (now-required, ca-usb-run-stamped) job seq is exactly what each
        # host's allocation record carries, via the within-job tiebreak
        # seq = job_seq*1000 + sorted-name index.
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        rc, _, _ = self._run(
            job=_job(seq=42, args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc, self.mod.EXIT_OK)
        with open(os.path.join(self.out_dir, "alloc-web1.json")) as f:
            alloc = json.load(f)
        self.assertEqual(alloc["seq"], 42000)

    def test_negative_seq_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(seq=-1, args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_non_int_seq_rejected(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})
        job["seq"] = "not-an-int"
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_bool_seq_rejected(self):
        # bool is an int subclass in Python -- must not silently pass as 0/1.
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})
        job["seq"] = True
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# RegistryError mapping: name_conflict and pool_exhausted.
# ---------------------------------------------------------------------------

class TestRegistryErrorMapping(_SignHostsTestBase):
    def test_name_conflict_when_pubkey_already_bound_to_different_name(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub", b"SHARED-PUBKEY-BYTES")
        rc1, _, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc1, self.mod.EXIT_OK)

        self._write_pub("web2.pub", b"SHARED-PUBKEY-BYTES")  # identical bytes, different name
        job2 = _job(job_id="22222222-2222-4222-8222-222222222222",
                     args={"hosts": [{"pub": "web2.pub", "name": "web2"}]})
        rc2, sign2, _ = self._run(job=job2)

        self.assertEqual(rc2, self.mod.EXIT_NAME_CONFLICT)
        self.assertEqual(sign2.calls, [])
        reg = registry.load(self.registry_path)
        self.assertNotIn("web2", reg["hosts"])

    def test_pool_exhausted_from_registry_allocate_maps_to_dedicated_exit_code(self):
        # registry_cidr can't realistically be exhausted through a manifest
        # override (any non-/16 is rejected as bad_prefix before allocate()
        # ever runs, and a real /16 has 65k+ addresses) -- so this patches
        # causb.registry.allocate at the module-attribute level to simulate
        # the exhausted-pool condition directly, mirroring test_handler_
        # ca_bootstrap.py's TestMainShim precedent of patching a shared
        # causb module attribute for an otherwise hard-to-reach edge case.
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})

        from causb.registry import RegistryError
        original_allocate = self.mod.registry.allocate

        def _exhausted(reg, name, pubkey_bytes, *, overlay_cidr=None, ip_hint=None):
            raise RegistryError("pool_exhausted")

        self.mod.registry.allocate = _exhausted
        try:
            rc, sign, _ = self._run(job=job)
        finally:
            self.mod.registry.allocate = original_allocate

        self.assertEqual(rc, self.mod.EXIT_POOL_EXHAUSTED)
        self.assertEqual(sign.calls, [])

    def test_corrupt_on_disk_registry_maps_to_write_failed(self):
        self._bootstrap_ca()
        with open(self.registry_path, "w") as f:
            f.write("{not valid json at all!!")
        self._write_pub("web1.pub")
        job = _job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]})

        rc, sign, _ = self._run(job=job)

        self.assertEqual(rc, self.mod.EXIT_WRITE_FAILED)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# Reserved host-name deny-list (task 4 review fix 2): a host named "ca" would
# write out_dir/ca.crt (the CA cert's conventional filename), "registry"
# collides with the registry.json topology file's stem -> bad_manifest.
# ---------------------------------------------------------------------------

class TestReservedNames(_SignHostsTestBase):
    def test_host_named_ca_rejected_as_bad_manifest(self):
        self._bootstrap_ca()
        self._write_pub("cahost.pub")
        job = _job(args={"hosts": [{"pub": "cahost.pub", "name": "ca"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])
        self.assertFalse(os.path.isfile(os.path.join(self.out_dir, "ca.crt")))

    def test_host_named_registry_rejected_as_bad_manifest(self):
        self._bootstrap_ca()
        self._write_pub("reghost.pub")
        job = _job(args={"hosts": [{"pub": "reghost.pub", "name": "registry"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_reserved_name_check_is_case_insensitive(self):
        # The vfat stick these certs are delivered onto is case-insensitive,
        # so "CA.crt" would collide with "ca.crt" there.
        self._bootstrap_ca()
        self._write_pub("cahost.pub")
        job = _job(args={"hosts": [{"pub": "cahost.pub", "name": "CA"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_reserved_name_via_fallback_glob_also_rejected(self):
        # A payload file "ca.pub" maps (fallback) to name "ca" -> rejected.
        self._bootstrap_ca()
        self._write_pub("ca.pub")
        rc, sign, _ = self._run(job=_job())  # no args.hosts -> fallback glob
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_a_normal_name_containing_ca_substring_is_fine(self):
        # Only an EXACT (case-insensitive) reserved name is rejected, not a
        # name that merely contains "ca"/"registry".
        self._bootstrap_ca()
        self._write_pub("cache.pub")
        rc, sign, _ = self._run(job=_job(args={"hosts": [{"pub": "cache.pub", "name": "cache"}]}))
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["name"], "cache")


# ---------------------------------------------------------------------------
# Overlay authority (task 4 review fix 3): the registry's overlay_cidr (set at
# ca-bootstrap) is authoritative. sign-hosts allocates into THAT /16; a
# manifest args.overlay that DIFFERS from it -> bad_manifest.
# ---------------------------------------------------------------------------

class TestOverlayAuthority(_SignHostsTestBase):
    def _save_registry(self, overlay_cidr):
        registry.save({"overlay_cidr": overlay_cidr, "hosts": {}}, self.registry_path)

    def test_overlay_derived_from_registry_not_config_default(self):
        # Registry bootstrapped into a NON-default /16; sign-hosts must
        # allocate into that /16, not config.OVERLAY_CIDR.
        self._bootstrap_ca()
        self._save_registry("10.77.0.0/16")
        self._write_pub("web1.pub")
        rc, sign, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["networks"], "10.77.0.10/16")
        reg = registry.load(self.registry_path)
        self.assertEqual(reg["hosts"]["web1"]["ip"], "10.77.0.10")

    def test_manifest_overlay_matching_registry_is_accepted(self):
        self._bootstrap_ca()
        self._save_registry("10.42.0.0/16")
        self._write_pub("web1.pub")
        job = _job(args={"overlay": "10.42.0.0/16",
                          "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(sign.calls[0]["networks"], "10.42.0.10/16")

    def test_manifest_overlay_differing_from_registry_is_bad_manifest(self):
        self._bootstrap_ca()
        self._save_registry("10.42.0.0/16")
        self._write_pub("web1.pub")
        job = _job(args={"overlay": "10.99.0.0/16",
                          "hosts": [{"pub": "web1.pub", "name": "web1"}]})
        rc, sign, _ = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(sign.calls, [])

    def test_registry_bootstrapped_into_a_non_16_overlay_is_bad_prefix(self):
        # Defensive: a box somehow bootstrapped into a non-/16 fails closed on
        # the prefix check even with no manifest overlay at all.
        self._bootstrap_ca()
        self._save_registry("10.0.0.0/8")
        self._write_pub("web1.pub")
        rc, sign, _ = self._run(job=_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))
        self.assertEqual(rc, self.mod.EXIT_BAD_PREFIX)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# main() argv/shim contract, mirrors test_handler_ca_bootstrap.py's
# TestMainShim precedent.
# ---------------------------------------------------------------------------

class TestMainShim(_SignHostsTestBase):
    def _write_job_json(self, job):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump(job, f)
        return path

    def test_main_argv_contract_reads_job_json_and_runs(self):
        self._bootstrap_ca()
        self._write_pub("web1.pub")
        job_path = self._write_job_json(_job(args={"hosts": [{"pub": "web1.pub", "name": "web1"}]}))

        orig_ca_dir = config.CA_DIR
        orig_registry = config.REGISTRY
        from causb import nebulacli as shared_nebulacli
        orig_sign = shared_nebulacli.sign
        orig_print = shared_nebulacli.print_json
        fake_sign = _FakeNebulaSign()
        fake_print = _FakeNebulaPrint()
        config.CA_DIR = self.ca_dir
        config.REGISTRY = self.registry_path
        shared_nebulacli.sign = fake_sign
        shared_nebulacli.print_json = fake_print
        try:
            mod = _load_sign_hosts_module()  # fresh exec -- binds the patched values above
            rc = mod.main(["sign-hosts", job_path, self.payload_dir, self.out_dir])
        finally:
            config.CA_DIR = orig_ca_dir
            config.REGISTRY = orig_registry
            shared_nebulacli.sign = orig_sign
            shared_nebulacli.print_json = orig_print

        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(len(fake_sign.calls), 1)
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "web1.crt")))

    def test_main_wrong_argc_returns_fault(self):
        rc = self.mod.main(["sign-hosts", "only-one-arg"])
        self.assertEqual(rc, self.mod.EXIT_FAULT)

    def test_main_unparseable_job_json_returns_bad_manifest(self):
        path = os.path.join(self.tmp, "bad-job.json")
        with open(path, "w") as f:
            f.write("not json{{{")
        rc = self.mod.main(["sign-hosts", path, self.payload_dir, self.out_dir])
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)

    def test_main_job_json_not_a_dict_returns_bad_manifest(self):
        path = os.path.join(self.tmp, "list-job.json")
        with open(path, "w") as f:
            json.dump(["not", "a", "dict"], f)
        rc = self.mod.main(["sign-hosts", path, self.payload_dir, self.out_dir])
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)


if __name__ == "__main__":
    unittest.main()
