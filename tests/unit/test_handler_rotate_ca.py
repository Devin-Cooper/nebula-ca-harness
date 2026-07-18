"""Tests for box/handlers/rotate-ca: the "rotate-ca" vetted handler (S8; CA
operation handlers plan, Task 2 -- the final, most complex CA operation).
rotate-ca mints a BRAND NEW ca.key/ca.crt ON THE BOX, re-signs every existing
host under the new CA, emits an old+new trust bundle (and, in compromise mode,
a nebula blocklist of the OLD leaf fingerprints), then ATOMICALLY swaps the
new CA in and SECURELY DESTROYS the old ca.key -- all wedge-safe: any failure
before the commit point leaves the OLD CA fully intact, and no ca.key (old or
new) ever reaches out_dir.

This suite's load-bearing properties (each has at least one dedicated test):
  1. The new CA is genuinely v1 (D16 -- nebula-cert `ca` DEFAULTS to
     -version 2, which would silently break the mixed/Android fleet).
  2. NO ca.key -- OLD or NEW -- can reach out_dir under any code path,
     including a "sweep the whole ca_dir" mutation (mutation-proof).
  3. WEDGE-SAFETY: a nebula_sign failure mid-resign leaves the on-box
     ca.key/ca.crt/registry BYTE-for-BYTE unchanged and re-runnable.
  4. The OLD ca.key is gone from ca_dir/ca.key after a successful rotate
     (its bytes are not recoverable from that file) and the OLD ca.crt is
     archived.

box/handlers/rotate-ca is a standalone, extensionless script (like
box/handlers/ca-bootstrap/sign-hosts before it) -- loaded in-process via
importlib exactly like test_handler_sign_hosts.py's `_load_sign_hosts_module()`
precedent, so its `sys.path.append("/usr/local/lib")` + `from causb import ...`
at module scope behave identically to a real standalone invocation.

`nebula_ca`/`nebula_sign`/`nebula_print` are injected fake recorders (mirrors
this project's established `runner=`/DI-seam convention): none ever shells out
to the real nebula-cert binary. Every test uses a fresh tempfile.mkdtemp()
tree for ca_dir/registry/out_dir, never the real /var/lib/nebula-ca.
"""

import base64
import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
import importlib.machinery
import importlib.util

from causb import config, registry
from causb.nebulacli import NebulaError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROTATE_CA_HANDLER_PATH = os.path.join(REPO_ROOT, "box", "handlers", "rotate-ca")

# Recognizable, mutually-non-substring key/cert bytes. The OLD ones are planted
# by _bootstrap_ca; the NEW ones are written by _FakeNebulaCa. Tests assert the
# OLD key bytes are GONE after rotation and that NEITHER key's bytes ever land
# under out_dir.
OLD_CA_KEY_BYTES = b"OLD-CA-PRIVATE-KEY-SECRET-do-not-leak-and-must-be-shredded-11aa"
OLD_CA_CRT_BYTES = b"OLD-CA-PUBLIC-CERT-PEM-BYTES-22bb"
NEW_CA_KEY_BYTES = b"NEW-CA-PRIVATE-KEY-SECRET-do-not-leak-freshly-minted-33cc"
NEW_CA_CRT_BYTES = b"NEW-CA-PUBLIC-CERT-PEM-BYTES-44dd"

PUBKEY_WEB1 = b"PUBKEY-BYTES-WEB1-aaaa"
PUBKEY_WEB2 = b"PUBKEY-BYTES-WEB2-bbbb"


def _load_rotate_ca_module():
    loader = importlib.machinery.SourceFileLoader("rotate_ca_handler_under_test", ROTATE_CA_HANDLER_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _job(args=None, seq=5, job_id="11111111-1111-4111-8111-111111111111"):
    return {
        "job_id": job_id,
        "operation": "rotate-ca",
        "args": {} if args is None else args,
        "payload": [],
        "seq": seq,
    }


class _FakeNebulaCa:
    """Stands in for causb.nebulacli.ca(). Records every call's bound
    arguments and writes recognizable NEW cert/key bytes to the out_crt/
    out_key paths it is given (exactly the brief's fixture description)."""

    def __init__(self, crt_bytes=NEW_CA_CRT_BYTES, key_bytes=NEW_CA_KEY_BYTES, raise_exc=None):
        self.calls = []
        self.crt_bytes = crt_bytes
        self.key_bytes = key_bytes
        self.raise_exc = raise_exc

    def __call__(self, name, curve, version, duration, *, out_crt, out_key):
        self.calls.append({
            "name": name, "curve": curve, "version": version,
            "duration": duration, "out_crt": out_crt, "out_key": out_key,
        })
        if self.raise_exc is not None:
            raise self.raise_exc
        with open(out_crt, "wb") as f:
            f.write(self.crt_bytes)
        with open(out_key, "wb") as f:
            f.write(self.key_bytes)


class _FakeNebulaSign:
    """Stands in for causb.nebulacli.sign(). Records every call and writes
    recognizable host-cert bytes to out_crt. `raise_on_nth` (1-indexed)
    raises `raise_exc` on that call only -- used by the wedge test to fail
    mid-resign (host 2 of 2)."""

    def __init__(self, raise_exc=None, raise_on_nth=None):
        self.calls = []
        self.raise_exc = raise_exc
        self.raise_on_nth = raise_on_nth

    def __call__(self, ca_crt, ca_key, in_pub, name, networks, duration, out_crt,
                 *, groups=None, out_qr=None):
        self.calls.append({
            "ca_crt": ca_crt, "ca_key": ca_key, "in_pub": in_pub, "name": name,
            "networks": networks, "duration": duration, "out_crt": out_crt,
            "groups": groups, "out_qr": out_qr,
            "in_pub_bytes": _read_bytes(in_pub),
        })
        if self.raise_exc is not None and (
            self.raise_on_nth is None or len(self.calls) == self.raise_on_nth
        ):
            raise self.raise_exc
        with open(out_crt, "wb") as f:
            f.write(b"FAKE-HOST-CERT-BYTES-" + name.encode())


class _FakeNebulaPrint:
    """Stands in for causb.nebulacli.print_json(). Returns a fingerprint/
    notAfter shaped like the real nebula-cert v1.10.3 `print -json` (a
    top-level "fingerprint" plus "notAfter" nested under "details"). The
    fingerprint is derived from the cert file's CONTENT so the OLD ca.crt,
    the NEW ca.crt, and each host cert all get distinct, easily-asserted
    fingerprints without coupling to the handler's temp filenames."""

    def __init__(self, raise_exc=None, not_after="2027-06-01T00:00:00Z"):
        self.calls = []
        self.raise_exc = raise_exc
        self.not_after = not_after

    def __call__(self, cert_path):
        self.calls.append(cert_path)
        if self.raise_exc is not None:
            raise self.raise_exc
        data = _read_bytes(cert_path)
        if data == OLD_CA_CRT_BYTES:
            fp = "OLDCAFP"
        elif data == NEW_CA_CRT_BYTES:
            fp = "NEWCAFP"
        else:
            fp = "newfp-" + os.path.splitext(os.path.basename(cert_path))[0]
        return {"fingerprint": fp, "details": {"notAfter": self.not_after}}


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class _RotateCaTestBase(unittest.TestCase):
    def setUp(self):
        self.mod = _load_rotate_ca_module()
        self.tmp = tempfile.mkdtemp(prefix="causb-rotate-ca-test-")
        self.ca_dir = os.path.join(self.tmp, "ca")
        os.makedirs(self.ca_dir, mode=0o700)
        self.registry_path = os.path.join(self.ca_dir, "registry.json")
        self.out_dir = os.path.join(self.tmp, "out")
        os.makedirs(self.out_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def _bootstrap_ca(self, key_bytes=OLD_CA_KEY_BYTES, crt_bytes=OLD_CA_CRT_BYTES):
        key_path = os.path.join(self.ca_dir, "ca.key")
        crt_path = os.path.join(self.ca_dir, "ca.crt")
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        with open(crt_path, "wb") as f:
            f.write(crt_bytes)
        os.chmod(key_path, 0o400)
        os.chmod(crt_path, 0o444)

    def _seed_registry_two_hosts(self):
        """A registry with two bootstrapped hosts (web1, web2) each carrying a
        stored `pubkey` (base64) plus its OLD leaf fingerprint -- exactly what
        sign-hosts would have left behind."""
        reg = {"overlay_cidr": "10.42.0.0/16", "hosts": {}}
        reg = registry.record(reg, "web1", "10.42.0.10", PUBKEY_WEB1,
                              "oldfp-web1", "2026-12-01T00:00:00Z", ["servers", "web"])
        reg = registry.record(reg, "web2", "10.42.0.11", PUBKEY_WEB2,
                              "oldfp-web2", "2026-12-01T00:00:00Z", [])
        registry.save(reg, self.registry_path)
        return reg

    def _run(self, job=None, ca=None, sign=None, pjson=None, out_dir=None, **overrides):
        ca = ca if ca is not None else _FakeNebulaCa()
        sign = sign if sign is not None else _FakeNebulaSign()
        pjson = pjson if pjson is not None else _FakeNebulaPrint()
        kwargs = dict(ca_dir=self.ca_dir, registry_path=self.registry_path,
                      nebula_ca=ca, nebula_sign=sign, nebula_print=pjson)
        kwargs.update(overrides)
        rc = self.mod.run(job or _job(), None, out_dir or self.out_dir, **kwargs)
        return rc, ca, sign, pjson

    def _out_files(self):
        found = []
        for root, _dirs, files in os.walk(self.out_dir):
            for name in files:
                found.append(os.path.join(root, name))
        return found


# ---------------------------------------------------------------------------
# 1. Happy path: the atomic swap.
# ---------------------------------------------------------------------------

class TestHappyPathSwap(_RotateCaTestBase):
    def test_new_ca_swapped_in_with_correct_modes_old_key_gone(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()

        rc, ca, _sign, _pjson = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)

        ca_key_path = os.path.join(self.ca_dir, "ca.key")
        ca_crt_path = os.path.join(self.ca_dir, "ca.crt")

        # The NEW key/cert are in place at the right modes...
        self.assertEqual(_read_bytes(ca_key_path), NEW_CA_KEY_BYTES)
        self.assertEqual(_read_bytes(ca_crt_path), NEW_CA_CRT_BYTES)
        self.assertEqual(self._mode(ca_key_path), 0o400)
        self.assertEqual(self._mode(ca_crt_path), 0o444)

        # ...and the OLD key's bytes are NOT recoverable from ca.key.
        self.assertNotIn(OLD_CA_KEY_BYTES, _read_bytes(ca_key_path))

    def test_old_ca_crt_archived_at_seq_named_path(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run(job=_job(seq=5))

        archived = os.path.join(self.ca_dir, "archive", "ca-5.crt")
        self.assertTrue(os.path.isfile(archived))
        self.assertEqual(_read_bytes(archived), OLD_CA_CRT_BYTES)
        self.assertEqual(self._mode(archived), 0o444)

    def test_old_key_bytes_appear_in_no_named_ca_dir_file_after_rotate(self):
        # After a successful rotate, the OLD private key must not linger in
        # ANY named file under ca_dir (ca.key holds the NEW key; the archive
        # holds only the OLD public cert; the temp ca.key.new is consumed).
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run()
        for root, _dirs, files in os.walk(self.ca_dir):
            for name in files:
                self.assertNotIn(OLD_CA_KEY_BYTES, _read_bytes(os.path.join(root, name)),
                                 f"OLD key bytes lingered in {name}")
        # And no leftover temp new-CA material.
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key.new")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt.new")))

    def test_nebula_ca_called_with_explicit_version_1_curve_and_defaults(self):
        # D16: the single most important call-shape assertion here.
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        _rc, ca, _s, _p = self._run()
        self.assertEqual(len(ca.calls), 1)
        self.assertEqual(ca.calls[0]["version"], "1")
        self.assertEqual(ca.calls[0]["curve"], "25519")
        self.assertEqual(ca.calls[0]["name"], "nebula-ca")
        self.assertEqual(ca.calls[0]["duration"], config.CA_DURATION)


# ---------------------------------------------------------------------------
# 2. The trust bundle = OLD ca.crt bytes ++ NEW ca.crt bytes.
# ---------------------------------------------------------------------------

class TestTrustBundle(_RotateCaTestBase):
    def test_out_dir_bundle_is_old_then_new_ca_crt(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run()
        bundle = os.path.join(self.out_dir, "ca-bundle.crt")
        self.assertTrue(os.path.isfile(bundle))
        self.assertEqual(_read_bytes(bundle), OLD_CA_CRT_BYTES + NEW_CA_CRT_BYTES)

    def test_on_box_bundle_also_written(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run()
        on_box = os.path.join(self.ca_dir, "ca-bundle.crt")
        self.assertTrue(os.path.isfile(on_box))
        self.assertEqual(_read_bytes(on_box), OLD_CA_CRT_BYTES + NEW_CA_CRT_BYTES)
        self.assertEqual(self._mode(on_box), 0o444)


# ---------------------------------------------------------------------------
# 3. Every host re-signed under the NEW CA + registry/alloc updated.
# ---------------------------------------------------------------------------

class TestReSign(_RotateCaTestBase):
    def test_each_host_resigned_against_new_ca_with_stable_ip_and_groups(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        rc, _ca, sign, _p = self._run(job=_job(seq=5))
        self.assertEqual(rc, self.mod.EXIT_OK)

        self.assertEqual(len(sign.calls), 2)
        by_name = {c["name"]: c for c in sign.calls}
        self.assertEqual(set(by_name), {"web1", "web2"})

        # Signed against the NEW CA temp material -- NOT the old ca.crt/ca.key.
        tmp_new_crt = os.path.join(self.ca_dir, "ca.crt.new")
        tmp_new_key = os.path.join(self.ca_dir, "ca.key.new")
        for c in sign.calls:
            self.assertEqual(c["ca_crt"], tmp_new_crt)
            self.assertEqual(c["ca_key"], tmp_new_key)
            self.assertEqual(c["duration"], config.HOST_CERT_DURATION)

        self.assertEqual(by_name["web1"]["networks"], "10.42.0.10/16")
        self.assertEqual(by_name["web2"]["networks"], "10.42.0.11/16")
        self.assertEqual(by_name["web1"]["groups"], ["servers", "web"])
        self.assertEqual(by_name["web2"]["groups"], [])

        # The decoded pubkey handed to nebula_sign is the host's stored one.
        self.assertEqual(by_name["web1"]["in_pub_bytes"], PUBKEY_WEB1)
        self.assertEqual(by_name["web2"]["in_pub_bytes"], PUBKEY_WEB2)

        # Signed host certs are delivered to out_dir.
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "web1.crt")))
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "web2.crt")))

    def test_registry_fingerprints_updated_ip_and_pubkey_preserved(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run()
        reg = registry.load(self.registry_path)
        web1 = reg["hosts"]["web1"]
        self.assertEqual(web1["fingerprint"], "newfp-web1")   # updated
        self.assertEqual(web1["ip"], "10.42.0.10")            # preserved
        self.assertEqual(web1["pubkey"], base64.b64encode(PUBKEY_WEB1).decode())
        self.assertEqual(web1["groups"], ["servers", "web"])
        self.assertEqual(reg["hosts"]["web2"]["fingerprint"], "newfp-web2")

    def test_alloc_record_per_host_carries_pubkey_and_new_fingerprint(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run(job=_job(seq=5))

        with open(os.path.join(self.out_dir, "alloc-web1.json")) as f:
            a1 = json.load(f)
        self.assertEqual(a1["name"], "web1")
        self.assertEqual(a1["ip"], "10.42.0.10")
        self.assertEqual(a1["fingerprint"], "newfp-web1")
        self.assertEqual(a1["pubkey"], base64.b64encode(PUBKEY_WEB1).decode())
        self.assertEqual(a1["pubkey_sha256"], hashlib.sha256(PUBKEY_WEB1).hexdigest())
        self.assertEqual(a1["seq"], 5 * 1000 + 0)   # sorted index 0

        with open(os.path.join(self.out_dir, "alloc-web2.json")) as f:
            a2 = json.load(f)
        self.assertEqual(a2["seq"], 5 * 1000 + 1)   # sorted index 1


# ---------------------------------------------------------------------------
# 4. NO ca.key (old OR new) anywhere under out_dir (mutation-proof).
# ---------------------------------------------------------------------------

class TestNoKeyReachesOutDir(_RotateCaTestBase):
    def test_neither_old_nor_new_key_bytes_appear_under_out_dir(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        rc, _ca, _s, _p = self._run(job=_job(args={"compromise": True}))
        self.assertEqual(rc, self.mod.EXIT_OK)

        found = self._out_files()
        self.assertTrue(found, "expected out_dir to hold the public deliverables")
        for path in found:
            base = os.path.basename(path)
            self.assertNotEqual(base, "ca.key")
            self.assertFalse(base.endswith(".key"), f"unexpected .key file in out_dir: {base}")
            content = _read_bytes(path)
            self.assertNotIn(OLD_CA_KEY_BYTES, content, f"OLD key leaked into {base}")
            self.assertNotIn(NEW_CA_KEY_BYTES, content, f"NEW key leaked into {base}")

    def test_out_dir_allowlist_only_expected_deliverables(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run(job=_job(args={"compromise": True}))
        got = set(os.listdir(self.out_dir))
        expected = {
            "web1.crt", "web2.crt",
            "alloc-web1.json", "alloc-web2.json",
            "ca-bundle.crt", "rotate-receipt.json", "blocklist.json",
        }
        self.assertEqual(got, expected)


# ---------------------------------------------------------------------------
# 5. Compromise mode -> blocklist of the OLD leaf fingerprints.
# ---------------------------------------------------------------------------

class TestCompromiseBlocklist(_RotateCaTestBase):
    def test_compromise_true_writes_blocklist_of_old_fingerprints(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        rc, _ca, _s, _p = self._run(job=_job(args={"compromise": True}))
        self.assertEqual(rc, self.mod.EXIT_OK)

        blocklist_path = os.path.join(self.out_dir, "blocklist.json")
        self.assertTrue(os.path.isfile(blocklist_path))
        with open(blocklist_path) as f:
            bl = json.load(f)
        # Exact nebula config key path: pki.blocklist = [<hex fingerprint>...].
        self.assertEqual(bl, {"pki": {"blocklist": ["oldfp-web1", "oldfp-web2"]}})

    def test_normal_mode_writes_no_blocklist(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run(job=_job(args={"compromise": False}))
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "blocklist.json")))

    def test_blocklist_includes_skipped_hosts_old_fingerprint(self):
        # A compromised OLD cert must be blocklisted even for a host we cannot
        # re-sign (no stored pubkey) -- its old fingerprint is captured too.
        self._bootstrap_ca()
        reg = {"overlay_cidr": "10.42.0.0/16", "hosts": {}}
        reg = registry.record(reg, "web1", "10.42.0.10", PUBKEY_WEB1,
                              "oldfp-web1", "2026-12-01T00:00:00Z", [])
        reg["hosts"]["legacy"] = {"ip": "10.42.0.12", "pubkey_sha256": "x",
                                  "fingerprint": "oldfp-legacy", "not_after": "z",
                                  "groups": []}  # NO pubkey
        registry.save(reg, self.registry_path)

        self._run(job=_job(args={"compromise": True}))
        with open(os.path.join(self.out_dir, "blocklist.json")) as f:
            bl = json.load(f)
        self.assertEqual(bl["pki"]["blocklist"], ["oldfp-legacy", "oldfp-web1"])


# ---------------------------------------------------------------------------
# 6. A host lacking a stored pubkey is skipped, not re-signed.
# ---------------------------------------------------------------------------

class TestSkippedHost(_RotateCaTestBase):
    def _seed_one_signable_one_pubkeyless(self):
        reg = {"overlay_cidr": "10.42.0.0/16", "hosts": {}}
        reg = registry.record(reg, "web1", "10.42.0.10", PUBKEY_WEB1,
                              "oldfp-web1", "2026-12-01T00:00:00Z", [])
        reg["hosts"]["legacy"] = {"ip": "10.42.0.12", "pubkey_sha256": "x",
                                  "fingerprint": "oldfp-legacy", "not_after": "z",
                                  "groups": []}  # NO pubkey key at all
        registry.save(reg, self.registry_path)

    def test_pubkeyless_host_is_skipped_and_not_signed(self):
        self._bootstrap_ca()
        self._seed_one_signable_one_pubkeyless()
        rc, _ca, sign, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)

        signed_names = {c["name"] for c in sign.calls}
        self.assertEqual(signed_names, {"web1"})   # legacy NOT signed

        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "legacy.crt")))
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "alloc-legacy.json")))

        with open(os.path.join(self.out_dir, "rotate-receipt.json")) as f:
            receipt = json.load(f)
        self.assertEqual(receipt["skipped"], ["legacy"])
        self.assertEqual(receipt["hosts_resigned"], 1)

    def test_skipped_host_registry_entry_preserved_unchanged(self):
        self._bootstrap_ca()
        self._seed_one_signable_one_pubkeyless()
        self._run()
        reg = registry.load(self.registry_path)
        # legacy keeps its old fingerprint (never re-signed).
        self.assertEqual(reg["hosts"]["legacy"]["fingerprint"], "oldfp-legacy")
        self.assertEqual(reg["hosts"]["legacy"]["ip"], "10.42.0.12")


# ---------------------------------------------------------------------------
# 7. not_bootstrapped when ca.key is absent -> nothing changed.
# ---------------------------------------------------------------------------

class TestNotBootstrapped(_RotateCaTestBase):
    def test_missing_ca_key_returns_not_bootstrapped_and_touches_nothing(self):
        # No _bootstrap_ca() -- ca.key absent.
        self._seed_registry_two_hosts()
        rc, ca, sign, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)
        self.assertEqual(ca.calls, [])
        self.assertEqual(sign.calls, [])
        self.assertEqual(os.listdir(self.out_dir), [])
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key")))

    def test_ca_crt_present_but_key_absent_still_not_bootstrapped(self):
        with open(os.path.join(self.ca_dir, "ca.crt"), "wb") as f:
            f.write(OLD_CA_CRT_BYTES)
        rc, ca, _s, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_NOT_BOOTSTRAPPED)
        self.assertEqual(ca.calls, [])


# ---------------------------------------------------------------------------
# 8. WEDGE: a nebula_sign failure mid-resign leaves the OLD CA fully intact.
# ---------------------------------------------------------------------------

class TestWedgeSafety(_RotateCaTestBase):
    def test_sign_failure_on_host_2_of_2_leaves_old_ca_byte_unchanged(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()

        ca_key_path = os.path.join(self.ca_dir, "ca.key")
        ca_crt_path = os.path.join(self.ca_dir, "ca.crt")
        key_before = _read_bytes(ca_key_path)
        crt_before = _read_bytes(ca_crt_path)
        reg_before = _read_bytes(self.registry_path)

        failing_sign = _FakeNebulaSign(raise_exc=NebulaError("nebula_failed"), raise_on_nth=2)
        rc, _ca, sign, _p = self._run(sign=failing_sign)

        self.assertNotEqual(rc, 0)
        self.assertEqual(rc, self.mod.EXIT_NEBULA_FAILED)
        self.assertEqual(len(sign.calls), 2)   # attempted web1 (ok) then web2 (raised)

        # The on-box CA is BYTE-for-BYTE unchanged: no swap, no destroyed key.
        self.assertEqual(_read_bytes(ca_key_path), key_before)
        self.assertEqual(_read_bytes(ca_key_path), OLD_CA_KEY_BYTES)
        self.assertEqual(_read_bytes(ca_crt_path), crt_before)
        self.assertEqual(_read_bytes(self.registry_path), reg_before)

        # No archive, no leftover temp new-CA material.
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "archive")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key.new")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt.new")))

    def test_box_is_rerunnable_after_a_mid_resign_failure(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()

        failing_sign = _FakeNebulaSign(raise_exc=NebulaError("nebula_failed"), raise_on_nth=2)
        rc1, _ca, _s, _p = self._run(sign=failing_sign)
        self.assertEqual(rc1, self.mod.EXIT_NEBULA_FAILED)

        # A clean retry (fresh out_dir) rotates successfully.
        shutil.rmtree(self.out_dir)
        os.makedirs(self.out_dir)
        rc2, ca2, sign2, _p2 = self._run()
        self.assertEqual(rc2, self.mod.EXIT_OK)
        self.assertEqual(len(ca2.calls), 1)
        self.assertEqual(len(sign2.calls), 2)
        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.key")), NEW_CA_KEY_BYTES)

    def test_nebula_ca_failure_leaves_old_ca_intact(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        failing_ca = _FakeNebulaCa(raise_exc=NebulaError("nebula_failed"))
        rc, _ca, sign, _p = self._run(ca=failing_ca)
        self.assertEqual(rc, self.mod.EXIT_NEBULA_FAILED)
        self.assertEqual(sign.calls, [])
        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.key")), OLD_CA_KEY_BYTES)
        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.crt")), OLD_CA_CRT_BYTES)
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.key.new")))
        self.assertFalse(os.path.exists(os.path.join(self.ca_dir, "ca.crt.new")))


# ---------------------------------------------------------------------------
# 9. Zero-host registry rotates fine (no re-signs, bundle still written).
# ---------------------------------------------------------------------------

class TestZeroHosts(_RotateCaTestBase):
    def test_empty_registry_rotates_ca_without_error(self):
        self._bootstrap_ca()
        # A fresh, host-less registry (ca-bootstrap's initial shape).
        registry.save({"overlay_cidr": "10.42.0.0/16", "hosts": {}}, self.registry_path)

        rc, ca, sign, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(ca.calls), 1)       # CA still rotated
        self.assertEqual(sign.calls, [])         # nothing to re-sign

        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.key")), NEW_CA_KEY_BYTES)
        bundle = os.path.join(self.out_dir, "ca-bundle.crt")
        self.assertEqual(_read_bytes(bundle), OLD_CA_CRT_BYTES + NEW_CA_CRT_BYTES)

        with open(os.path.join(self.out_dir, "rotate-receipt.json")) as f:
            receipt = json.load(f)
        self.assertEqual(receipt["hosts_resigned"], 0)
        self.assertEqual(receipt["skipped"], [])

    def test_missing_registry_file_treated_as_zero_hosts(self):
        # ca.key/ca.crt present but no registry.json yet -> load() yields an
        # empty registry; rotate should still succeed with zero re-signs.
        self._bootstrap_ca()
        self.assertFalse(os.path.exists(self.registry_path))
        rc, ca, sign, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)
        self.assertEqual(len(ca.calls), 1)
        self.assertEqual(sign.calls, [])


# ---------------------------------------------------------------------------
# 10. The rotate receipt.
# ---------------------------------------------------------------------------

class TestReceipt(_RotateCaTestBase):
    def test_receipt_fields(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run(job=_job(args={"compromise": True}))
        with open(os.path.join(self.out_dir, "rotate-receipt.json")) as f:
            receipt = json.load(f)
        self.assertEqual(receipt["old_ca_fingerprint"], "OLDCAFP")
        self.assertEqual(receipt["new_ca_fingerprint"], "NEWCAFP")
        self.assertEqual(receipt["hosts_resigned"], 2)
        self.assertEqual(receipt["skipped"], [])
        self.assertEqual(receipt["compromise"], True)

    def test_receipt_compromise_false_in_normal_mode(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        self._run()
        with open(os.path.join(self.out_dir, "rotate-receipt.json")) as f:
            receipt = json.load(f)
        self.assertEqual(receipt["compromise"], False)


# ---------------------------------------------------------------------------
# 11. bad_manifest guards (seq/compromise/duration/name) leave the CA intact.
# ---------------------------------------------------------------------------

class TestBadManifest(_RotateCaTestBase):
    def _assert_bad_manifest_no_change(self, job):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        rc, ca, sign, _p = self._run(job=job)
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)
        self.assertEqual(ca.calls, [])
        self.assertEqual(sign.calls, [])
        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.key")), OLD_CA_KEY_BYTES)
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_missing_seq_is_bad_manifest(self):
        job = {"job_id": "x", "operation": "rotate-ca", "args": {}, "payload": []}
        self._assert_bad_manifest_no_change(job)

    def test_none_seq_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(seq=None))

    def test_bool_seq_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(seq=True))

    def test_negative_seq_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(seq=-1))

    def test_non_int_seq_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(seq="5"))

    def test_non_bool_compromise_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(args={"compromise": "yes"}))

    def test_int_compromise_is_bad_manifest(self):
        # 1 is truthy but not a real JSON bool -- reject it.
        self._assert_bad_manifest_no_change(_job(args={"compromise": 1}))

    def test_zero_duration_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(args={"duration": "0h"}))

    def test_control_char_in_name_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(args={"name": "evil\x00ca"}))

    def test_bad_host_duration_is_bad_manifest(self):
        self._assert_bad_manifest_no_change(_job(args={"host_duration": "0"}))


# ---------------------------------------------------------------------------
# 12. Manifest overrides for the new CA.
# ---------------------------------------------------------------------------

class TestManifestOverrides(_RotateCaTestBase):
    def test_name_and_duration_and_host_duration_overrides(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        job = _job(args={"name": "rotated-ca", "duration": "17520h", "host_duration": "4380h"})
        _rc, ca, sign, _p = self._run(job=job)
        self.assertEqual(ca.calls[0]["name"], "rotated-ca")
        self.assertEqual(ca.calls[0]["duration"], "17520h")
        self.assertEqual(ca.calls[0]["version"], "1")   # still v1, never overridable
        for c in sign.calls:
            self.assertEqual(c["duration"], "4380h")

    def test_non_dict_args_falls_back_to_defaults(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        _rc, ca, _s, _p = self._run(job=_job(args=["not", "a", "dict"]))
        self.assertEqual(ca.calls[0]["name"], "nebula-ca")
        self.assertEqual(ca.calls[0]["duration"], config.CA_DURATION)


# ---------------------------------------------------------------------------
# 13. write_failed on a corrupt on-disk registry (fail closed, CA intact).
# ---------------------------------------------------------------------------

class TestCorruptRegistry(_RotateCaTestBase):
    def test_corrupt_registry_is_write_failed_and_ca_untouched(self):
        self._bootstrap_ca()
        with open(self.registry_path, "w") as f:
            f.write("{ this is not valid json")
        rc, ca, sign, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_WRITE_FAILED)
        self.assertEqual(ca.calls, [])
        self.assertEqual(sign.calls, [])
        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.key")), OLD_CA_KEY_BYTES)


# ---------------------------------------------------------------------------
# 14. Collision guard: a host named "ca-bundle" cannot clobber the bundle.
# ---------------------------------------------------------------------------

class TestBundleNameCollision(_RotateCaTestBase):
    def test_host_named_ca_bundle_is_skipped_not_clobbering_the_bundle(self):
        self._bootstrap_ca()
        reg = {"overlay_cidr": "10.42.0.0/16", "hosts": {}}
        reg = registry.record(reg, "web1", "10.42.0.10", PUBKEY_WEB1,
                              "oldfp-web1", "2026-12-01T00:00:00Z", [])
        reg = registry.record(reg, "ca-bundle", "10.42.0.11", PUBKEY_WEB2,
                              "oldfp-cab", "2026-12-01T00:00:00Z", [])
        registry.save(reg, self.registry_path)

        rc, _ca, sign, _p = self._run()
        self.assertEqual(rc, self.mod.EXIT_OK)
        signed = {c["name"] for c in sign.calls}
        self.assertNotIn("ca-bundle", signed)   # skipped to protect the bundle

        # The bundle is the real trust bundle, not a host cert.
        bundle = os.path.join(self.out_dir, "ca-bundle.crt")
        self.assertEqual(_read_bytes(bundle), OLD_CA_CRT_BYTES + NEW_CA_CRT_BYTES)

        with open(os.path.join(self.out_dir, "rotate-receipt.json")) as f:
            receipt = json.load(f)
        self.assertIn("ca-bundle", receipt["skipped"])


# ---------------------------------------------------------------------------
# 15. The __main__ argv shim.
# ---------------------------------------------------------------------------

class TestMainShim(_RotateCaTestBase):
    def _write_job_json(self, job):
        path = os.path.join(self.tmp, "job.json")
        with open(path, "w") as f:
            json.dump(job, f)
        return path

    def test_main_argv_contract_reads_job_json_and_runs(self):
        self._bootstrap_ca()
        self._seed_registry_two_hosts()
        job_path = self._write_job_json(_job())

        orig_ca_dir = config.CA_DIR
        orig_registry = config.REGISTRY
        from causb import nebulacli as shared
        orig_ca, orig_sign, orig_print = shared.ca, shared.sign, shared.print_json
        config.CA_DIR = self.ca_dir
        config.REGISTRY = self.registry_path
        shared.ca = _FakeNebulaCa()
        shared.sign = _FakeNebulaSign()
        shared.print_json = _FakeNebulaPrint()
        try:
            mod = _load_rotate_ca_module()   # fresh exec binds the patched defaults
            rc = mod.main(["rotate-ca", job_path, "unused-payload", self.out_dir])
        finally:
            config.CA_DIR = orig_ca_dir
            config.REGISTRY = orig_registry
            shared.ca, shared.sign, shared.print_json = orig_ca, orig_sign, orig_print

        self.assertEqual(rc, mod.EXIT_OK)
        self.assertEqual(_read_bytes(os.path.join(self.ca_dir, "ca.key")), NEW_CA_KEY_BYTES)

    def test_main_wrong_argc_returns_fault(self):
        rc = self.mod.main(["rotate-ca", "only-one-arg"])
        self.assertEqual(rc, self.mod.EXIT_FAULT)

    def test_main_unparseable_job_json_returns_bad_manifest(self):
        path = os.path.join(self.tmp, "bad-job.json")
        with open(path, "w") as f:
            f.write("not json{{{")
        rc = self.mod.main(["rotate-ca", path, "unused", self.out_dir])
        self.assertEqual(rc, self.mod.EXIT_BAD_MANIFEST)


if __name__ == "__main__":
    unittest.main()
