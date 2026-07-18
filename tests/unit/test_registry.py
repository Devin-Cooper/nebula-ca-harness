"""Tests for causb.registry: the reconcilable host allocation store (S8, R7).

The load-bearing property under test is IP STABILITY: a host's IP must never
change once assigned -- not on re-sign (re-key with a new pubkey), not
across a reconcile() rebuild from committed allocation records, regardless
of the order those records are replayed in. reconcile() is a boot-time
rebuild of registry.json from the authoritative per-job records committed
under results/<job_id>/ (R7) -- a rebuild that reassigned IPs would
invalidate every cert already issued against the old address, so
test_reconcile_is_deterministic_across_shuffled_order and
test_reconcile_keeps_first_seen_ip_across_a_rekey are the two hardest
guards here and are written to fail loudly if that property ever regresses.

A second guard (test_module_never_calls_time_or_random) is a static check
of the module source itself: this store's reproducibility depends on
NEVER consulting a clock or an RNG internally -- not_after and any
ordering/seq key must always arrive as caller-supplied params.
"""

import ast
import base64
import copy
import hashlib
import json
import os
import random
import tempfile
import unittest

from causb import config
from causb.registry import RegistryError, allocate, allocation_record, load, record, reconcile, save


def _empty_reg(overlay_cidr=None):
    return {"overlay_cidr": overlay_cidr or config.OVERLAY_CIDR, "hosts": {}}


class TestAllocate(unittest.TestCase):
    def test_first_three_hosts_get_sequential_ips_after_lighthouse_block(self):
        reg = _empty_reg()

        ip1, reg = allocate(reg, "host-a", b"pubkey-a")
        ip2, reg = allocate(reg, "host-b", b"pubkey-b")
        ip3, reg = allocate(reg, "host-c", b"pubkey-c")

        self.assertEqual(ip1, "10.66.0.10")
        self.assertEqual(ip2, "10.66.0.11")
        self.assertEqual(ip3, "10.66.0.12")
        self.assertEqual(reg["hosts"]["host-a"]["ip"], "10.66.0.10")
        self.assertEqual(reg["hosts"]["host-b"]["ip"], "10.66.0.11")
        self.assertEqual(reg["hosts"]["host-c"]["ip"], "10.66.0.12")

    def test_reallocate_existing_name_returns_same_ip_even_with_different_pubkey(self):
        reg = _empty_reg()
        ip1, reg1 = allocate(reg, "host-a", b"pubkey-original")

        ip2, reg2 = allocate(reg1, "host-a", b"pubkey-AFTER-REKEY")

        self.assertEqual(ip2, ip1)
        self.assertEqual(reg2, reg1)  # unchanged: no new allocation happened

    def test_pubkey_reused_for_different_name_raises_name_conflict(self):
        reg = _empty_reg()
        _, reg = allocate(reg, "host-a", b"shared-pubkey-bytes")

        with self.assertRaises(RegistryError) as ctx:
            allocate(reg, "host-b", b"shared-pubkey-bytes")

        self.assertEqual(ctx.exception.reason, "name_conflict")

    def test_pool_exhausted_past_capacity_on_tiny_overlay(self):
        # /28 = 16 addresses; ipaddress.hosts() yields 14 usable (.1-.14);
        # LIGHTHOUSE_RESERVED=9 eats offsets 1-9, leaving exactly 5
        # allocatable addresses (.10-.14). Allocate all 5 successfully
        # (proving the incrementing/skip logic works), then the 6th call
        # must raise pool_exhausted -- "past capacity", not merely "empty".
        reg = _empty_reg("10.0.0.0/28")
        expected_ips = [f"10.0.0.{n}" for n in range(10, 15)]

        got_ips = []
        for i in range(5):
            ip, reg = allocate(reg, f"host-{i}", f"pubkey-{i}".encode())
            got_ips.append(ip)

        self.assertEqual(got_ips, expected_ips)
        self.assertNotIn("10.0.0.0", got_ips)   # network address never handed out
        self.assertNotIn("10.0.0.15", got_ips)  # broadcast address never handed out

        with self.assertRaises(RegistryError) as ctx:
            allocate(reg, "host-overflow", b"pubkey-overflow")
        self.assertEqual(ctx.exception.reason, "pool_exhausted")

    def test_pool_exhausted_immediately_when_reserved_block_covers_whole_pool(self):
        # /29 has only 6 usable host addresses (.1-.6), ALL inside the
        # lighthouse-reserved block (1..9) -- so even the very FIRST
        # allocation on this tiny pool must fail closed, not silently
        # hand out a "reserved" address.
        reg = _empty_reg("10.0.0.0/29")

        with self.assertRaises(RegistryError) as ctx:
            allocate(reg, "host-a", b"pubkey-a")
        self.assertEqual(ctx.exception.reason, "pool_exhausted")

    def test_ip_hint_honored_when_free_and_uncollided(self):
        reg = _empty_reg()

        ip, reg = allocate(reg, "host-a", b"pubkey-a", ip_hint="10.66.0.50")

        self.assertEqual(ip, "10.66.0.50")
        self.assertEqual(reg["hosts"]["host-a"]["ip"], "10.66.0.50")

    def test_ip_hint_ignored_when_it_collides_with_a_different_name(self):
        reg = _empty_reg()
        taken_ip, reg = allocate(reg, "host-a", b"pubkey-a")  # takes 10.66.0.10

        # host-b hints at host-a's IP; must be ignored (not an error), and
        # normal sequential allocation takes over instead.
        ip, reg = allocate(reg, "host-b", b"pubkey-b", ip_hint=taken_ip)

        self.assertNotEqual(ip, taken_ip)
        self.assertEqual(ip, "10.66.0.11")

    def test_ip_hint_ignored_when_it_targets_the_lighthouse_reserved_block(self):
        reg = _empty_reg()

        ip, reg = allocate(reg, "host-a", b"pubkey-a", ip_hint="10.66.0.5")

        self.assertEqual(ip, "10.66.0.10")  # hint ignored; normal alloc used

    def test_ip_hint_ignored_when_it_targets_network_or_broadcast_address(self):
        reg = _empty_reg("10.0.0.0/28")

        ip, reg = allocate(reg, "host-a", b"pubkey-a", ip_hint="10.0.0.15")
        self.assertEqual(ip, "10.0.0.10")

        ip2, reg = allocate(reg, "host-b", b"pubkey-b", ip_hint="10.0.0.0")
        self.assertEqual(ip2, "10.0.0.11")

    def test_ip_hint_equal_to_names_existing_ip_is_a_harmless_noop(self):
        reg = _empty_reg()
        ip1, reg1 = allocate(reg, "host-a", b"pubkey-a")

        ip2, reg2 = allocate(reg1, "host-a", b"pubkey-a-rekeyed", ip_hint=ip1)

        self.assertEqual(ip2, ip1)
        self.assertEqual(reg2, reg1)

    def test_ip_hint_garbage_string_is_ignored_not_an_error(self):
        reg = _empty_reg()

        ip, reg = allocate(reg, "host-a", b"pubkey-a", ip_hint="not-an-ip-address")

        self.assertEqual(ip, "10.66.0.10")  # fell back to normal allocation

    def test_ip_hint_outside_the_overlay_network_is_ignored(self):
        reg = _empty_reg()  # default overlay is 10.66.0.0/16

        ip, reg = allocate(reg, "host-a", b"pubkey-a", ip_hint="192.168.1.5")

        self.assertEqual(ip, "10.66.0.10")  # fell back to normal allocation


class TestRecord(unittest.TestCase):
    def test_record_does_not_mutate_input_registry(self):
        reg = _empty_reg()
        _, reg = allocate(reg, "host-a", b"pubkey-a")
        snapshot = copy.deepcopy(reg)

        result = record(
            reg, "host-b", "10.42.0.99", b"pubkey-b",
            "fp-b", "2027-01-01T00:00:00Z", ["group1"],
        )

        self.assertEqual(reg, snapshot)  # original untouched
        self.assertNotIn("host-b", reg["hosts"])  # the new host is only in the RETURNED copy
        self.assertIn("host-b", result["hosts"])

    def test_record_updates_pubkey_fingerprint_not_after_groups_but_keeps_ip(self):
        reg = _empty_reg()
        ip, reg = allocate(reg, "host-a", b"pubkey-original")
        reg = record(reg, "host-a", ip, b"pubkey-original", "fp-1", "2027-01-01T00:00:00Z", ["g1"])

        # Re-key: same name+ip, new pubkey/fingerprint/not_after/groups.
        reg2 = record(reg, "host-a", ip, b"pubkey-REKEYED", "fp-2", "2028-06-01T00:00:00Z", ["g2", "g3"])

        host = reg2["hosts"]["host-a"]
        self.assertEqual(host["ip"], ip)  # IP stable across re-key
        self.assertEqual(host["fingerprint"], "fp-2")
        self.assertEqual(host["not_after"], "2028-06-01T00:00:00Z")
        self.assertEqual(host["groups"], ["g2", "g3"])
        self.assertNotEqual(host["pubkey_sha256"], reg["hosts"]["host-a"]["pubkey_sha256"])
        # The full base64 pubkey is re-keyed too, not just its hash.
        self.assertEqual(base64.b64decode(host["pubkey"]), b"pubkey-REKEYED")

    def test_record_stores_base64_pubkey_that_decodes_back_to_original_bytes(self):
        # Task 1 of the rotate-ca plan: record() must ALSO persist the full
        # pubkey (base64-encoded), alongside the existing pubkey_sha256 hash
        # -- rotate-ca needs the actual bytes to re-sign every host under a
        # new CA, and a hash alone cannot be reversed back into them.
        reg = _empty_reg()
        ip, reg = allocate(reg, "host-a", b"pubkey-original-bytes")
        original_bytes = b"pubkey-original-bytes"

        result = record(reg, "host-a", ip, original_bytes, "fp-a", "2027-01-01T00:00:00Z", ["g1"])

        host = result["hosts"]["host-a"]
        self.assertIn("pubkey", host)
        self.assertEqual(base64.b64decode(host["pubkey"]), original_bytes)
        # The existing pubkey_sha256 field is unchanged by this addition.
        self.assertEqual(host["pubkey_sha256"], hashlib.sha256(original_bytes).hexdigest())

    def test_pubkey_round_trips_bytes_with_newlines_and_high_bytes(self):
        # rotate-ca decodes this pubkey and feeds it back to `nebula-cert sign`,
        # so the round-trip must be byte-EXACT for non-ASCII input. Real
        # nebula-cert .pub files are PEM text WITH embedded newlines; this
        # fixture also carries high bytes (0x80-0xFF) and a NUL to lock the
        # property against any accidental str-decode/normalisation. record() ->
        # allocation_record() -> JSON dump/load -> reconcile() -> save()/load()
        # must all preserve the exact bytes.
        raw = (b"-----BEGIN NEBULA CERTIFICATE-----\n"
               b"\x00\x80\xff\xfe\x0a\x0d\x7f\xc3\xa9 mixed \xe2\x9c\x93\n"
               b"-----END NEBULA CERTIFICATE-----\n")
        reg = _empty_reg()
        ip, reg = allocate(reg, "host-bin", raw)
        reg = record(reg, "host-bin", ip, raw, "fp-bin", "2027-01-01T00:00:00Z", [])
        b64 = reg["hosts"]["host-bin"]["pubkey"]
        self.assertEqual(base64.b64decode(b64), raw)
        # Through a committed alloc record + reconcile, the bytes survive intact.
        rec = allocation_record("host-bin", ip, hashlib.sha256(raw).hexdigest(),
                                "fp-bin", "2027-01-01T00:00:00Z", [], seq=1, pubkey=b64)
        round_tripped = json.loads(json.dumps(rec))
        rebuilt = reconcile([round_tripped], config.OVERLAY_CIDR)
        self.assertEqual(base64.b64decode(rebuilt["hosts"]["host-bin"]["pubkey"]), raw)


class TestSaveLoad(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="causb-registry-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_then_load_round_trips_exactly(self):
        path = os.path.join(self.tmp, "sub", "registry.json")
        reg = _empty_reg()
        ip, reg = allocate(reg, "host-a", b"pubkey-a")
        reg = record(reg, "host-a", ip, b"pubkey-a", "fp-a", "2027-01-01T00:00:00Z", ["lighthouse"])

        save(reg, path=path)
        loaded = load(path=path)

        self.assertEqual(loaded, reg)

    def test_load_missing_file_returns_empty_registry_with_default_overlay(self):
        path = os.path.join(self.tmp, "does-not-exist.json")

        reg = load(path=path)

        self.assertEqual(reg, {"overlay_cidr": config.OVERLAY_CIDR, "hosts": {}})

    def test_load_corrupt_json_raises_bad_registry(self):
        path = os.path.join(self.tmp, "corrupt.json")
        with open(path, "w") as f:
            f.write("{not valid json at all!!")

        with self.assertRaises(RegistryError) as ctx:
            load(path=path)
        self.assertEqual(ctx.exception.reason, "bad_registry")

    def test_load_wrong_shape_raises_bad_registry(self):
        path = os.path.join(self.tmp, "wrong-shape.json")
        with open(path, "w") as f:
            json.dump(["not", "a", "registry", "dict"], f)

        with self.assertRaises(RegistryError) as ctx:
            load(path=path)
        self.assertEqual(ctx.exception.reason, "bad_registry")

    def test_load_hosts_not_a_dict_raises_bad_registry(self):
        path = os.path.join(self.tmp, "bad-hosts.json")
        with open(path, "w") as f:
            json.dump({"overlay_cidr": "10.42.0.0/16", "hosts": ["oops"]}, f)

        with self.assertRaises(RegistryError) as ctx:
            load(path=path)
        self.assertEqual(ctx.exception.reason, "bad_registry")

    def test_save_is_atomic_no_tmp_file_left_behind(self):
        path = os.path.join(self.tmp, "registry.json")
        reg = _empty_reg()

        save(reg, path=path)

        self.assertTrue(os.path.isfile(path))
        self.assertFalse(os.path.isfile(path + ".tmp"))


class TestReconcile(unittest.TestCase):
    def _build_records(self):
        """Simulate 5 committed jobs, each allocating one new host, via the
        real allocate()/record() flow -- then package each as the
        allocation_record() dict a job would write to its results dir."""
        reg = _empty_reg()
        records = []
        for i in range(5):
            name = f"host-{i}"
            pubkey = f"pubkey-{i}".encode()
            ip, reg = allocate(reg, name, pubkey)
            fingerprint = f"fp-{i}"
            not_after = f"2027-0{i + 1}-01T00:00:00Z"
            groups = [f"group-{i}"]
            reg = record(reg, name, ip, pubkey, fingerprint, not_after, groups)
            rec = allocation_record(
                name, ip, reg["hosts"][name]["pubkey_sha256"], fingerprint,
                not_after, groups, seq=i,
            )
            records.append(rec)
        return records

    def test_reconcile_is_deterministic_across_shuffled_order(self):
        records = self._build_records()
        shuffled = list(records)
        rng = random.Random(1234)
        while shuffled == records:  # guarantee an actually-different order
            rng.shuffle(shuffled)

        reg_original_order = reconcile(records, config.OVERLAY_CIDR)
        reg_shuffled_order = reconcile(shuffled, config.OVERLAY_CIDR)

        self.assertEqual(reg_original_order, reg_shuffled_order)
        # And pinned to the exact expected name->ip map (not just
        # order-independent -- actually right).
        expected_ips = {f"host-{i}": f"10.66.0.{10 + i}" for i in range(5)}
        got_ips = {name: h["ip"] for name, h in reg_original_order["hosts"].items()}
        self.assertEqual(got_ips, expected_ips)

    def test_reconcile_keeps_first_seen_ip_across_a_rekey_regardless_of_order(self):
        # Two records for the SAME name: an original allocation at seq=1
        # with IP .10, and a later re-key at seq=5. Even if the later
        # record's IP field were ever wrong/corrupted (simulating a bug
        # upstream), reconcile must keep the FIRST-assigned IP -- never
        # let a rebuild reassign an already-issued cert's address.
        first = allocation_record(
            "host-a", "10.42.0.10", "sha-original", "fp-original",
            "2027-01-01T00:00:00Z", [], seq=1,
        )
        rekeyed_same_ip = allocation_record(
            "host-a", "10.42.0.10", "sha-rekeyed", "fp-rekeyed",
            "2028-01-01T00:00:00Z", ["g1"], seq=5,
        )

        for records in ([first, rekeyed_same_ip], [rekeyed_same_ip, first]):
            reg = reconcile(records, config.OVERLAY_CIDR)
            self.assertEqual(reg["hosts"]["host-a"]["ip"], "10.42.0.10")
            # the LATER (higher-seq) record's metadata wins for non-IP fields
            self.assertEqual(reg["hosts"]["host-a"]["fingerprint"], "fp-rekeyed")

    def test_reconcile_metadata_winner_is_deterministic_under_seq_and_name_tie(self):
        # CAop-Task 2 review Minor, folded into CAop-Task 8: the sort key
        # was (seq, name) -- NOT a total order. Two records sharing BOTH the
        # same seq AND the same name (should never happen from the real
        # sign-hosts flow, which mints a unique per-host seq, but reconcile
        # must still behave deterministically rather than trust that) used
        # to resolve their non-IP metadata by whichever order the CALLER
        # happened to list them in (Python's sorted() is stable, so a tied
        # key preserves input order). The IP itself was already stable
        # either way (both records agree on it here); what must now be
        # pinned down is that the WINNING fingerprint/pubkey_sha256 is the
        # same regardless of input order once pubkey_sha256 is folded into
        # the sort key as a tiebreaker.
        rec_a = allocation_record(
            "host-tie", "10.42.0.10", "sha-aaaa", "fp-aaaa",
            "2027-01-01T00:00:00Z", ["ga"], seq=9,
        )
        rec_b = allocation_record(
            "host-tie", "10.42.0.10", "sha-bbbb", "fp-bbbb",
            "2027-06-01T00:00:00Z", ["gb"], seq=9,
        )

        reg_order_ab = reconcile([rec_a, rec_b], config.OVERLAY_CIDR)
        reg_order_ba = reconcile([rec_b, rec_a], config.OVERLAY_CIDR)

        self.assertEqual(reg_order_ab, reg_order_ba)
        # Pinned to the actual deterministic winner (sha-bbbb sorts AFTER
        # sha-aaaa, so it is processed last and its metadata wins) -- not
        # just "equal to itself", which would pass even if BOTH orders were
        # independently order-dependent in some other, still-nondeterministic
        # way.
        self.assertEqual(reg_order_ab["hosts"]["host-tie"]["fingerprint"], "fp-bbbb")
        self.assertEqual(reg_order_ab["hosts"]["host-tie"]["pubkey_sha256"], "sha-bbbb")

    def test_reconcile_builds_registry_from_empty_record_list(self):
        reg = reconcile([], config.OVERLAY_CIDR)

        self.assertEqual(reg, {"overlay_cidr": config.OVERLAY_CIDR, "hosts": {}})

    def test_reconcile_round_trips_pubkey_into_the_rebuilt_host_record(self):
        # rotate-ca's whole reason for existing: a registry rebuilt from
        # committed alloc-*.json records must still carry each host's full
        # pubkey, not just its hash.
        pubkey_b64 = base64.b64encode(b"host-a-real-pubkey-bytes").decode("ascii")
        rec = allocation_record(
            "host-a", "10.42.0.10", "sha-a", "fp-a",
            "2027-01-01T00:00:00Z", ["g1"], seq=1, pubkey=pubkey_b64,
        )

        reg = reconcile([rec], config.OVERLAY_CIDR)

        self.assertEqual(reg["hosts"]["host-a"]["pubkey"], pubkey_b64)

    def test_reconcile_record_missing_pubkey_key_entirely_yields_none_not_a_crash(self):
        # Forward/back-compat: a record dict that simply lacks the "pubkey"
        # key at all (e.g. an alloc-*.json committed before this field
        # existed) must reconcile cleanly to pubkey=None, never KeyError.
        rec = allocation_record(
            "host-b", "10.42.0.11", "sha-b", "fp-b",
            "2027-01-01T00:00:00Z", [], seq=2, pubkey="irrelevant-b64==",
        )
        del rec["pubkey"]

        reg = reconcile([rec], config.OVERLAY_CIDR)

        self.assertIsNone(reg["hosts"]["host-b"]["pubkey"])


class TestAllocationRecord(unittest.TestCase):
    def test_allocation_record_shape(self):
        rec = allocation_record(
            "host-a", "10.42.0.10", "deadbeef", "fp-a",
            "2027-01-01T00:00:00Z", ["g1", "g2"], seq=3,
        )

        self.assertEqual(rec["name"], "host-a")
        self.assertEqual(rec["ip"], "10.42.0.10")
        self.assertEqual(rec["pubkey_sha256"], "deadbeef")
        self.assertEqual(rec["fingerprint"], "fp-a")
        self.assertEqual(rec["not_after"], "2027-01-01T00:00:00Z")
        self.assertEqual(rec["groups"], ["g1", "g2"])
        self.assertEqual(rec["seq"], 3)

    def test_allocation_record_omitting_pubkey_defaults_to_none(self):
        # Pre-existing call sites (and this test itself, unmodified) must
        # keep working with no pubkey= argument at all -- additive field,
        # not a breaking signature change.
        rec = allocation_record(
            "host-a", "10.42.0.10", "deadbeef", "fp-a",
            "2027-01-01T00:00:00Z", ["g1", "g2"], seq=3,
        )

        self.assertIsNone(rec["pubkey"])

    def test_allocation_record_carries_the_supplied_base64_pubkey(self):
        pubkey_b64 = base64.b64encode(b"some-actual-pubkey-bytes").decode("ascii")

        rec = allocation_record(
            "host-a", "10.42.0.10", "deadbeef", "fp-a",
            "2027-01-01T00:00:00Z", ["g1", "g2"], seq=3, pubkey=pubkey_b64,
        )

        self.assertEqual(rec["pubkey"], pubkey_b64)


class TestNoTimeOrRandom(unittest.TestCase):
    def test_module_never_imports_time_random_or_datetime(self):
        # Static guard via the AST (not a text/substring search, which
        # would false-positive on this very docstring's prose): this
        # store's whole determinism/reproducibility story depends on
        # never consulting a clock or an RNG internally. not_after and any
        # ordering/seq key must always be caller-supplied params
        # (sign-hosts passes the cert's real not_after + a seq). A module
        # that never imports time/random/datetime cannot call into them
        # (no bare name would be bound), so checking imports is both
        # sufficient and immune to docstring false positives.
        import causb.registry as registry_module

        with open(registry_module.__file__) as f:
            source = f.read()
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        forbidden = {"time", "random", "datetime"}
        self.assertEqual(
            imported & forbidden, set(),
            f"registry.py must never import time/random/datetime; found: {imported & forbidden}",
        )


if __name__ == "__main__":
    unittest.main()
