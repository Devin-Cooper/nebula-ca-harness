"""Stable-by-name host IP allocation store, reconcilable from committed job
records (spec S8, R7).

**Why this exists.** The `sign-hosts` handler (built next) needs to hand
every mesh host a stable overlay IP by name, and remember the pubkey it was
last signed with. This module is that allocation store: `allocate()`
decides (or recalls) a host's IP, `record()` persists what was actually
signed against it, and `load()`/`save()` move the whole thing to/from
`registry.json` as one atomic JSON blob.

**registry.json is a CACHE, not the source of truth (R7).** The
authoritative record of every allocation lives inside the committed,
crash-atomic `results/<job_id>/` directories `causb.commitlog` already
guarantees are durable (see that module's docstring). `registry.json` is a
convenience projection of those records, rebuilt from scratch on boot by
`reconcile()` -- exactly the same "derived cache, never independently
authoritative" relationship `causb.commitlog`'s own seq/consumed-jobs
caches have to their `DONE` markers. This is why `allocation_record()`
exists as a distinct, smaller shape from a full registry host entry: it is
the flat, self-contained fact `sign-hosts` writes into its own job's
results directory (`{"name","ip","pubkey_sha256","pubkey","fingerprint",
"not_after","groups","seq"}`), and `reconcile()`'s only input is a list of
those. A full registry host entry carries the same fields minus `name`
(the dict key IS the name) and `seq` (a replay-ordering detail with no
place in the rebuilt registry itself): `{"ip","pubkey_sha256","pubkey",
"fingerprint","not_after","groups"}`.

**`pubkey` is the full public key, base64-encoded,
alongside the pre-existing `pubkey_sha256` hash.** The hash alone cannot be
reversed back into the original bytes; a later `rotate-ca` operation that
must re-sign every existing host under a brand new CA needs those bytes on
hand, on-box, without requiring every operator to re-submit every host's
`.pub` file again. `record()` derives both `pubkey_sha256` and `pubkey` from
the same `pubkey_bytes` it is already handed; `allocation_record()` accepts
`pubkey` as an optional (default `None`) keyword so it threads through to
the committed record and back out again via `reconcile()`. A record that
predates this field (or otherwise omits it) reconciles to `pubkey: None`
rather than raising -- the same forward/back-compat stance `groups` already
takes via `rec.get("groups") or []` below.

**IP stability is the property an adversarial rebuild must never break.**
Certs this harness issues embed a `networks` field baked from the IP at
signing time; if a `registry.json` rebuild ever handed an already-used name
a DIFFERENT IP, every cert issued against the old address would silently
stop matching the registry a future `sign-hosts` run consults. Three
separate mechanisms hold this invariant:
  1. `allocate()`'s first check is always "does this name already have an
     IP" -- if so, that IP is returned UNCONDITIONALLY (even across a
     re-key with a brand new pubkey), never re-derived.
  2. `record()` always takes `ip` as a caller-supplied param (traced back
     to an earlier `allocate()` call) rather than ever computing one --
     re-keying a name updates its pubkey/fingerprint/not_after/groups but
     the `ip` field is simply carried through untouched.
  3. `reconcile()` replays every record in a fixed, deterministic order
     (sorted by the `seq` each record carries -- see below) and, when two
     records name the SAME host, keeps the IP from the FIRST one processed
     in that order and only lets LATER records update the non-IP fields.
     Because the sort order never depends on the input list's order, this
     holds regardless of what order the caller happened to hand records in
     (a boot-time directory listing has no guaranteed order) -- this is
     the property `test_registry.py`'s
     `test_reconcile_is_deterministic_across_shuffled_order` and
     `test_reconcile_keeps_first_seen_ip_across_a_rekey_regardless_of_order`
     exist specifically to pin down.

**No time/random anywhere in this module.** `not_after` and the `seq`
ordering key `allocation_record()`/`reconcile()` rely on for determinism
both arrive as caller-supplied params -- `sign-hosts` is expected to pass
the signed cert's real `not_after` and the job's own manifest `seq` (S7.5's
already-monotonic, harness-enforced per-job counter -- a perfect, free,
collision-free ordering key, since dispatch's `jobs:1` cap means each
committed job produces at most one allocation record). Calling
`time.time()`/`datetime.now()`/anything in `random` here would make
`reconcile()` non-reproducible across a rebuild, exactly the failure mode
R7 exists to prevent.

**allocate()'s two-phase relationship with record().** `allocate()` alone
already writes a PARTIAL host entry into the registry dict it returns --
just `{"ip", "pubkey_sha256"}` -- rather than waiting for `record()`. This
is deliberate, not an oversight: the `name_conflict` check (a pubkey
already bound to a different name) must see every allocation made so far
within the SAME in-memory reconciliation pass, including ones `record()`
hasn't been called for yet (e.g. two back-to-back `allocate()` calls for
two different new names before either is signed). The trade-off is that a
registry saved between an `allocate()` and its matching `record()` would
contain a partial entry missing `fingerprint`/`not_after`/`groups` -- this
is never actually reachable in the real `sign-hosts` flow (which always
completes `allocate() -> sign the cert -> record() -> save()` before ever
calling `save()`), and `load()`'s shape validation only requires an "ip"
key to be present per host, so a partial entry round-trips cleanly if it
ever were saved.

**Trust scope.** Like `causb.commitlog`, this module's `reg`/`records`
inputs are harness-internal values already produced by this module's own
functions (or, for `reconcile()`, by `allocation_record()`) -- not raw wire
bytes. `load()` is the one function that reads arbitrary bytes off disk (a
`registry.json` that could in principle be corrupted by a crash or
tampering) and is accordingly the one place this module raises the
wire-style `RegistryError("bad_registry")` for a structurally-invalid
file; `reconcile()`'s `records` are assumed well-formed the way
`commitlog.commit()`'s `outputs` are.
"""

import base64
import hashlib
import ipaddress
import json
import os

from causb import config


class RegistryError(Exception):
    """A registry operation failed. `reason` is one of the fixed enum
    strings `"bad_registry"` (registry.json missing/unparseable/wrong
    shape), `"name_conflict"` (a pubkey is already bound to a different
    name -- prevents duplicate identity), or `"pool_exhausted"` (no free IP
    remains in the overlay /16). This is a wire-adjacent contract other
    handlers (`sign-hosts`) key off of; the strings must not change.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _empty_registry():
    return {"overlay_cidr": config.OVERLAY_CIDR, "hosts": {}}


def _clone_registry(reg):
    """A registry dict that shares no mutable top-level container with
    `reg`: a fresh outer dict and a fresh `hosts` mapping. Individual
    per-host dicts for names NOT being touched by this call are shared by
    reference with the original -- harmless, since every write path in
    this module only ever installs a brand new per-host dict rather than
    mutating one in place, so no caller can observe the aliasing."""
    return {"overlay_cidr": reg["overlay_cidr"], "hosts": dict(reg["hosts"])}


def _is_well_formed(reg) -> bool:
    """Structural check `load()` uses to decide bad_registry: a dict with
    a string `overlay_cidr`, a dict `hosts`, and every host entry itself a
    dict with at least a string `ip`. Deliberately does NOT require
    `pubkey_sha256`/`fingerprint`/`not_after`/`groups` to be present -- see
    the module docstring's note on allocate()'s partial entries."""
    if not isinstance(reg, dict):
        return False
    if not isinstance(reg.get("overlay_cidr"), str):
        return False
    hosts = reg.get("hosts")
    if not isinstance(hosts, dict):
        return False
    for name, host in hosts.items():
        if not isinstance(name, str) or not isinstance(host, dict):
            return False
        if not isinstance(host.get("ip"), str):
            return False
    return True


def load(path=config.REGISTRY) -> dict:
    """Read the JSON registry at `path`. Absent file -> a fresh empty
    registry (`{"overlay_cidr": config.OVERLAY_CIDR, "hosts": {}}` -- a box
    that has never allocated a host has no registry yet). Corrupt bytes or
    a structurally-wrong shape -> `RegistryError("bad_registry")`, never a
    raw json.JSONDecodeError/KeyError escaping to the caller.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return _empty_registry()

    try:
        reg = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        raise RegistryError("bad_registry")

    if not _is_well_formed(reg):
        raise RegistryError("bad_registry")

    return reg


def _fsync_dir(path: str) -> None:
    """Mirrors causb.commitlog._fsync_dir exactly (see that module's
    docstring for the full rationale): fsync `path` as a directory so a
    pending rename/create of a child ENTRY in it is made durable. Kept as
    a local copy rather than an import -- each module's on-disk-durability
    helper stays self-contained, the same precedent commitlog._read_seq /
    freshness._last_seq already set."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(dir_path: str, name: str, data: bytes) -> None:
    """Mirrors causb.commitlog._atomic_write exactly: tmp sibling -> write
    -> fsync the fd -> close -> os.replace into place. Does NOT fsync
    `dir_path` itself -- callers pair this with `_fsync_dir(dir_path)`."""
    final_path = os.path.join(dir_path, name)
    tmp_path = final_path + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)


def save(reg: dict, path=config.REGISTRY) -> None:
    """Durably write `reg` as JSON to `path`: tmp -> fsync -> rename ->
    fsync the PARENT directory (mirrors `causb.commitlog`'s durability
    pattern exactly -- see `_atomic_write`/`_fsync_dir` above). The parent
    directory is created first (`exist_ok=True`) so this works on a fresh
    box before `CA_DIR` has otherwise been populated.
    """
    dir_path = os.path.dirname(path)
    name = os.path.basename(path)
    os.makedirs(dir_path, exist_ok=True)
    data = json.dumps(reg, indent=2, sort_keys=True).encode()
    _atomic_write(dir_path, name, data)
    _fsync_dir(dir_path)


def _offset(addr, network) -> int:
    """Host offset of `addr` within `network`: 0 for the network address
    itself, 1 for the first host address, etc."""
    return int(addr) - int(network.network_address)


def _is_allocatable(addr, network) -> bool:
    """True if `addr` is a candidate for host allocation: not the network
    or broadcast address, and past the lighthouse-reserved block (offsets
    1..LIGHTHOUSE_RESERVED, i.e. X.X.0.1-X.X.0.9 for the default /16)."""
    if addr in (network.network_address, network.broadcast_address):
        return False
    return _offset(addr, network) > config.LIGHTHOUSE_RESERVED


def _next_free_ip(network, assigned) -> str:
    """The next allocatable address in `network` (in ascending order, past
    the lighthouse-reserved block) not already present in `assigned`.
    `network.hosts()` already excludes the network/broadcast addresses on
    its own for any ordinary prefix; `_is_allocatable`'s own check of the
    same thing is redundant here but harmless, and IS load-bearing for
    `_resolve_ip_hint` below, which reuses it against a value `.hosts()`
    never produced in the first place."""
    for addr in network.hosts():
        if not _is_allocatable(addr, network):
            continue
        ip_str = str(addr)
        if ip_str not in assigned:
            return ip_str
    raise RegistryError("pool_exhausted")


def _resolve_ip_hint(ip_hint, network, assigned):
    """Return the canonical string form of `ip_hint` if it is usable (box
    is authoritative, per the module contract: a hint is honored ONLY when
    it is free-and-uncollided), else `None` -- callers fall back to
    `_next_free_ip` rather than raising on a bad hint."""
    try:
        addr = ipaddress.ip_address(ip_hint)
    except ValueError:
        return None
    if addr not in network:
        return None
    if not _is_allocatable(addr, network):
        return None
    ip_str = str(addr)
    if ip_str in assigned:
        return None
    return ip_str


def allocate(reg: dict, name: str, pubkey_bytes: bytes, *, overlay_cidr=None, ip_hint=None):
    """Return `(ip, reg2)`: the stable overlay IP for `name`, and the
    registry dict reflecting that allocation.

    If `name` already has an IP, it is returned UNCONDITIONALLY -- even if
    `pubkey_bytes` differs from whatever is currently on file for it (a
    re-key keeps the IP; see module docstring) -- and `reg` is returned
    untouched (no new registry object is built; nothing changed).

    Otherwise a NEW name is being allocated:
      - `RegistryError("name_conflict")` if `pubkey_bytes` (compared by its
        sha256) is already bound to any OTHER existing name -- prevents two
        names sharing one identity.
      - the next free address in `ipaddress.ip_network(overlay_cidr or
        reg["overlay_cidr"])` is handed out, skipping the network address,
        the lighthouse-reserved block (`config.LIGHTHOUSE_RESERVED` host
        offsets), the broadcast address, and any IP already assigned to
        another host; `RegistryError("pool_exhausted")` if none remains.
      - `ip_hint`, if given, is used INSTEAD of the next free address, but
        ONLY if it is itself a free, non-reserved, in-range address; an
        unusable hint is silently ignored (never raises) and normal
        sequential allocation proceeds.

    The returned `reg2` for a new name already carries a (partial) host
    entry -- see the module docstring's note on why `allocate()` cannot
    defer that to `record()`.
    """
    hosts = reg["hosts"]
    if name in hosts:
        return hosts[name]["ip"], reg

    pubkey_sha256 = hashlib.sha256(pubkey_bytes).hexdigest()
    for other_name, host in hosts.items():
        if host.get("pubkey_sha256") == pubkey_sha256:
            raise RegistryError("name_conflict")

    network = ipaddress.ip_network(overlay_cidr or reg["overlay_cidr"], strict=False)
    assigned = {host["ip"] for host in hosts.values()}

    ip = None
    if ip_hint is not None:
        ip = _resolve_ip_hint(ip_hint, network, assigned)
    if ip is None:
        ip = _next_free_ip(network, assigned)

    reg2 = _clone_registry(reg)
    reg2["hosts"][name] = {"ip": ip, "pubkey_sha256": pubkey_sha256}
    return ip, reg2


def record(reg: dict, name: str, ip: str, pubkey_bytes: bytes, fingerprint, not_after, groups) -> dict:
    """Return a NEW registry dict (the input `reg` is never mutated) with
    `name`'s host entry recorded/updated: `pubkey_sha256` (derived here
    from `pubkey_bytes`), `pubkey` (the FULL key, base64-encoded -- also
    derived here from `pubkey_bytes`; a hash alone
    cannot be reversed back into the bytes a future rotate-ca needs to
    re-sign this host under a new CA), `fingerprint`, `not_after`, and
    `groups` are all (re)written; `ip` is simply stored as given -- always
    the value an earlier `allocate()` call returned, so a re-key never
    changes it.
    """
    reg2 = _clone_registry(reg)
    reg2["hosts"][name] = {
        "ip": ip,
        "pubkey_sha256": hashlib.sha256(pubkey_bytes).hexdigest(),
        "pubkey": base64.b64encode(pubkey_bytes).decode("ascii"),
        "fingerprint": fingerprint,
        "not_after": not_after,
        "groups": list(groups) if groups else [],
    }
    return reg2


def allocation_record(name, ip, pubkey_sha256, fingerprint, not_after, groups, *, seq, pubkey=None) -> dict:
    """The flat, self-contained per-job record `sign-hosts` writes into its
    own `results/<job_id>/` output (R7): everything `reconcile()` needs to
    replay this one allocation, with no reference to any other job's
    record. `seq` is a caller-supplied ordering key -- `sign-hosts` is
    expected to pass the job's own manifest `seq` (S7.5's already-monotonic,
    harness-enforced per-job counter), NEVER a value derived from `time` or
    `random` here (see module docstring) -- used only so `reconcile()` can
    sort records into a fixed, deterministic replay order.

    `pubkey` is the same base64-encoded full key
    `record()` stores, so a committed `alloc-<name>.json` carries it and a
    `reconcile()` rebuild can restore it. Keyword-only with a `None`
    default -- purely additive: existing call sites that never pass it keep
    working, and the resulting record's `pubkey` is `None` rather than the
    keyword being required.
    """
    return {
        "name": name,
        "ip": ip,
        "pubkey_sha256": pubkey_sha256,
        "pubkey": pubkey,
        "fingerprint": fingerprint,
        "not_after": not_after,
        "groups": list(groups) if groups else [],
        "seq": seq,
    }


def reconcile(records: list, overlay_cidr) -> dict:
    """Rebuild a full registry from `records` (each an `allocation_record()`
    dict) -- the boot-time repair pass over every committed job's own
    allocation record (R7's "registry.json is a rebuildable cache").

    DETERMINISTIC by construction: `records` is sorted by the TOTAL order
    `(seq, name, pubkey_sha256)` BEFORE anything is replayed, so the
    processing order -- and therefore every name's assigned IP -- depends
    only on the records' OWN content, never on the order the caller
    happened to list them in (a directory scan has no guaranteed order).
    When more than one record names the same host (a re-key across two
    different jobs), the IP from the FIRST-processed (lowest `seq`) record
    wins and is kept for every later one; only the non-IP fields
    (pubkey_sha256/fingerprint/not_after/groups) are updated from the later
    record. This is what makes a rebuild safe to run repeatedly and in any
    listing order without ever invalidating an already-issued cert's
    address.

    `pubkey_sha256` is folded into the sort key as a THIRD tiebreaker:
    `(seq, name)` alone left the
    non-IP metadata winner input-order-dependent, since `sorted()` is
    stable and leaves a tied key in whatever order the CALLER listed the
    records. The key is now total OVER `(seq, name, pubkey_sha256)` -- which
    is SUFFICIENT because `seq` is unique per committed job (sign-hosts
    mints a distinct per-host seq -- see its own within-job tiebreak scheme
    -- and dispatch's `jobs:1` cap means one committed job yields at most
    one record per host), so a `(seq, name)` collision, let alone a full
    three-field one, cannot arise from the real flow at all. A hypothetical
    record pair sharing all THREE key fields yet differing in
    fingerprint/not_after/groups WOULD still resolve by input order -- but
    that is unreachable given the unique-per-job seq, and it does not matter
    anyway: the IP, the one property a rebuild must never destabilize, stays
    fixed under ANY tie regardless (reconcile replays each record's own ip
    and keeps the first-seen one per name). This tiebreaker only fixes which
    record's non-IP metadata a rebuild keeps under a `(seq, name)`
    collision.
    """
    reg = {"overlay_cidr": overlay_cidr, "hosts": {}}
    for rec in sorted(records, key=lambda r: (r["seq"], r["name"], r["pubkey_sha256"])):
        name = rec["name"]
        ip = rec["ip"]
        existing = reg["hosts"].get(name)
        if existing is not None:
            ip = existing["ip"]  # first-seen IP always wins -- never reassign
        reg["hosts"][name] = {
            "ip": ip,
            "pubkey_sha256": rec["pubkey_sha256"],
            # .get(), not ["pubkey"]: a record from BEFORE this field existed
            # may lack the key entirely -- that must
            # reconcile to None, never KeyError (forward/back-compat).
            "pubkey": rec.get("pubkey"),
            "fingerprint": rec["fingerprint"],
            "not_after": rec["not_after"],
            "groups": list(rec.get("groups") or []),
        }
    return reg
