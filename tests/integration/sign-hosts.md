# `sign-hosts`: integration notes

No hardware dependency (no LED/K1/USB stick) -- like `ca-bootstrap` before
it, this handler's only real-world surface is `nebula-cert` itself, so the
one thing unit tests (injected fake `nebula_sign`/`nebula_print`) cannot
prove is that the REAL binary, called with this handler's exact argv,
actually produces a **v1** host cert with the right `networks` that a real
CA accepts. That is what this integration check is designed to prove,
against the box's real `nebula-cert v1.10.3`, in a throwaway directory
under `/tmp` -- **never** the real `/var/lib/nebula-ca` or `/etc/nebula-ca`.

## Execution status

Read-only probes against the box (below) are proven live; the
handler-level run against deployed code is written and ready but requires
`./deploy.sh` (or `./run-tests.sh`) to have staged the new handler code on
the box first -- that deploy step is deliberately never run as an
unattended, automatic production write (same posture as
`tests/integration/airgap.md`'s identical note). Two things follow from
that:

1. The **probes** in the "What was independently confirmed live" section
   below were actually run against the real box -- they are
   read-only/throwaway (mint-and-delete under `/tmp`, no repo code
   deployed) and directly shaped this handler's implementation (the
   backdating finding, and the exact `print -json` shape the fingerprint/
   notAfter extraction code depends on).
2. The **handler-level run** (the script in "Procedure" below, executing
   `box/handlers/sign-hosts` itself against a real CA/host keypair) is
   written and ready, exactly like `ca-bootstrap.md`'s own precedent, but
   has **not yet been executed** against deployed code -- it requires the
   new handler code to actually be present on the box first (`./deploy.sh`
   or equivalent). Whoever next has deploy
   permission for this box should run the "Procedure" script
   verbatim and record its real output in the "Real output" section below,
   the same way `ca-bootstrap.md` records its own.

## What was independently confirmed live (read-only)

Non-root, over SSH, no passwordless sudo available either (same useful
proof point `ca-bootstrap.md` recorded: nothing below needs root):

```bash
D=$(mktemp -d /tmp/sign-hosts-probe.XXXXXX)
cd "$D"
nebula-cert ca -name "probe-ca" -curve 25519 -version 1 -duration 43800h -out-crt ca.crt -out-key ca.key
nebula-cert keygen -curve 25519 -out-pub host.pub -out-key host.key
nebula-cert sign -ca-crt ca.crt -ca-key ca.key -in-pub host.pub -name web1 \
    -networks 10.42.0.10/16 -duration 8760h -version 1 -out-crt host.crt -groups g1,g2
nebula-cert print -json -path host.crt
nebula-cert verify -ca ca.crt -crt host.crt
rm -rf "$D"
```

Real output (verbatim):

```
=== print -json (host cert) ===
[{"details":{"curve":"CURVE25519","groups":["g1","g2"],"isCa":false,
"issuer":"cc982c3d27ad854131765eeba30807a28004a6b68b0d2e0d5bfa7ee19620d2d0",
"name":"web1","networks":["10.42.0.10/16"],"notAfter":"2027-07-14T02:18:02Z",
"notBefore":"2026-07-14T02:18:02Z",
"publicKey":"d2c3a4851732826403ede933938eb019bcc315131cd1d136747f542ca49c635f",
"unsafeNetworks":[]},
"fingerprint":"02ac836f779e49bdd5003ef751b3ec979167db4a4fbdf5cd976f940875b15350",
"signature":"3dc96fa948150cdccf0cb254b9eec0917a5c51fae70c513cc0ce3ce58817e8fe...",
"version":1}]

=== verify ===
(no output -- exit 0 -- accepted)
```

This confirms three things this handler's implementation depends on
directly:

1. **`nebula-cert print -json`'s real shape.** `fingerprint` is top-level;
   `notAfter`/`notBefore` are nested one level down under `"details"`. This
   is exactly what `box/handlers/sign-hosts`'s `run()` assumes when it does
   `details.get("fingerprint")` / `(details.get("details") or
   {}).get("notAfter")` against `nebula_print`'s return value -- verified
   against the real binary, not just inferred from the spec's prose.
2. **Backdating: `nebula-cert sign -h` (v1.10.3, this box) lists no
   `-notBefore`/backdate flag at all** -- only `-ca-crt -ca-key -duration
   -groups -in-pub -ip -name -networks -out-crt -out-key -out-qr -subnets
   -unsafe-networks -version`. The live signed cert's `notBefore`
   (`2026-07-14T02:18:02Z`) is exactly the real signing instant, confirming
   there is no way to backdate a cert through this CLI version. See
   `config.BACKDATE`'s docstring for the full
   implication: the 5-minute skew is a mesh-side (peer clock) tolerance
   policy, never a backdated `notBefore`, and `causb.nebulacli.sign()`
   has no parameter for it either way.
3. **A CA's own duration bounds what it can sign.** The first attempt at
   this probe (a 1-hour CA signing an 8760h host cert) failed with `Error:
   error while signing: certificate expires after signing certificate` --
   nebula-cert refuses to sign a cert that would outlive its issuing CA.
   Not itself a sign-hosts concern (the box's real CA is minted with
   `config.CA_DURATION = "43800h"`, comfortably longer than
   `config.HOST_CERT_DURATION = "8760h"`), but worth recording here since it
   shaped how this probe (and the procedure below) must mint its throwaway
   CA.

`nebula-cert verify -ca ca.crt -crt host.crt` accepted the cert silently
(exit 0) -- confirms `nebula-cert verify`'s exact flag names (`-ca`, `-crt`)
for the procedure below, and that a normally-signed v1 host cert against its
own CA verifies clean.

## Procedure (handler-level; run once this box has the new code deployed)

```bash
cd /opt/nebula-ca/src
THROWAWAY="$(mktemp -d /tmp/sign-hosts-integration.XXXXXX)"
CA_DIR="$THROWAWAY/ca"; OUT_DIR="$THROWAWAY/out"; PAYLOAD_DIR="$THROWAWAY/payload"
mkdir -p "$OUT_DIR" "$PAYLOAD_DIR"

# 1. A real, throwaway CA -- long enough duration to outlive the host cert.
nebula-cert ca -name "integration-ca" -curve 25519 -version 1 -duration 43800h \
    -out-crt "$CA_DIR/ca.crt" -out-key "$CA_DIR/ca.key"

# 2. A real host keypair, placed as this job's payload.
nebula-cert keygen -curve 25519 -out-pub "$PAYLOAD_DIR/web1.pub" -out-key "$THROWAWAY/web1.key"

PYTHONPATH=box/lib python3 - "$CA_DIR" "$OUT_DIR" "$PAYLOAD_DIR" <<'PYEOF'
import importlib.machinery, importlib.util, json, os, sys
ca_dir, out_dir, payload_dir = sys.argv[1], sys.argv[2], sys.argv[3]

loader = importlib.machinery.SourceFileLoader("sign_hosts_integration", "box/handlers/sign-hosts")
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

job = {
    "job_id": "44444444-4444-4444-8444-444444444444",
    "operation": "sign-hosts",
    "args": {"hosts": [{"pub": "web1.pub", "name": "web1", "groups": ["web"]}]},
    "payload": ["web1.pub"],
    "seq": 1,
}
registry_path = os.path.join(ca_dir, "registry.json")

# nebula_sign/nebula_print are NOT overridden here -- this calls the REAL
# causb.nebulacli.sign()/print_json(), which shell out to the REAL
# nebula-cert binary.
rc = mod.run(job, payload_dir, out_dir, ca_dir=ca_dir, registry_path=registry_path)
print("run() rc =", rc)
assert rc == mod.EXIT_OK, f"expected EXIT_OK, got {rc}"

crt_path = os.path.join(out_dir, "web1.crt")
assert os.path.isfile(crt_path)
assert not os.path.exists(os.path.join(out_dir, "ca.key")), "ca.key LEAKED to out_dir!"
assert not os.path.exists(os.path.join(out_dir, "ca.crt")), "ca.crt re-delivered by sign-hosts!"

with open(os.path.join(out_dir, "alloc-web1.json")) as f:
    print("alloc-web1.json:", f.read())
with open(registry_path) as f:
    print("registry.json:", f.read())
PYEOF

echo "--- nebula-cert print -json against the REAL signed host cert ---"
nebula-cert print -json -path "$CA_DIR/../out/web1.crt" 2>/dev/null || \
    nebula-cert print -json -path "$OUT_DIR/web1.crt"

echo "--- nebula-cert verify against the REAL CA ---"
nebula-cert verify -ca "$CA_DIR/ca.crt" -crt "$OUT_DIR/web1.crt" && echo "VERIFY OK"

echo "--- cleanup ---"
rm -rf "$THROWAWAY"
ls "$THROWAWAY" 2>&1 || echo "throwaway dir removed OK"
```

Expected (not yet re-confirmed against the deployed handler --
see "Execution status" above; based on the read-only probe's already-confirmed
`nebula-cert` behavior, `run()`'s own logic, and the unit suite's identical
assertions against the fake):

- `run() rc = 0`.
- `web1.crt` exists under `$OUT_DIR`; `nebula-cert print -json` on it shows
  `"version":1`, `"networks":["10.42.0.10/16"]`, `"name":"web1"`,
  `"groups":["web"]`.
- `nebula-cert verify -ca ca.crt -crt web1.crt` accepts it silently (exit 0).
- `alloc-web1.json` shows `{"name": "web1", "ip": "10.42.0.10", ...,
  "seq": 1000}` (job seq 1 * 1000 + within-job index 0).
- `registry.json` (both under `$CA_DIR` and copied to `$OUT_DIR`) shows
  `web1` at `10.42.0.10` with the real fingerprint and `not_after` the CA
  actually issued.
- Neither `ca.key` nor `ca.crt` appear anywhere under `$OUT_DIR`.
- `$THROWAWAY` is fully removed; the real `/var/lib/nebula-ca` and
  `/etc/nebula-ca` are never read from or written to at any point --
  `ca_dir`/`registry_path`/`out_dir`/`payload_dir` are all explicit tmpdir
  paths passed to `run()`'s injectable keyword arguments throughout.

## Real output

*(pending -- fill in verbatim once the procedure above is actually executed
against the deployed handler; see "Execution status" above for why this
run stops at the already-confirmed read-only probe instead.)*

## Fault-injection expectation: replay returns identical bytes

This is a **harness-level** property, not something `sign-hosts` itself
implements or needs to. `causb.commitlog.commit()`'s own docstring is
explicit: "If `results/<job_id>/DONE` already exists and is valid, this is
a silent no-op: the job was already committed, and D22 requires a retry to
replay those exact bytes rather than accept new ones." Concretely: if the
SAME `job_id` is ever submitted a second time (a stick reinsertion, a retry
after a crash between commit and delivery), `box/bin/ca-usb-run` /
`causb.commitlog` detect the existing `DONE` marker BEFORE `dispatch.run()`
would ever invoke `sign-hosts` again, and serve the previously-committed
`results/<job_id>/` bytes verbatim -- `sign-hosts` is never re-executed for
a job_id that already has a durable `DONE`, so it cannot itself produce
divergent output on replay.

This is worth spelling out because `sign-hosts`'s own per-host work is
**not** independently idempotent at the byte level: two genuinely separate
real `nebula-cert sign` invocations against identical inputs (same CA, same
pubkey, same name/networks/duration) do NOT produce byte-identical cert
files -- each signature embeds `notBefore=now` (a fresh wall-clock read
every call; confirmed live above) and nebula's Ed25519 signing is
non-deterministic across processes. What IS guaranteed, and IS this
handler's own responsibility, is the property `causb.registry.allocate()`
provides directly: a **name** that already has an IP keeps that exact IP
forever, so a legitimate re-sign of the same host under a NEW job_id (not a
replay -- a deliberate re-key) is stable on the one
axis that actually matters operationally (the overlay address), even though
the cert bytes themselves differ every time by design (a fresh `notBefore`,
a fresh signature). Byte-for-byte replay identity is what `commitlog`
guarantees for a repeated `job_id`; IP stability is what `sign-hosts` (via
`causb.registry`) guarantees for a repeated **name** across different
job_ids. Neither one is the other, and this handler was built, and its unit
suite written, to keep that distinction clear (see e.g.
`TestNebulaSignFailureMidJob` and `TestRekey` in
`tests/unit/test_handler_sign_hosts.py`).

## Scope / what this does NOT cover

- **The handler-level run against deployed code** (see "Execution status"
  above) -- written, not yet executed.
- **Root ownership / real `/var/lib/nebula-ca`.** Never touched, on
  purpose, exactly like `ca-bootstrap.md`'s identical stance -- this box is
  pre-air-gap; the real bootstrap and subsequent real sign-hosts runs are
  operator-run, physical-session actions.
- **`caj`/`caj-recv` delivery of `out_dir`'s contents back to the
  operator's Mac.** Out of scope here -- the existing
  `causb.collect`/`commitlog`/`mac/caj-recv` pipeline
  already owns getting `out_dir`'s contents onto the outbox
  and back to the Mac; this check only had to prove `out_dir` ends up with
  the right, key-free content, and that the real `nebula-cert` calls behind
  it behave as the unit suite's fakes assume.
- **`registry.reconcile()`'s cross-job boot-time rebuild.** No caller for
  it exists yet anywhere in this codebase (confirmed by search -- it is
  pure library code awaiting a future caller); this handler only had to
  produce correctly-shaped `allocation_record()` dicts for that future
  caller to consume, which the unit suite (`TestTwoHostsOneJob`,
  `TestSeqHandling`) verifies directly.
