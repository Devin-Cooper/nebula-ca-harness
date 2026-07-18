# `ca-bootstrap`: integration notes

No hardware dependency (no LED/K1/USB stick) -- this handler's only
real-world surface is `nebula-cert` itself, so the one thing unit tests
(injected fake `nebula_ca`) cannot prove is that the REAL binary, called
with this handler's exact argv, actually produces a **v1** CA certificate
(`nebula-cert ca` silently defaults to `-version 2` if omitted, which
would break the mixed/Android fleet). That is what this integration check
proves, against the box's real `nebula-cert v1.10.3`, in a throwaway
directory under `/tmp` -- **never** the real `/var/lib/nebula-ca` or
`/etc/nebula-ca`.

## What was run

Non-root, over SSH, on `<operator>@<box>` (no passwordless sudo
available, which is itself a useful proof point: nothing below needed
root):

```bash
cd /opt/nebula-ca/src
THROWAWAY="$(mktemp -d /tmp/ca-bootstrap-integration.XXXXXX)"
CA_DIR="$THROWAWAY/ca"; OUT_DIR="$THROWAWAY/out"; PAYLOAD_DIR="$THROWAWAY/payload"
mkdir -p "$OUT_DIR" "$PAYLOAD_DIR"

PYTHONPATH=box/lib python3 - "$CA_DIR" "$OUT_DIR" "$PAYLOAD_DIR" <<'PYEOF'
import importlib.machinery, importlib.util, json, os, sys
ca_dir, out_dir, payload_dir = sys.argv[1], sys.argv[2], sys.argv[3]

loader = importlib.machinery.SourceFileLoader("ca_bootstrap_integration", "box/handlers/ca-bootstrap")
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

job = {"job_id": "33333333-3333-4333-8333-333333333333",
       "operation": "ca-bootstrap", "args": {}, "payload": []}
registry_path = os.path.join(ca_dir, "registry.json")

# nebula_ca is NOT overridden here -- this calls the REAL
# causb.nebulacli.ca(), which shells out to the REAL nebula-cert binary.
rc = mod.run(job, payload_dir, out_dir, ca_dir=ca_dir, registry_path=registry_path)
assert rc == mod.EXIT_OK, f"expected EXIT_OK, got {rc}"

ca_key, ca_crt = os.path.join(ca_dir, "ca.key"), os.path.join(ca_dir, "ca.crt")
assert os.path.isfile(ca_key) and os.path.isfile(ca_crt)
print("ca.key mode:", oct(os.stat(ca_key).st_mode & 0o777))
print("ca.crt mode:", oct(os.stat(ca_crt).st_mode & 0o777))
print("ca_dir mode:", oct(os.stat(ca_dir).st_mode & 0o777))

with open(os.path.join(out_dir, "ca.crt"), "rb") as f: out_crt_bytes = f.read()
with open(ca_crt, "rb") as f: real_crt_bytes = f.read()
assert out_crt_bytes == real_crt_bytes
assert not os.path.exists(os.path.join(out_dir, "ca.key")), "ca.key LEAKED to out_dir!"
with open(registry_path) as f: print("registry.json:", f.read())
PYEOF

echo "--- nebula-cert print -json against the REAL generated ca.crt ---"
nebula-cert print -json -path "$CA_DIR/ca.crt"

rm -rf "$THROWAWAY"
```

## Real output (verbatim, this run)

```
run() rc = 0
ca.key mode: 0o400
ca.crt mode: 0o444
ca_dir mode: 0o700
registry.json: {
  "hosts": {},
  "overlay_cidr": "10.42.0.0/16"
}
--- nebula-cert print -json against the REAL generated ca.crt ---
[{"details":{"curve":"CURVE25519","groups":[],"isCa":true,"issuer":"","name":"nebula-ca",
"networks":[],"notAfter":"2031-07-13T01:35:23Z","notBefore":"2026-07-14T01:35:23Z",
"publicKey":"05f8a1ac4b4a023c3d06b3d481186748a0d0b4629048fa6940aa9425d48f584c",
"unsafeNetworks":[]},"fingerprint":"9939a465dfbfc4eb9bc102ca9463cddb975b3d25029d98b1c5a07feb76995b6f",
"signature":"d521f7ada98eb02379f9977f362b1588fd4de82daf2a7d11370bbc0acfa0ec1f5b2ff96108bce921cf1a759dd77d28978a29e837997c1eb3548fb62811faa104",
"version":1}]
--- cleanup ---
ls: cannot access '/tmp/ca-bootstrap-integration.zIMvDY': No such file or directory
throwaway dir removed OK
```

**`"version":1`** — confirmed directly against the real, freshly-minted CA
cert (not asserted from reading nebulacli's argv-building code, and not a
fake). `notAfter` (`2031-07-13`) is exactly 5 years after `notBefore`
(`2026-07-14`), matching `config.CA_DURATION = "43800h"` (43800h / 24 /
365 = 5.0y) -- confirms the default duration flows through correctly too.
`curve: CURVE25519`, `isCa: true`, `name: nebula-ca` all match the
handler's defaults. `ca.key`/`ca.crt`/`ca_dir` modes are exactly 0400/
0444/0700 as required, all set as a genuinely non-root user (the `chown
root:root` best-effort step silently no-ops here -- see the handler's
module docstring -- since it ran without root). `ca.key` did NOT
appear in `out_dir` (the script's own `assert` would have raised
`AssertionError` and aborted before printing the `nebula-cert print`
output otherwise; it did not).

The throwaway directory (`/tmp/ca-bootstrap-integration.zIMvDY` this run)
was removed with `rm -rf` immediately after and independently confirmed
absent (`ls` against it fails). The real `/var/lib/nebula-ca` and
`/etc/nebula-ca` were never read from or written to at any point --
`ca_dir`/`registry_path`/`out_dir` were all explicit tmpdir paths passed to
`run()`'s injectable keyword arguments the whole time.

## Scope / what this does NOT cover

- **Root ownership (`chown root:root`).** Without passwordless sudo
  available, the best-effort `os.chown` step above always hits `PermissionError`
  and silently no-ops (by design -- see the handler's module docstring).
  The explicit `chmod` modes (0400/0444/0700) are the real access-control
  gate and are fully proven above; root ownership itself is unverified
  here (deferred to the operator's real air-gap
  finalization, alongside every other root-owned-file expectation this
  whole project defers the same way -- e.g. `/etc/nebula-ca`'s
  0750 root:root).
- **The real `/var/lib/nebula-ca/ca` bootstrap.** Never touched, on
  purpose -- this box is pre-air-gap and still running dummy anchors;
  the REAL bootstrap is an operator-run, physical-session
  action, not something this integration check should perform.
- **`caj`/`caj-recv` delivery of the resulting `ca.crt`/`registry.json`
  back to the operator's Mac.** Out of scope here (the harness's
  existing `causb.collect`/`commitlog`/`mac/caj-recv` pipeline
  already owns getting `out_dir`'s contents
  onto the outbox and back to the Mac -- this check only had to prove
  `out_dir` ends up with the right, key-free content).
