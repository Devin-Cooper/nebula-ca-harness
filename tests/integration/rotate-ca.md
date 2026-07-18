# `rotate-ca`: integration notes

`rotate-ca` mints a brand new CA on-box, re-signs every host under it, emits an
old+new trust bundle (and, in compromise mode, a nebula blocklist of the OLD
leaf fingerprints), then atomically swaps the new CA in and destroys the old
`ca.key`. The unit tests (`tests/unit/test_handler_rotate_ca.py`, injected fake
`nebula_ca`/`nebula_sign`/`nebula_print`) prove the wedge-safety, allowlist, and
shred bookkeeping. The one thing they cannot prove — because they never invoke
the real binary — is that a cert this handler re-signs against the freshly
minted CA **actually cryptographically verifies** against the new `ca.crt` (and
no longer against the old one), that the trust bundle is genuinely a
both-CA `pki.ca`, and that the `blocklist.json` shape is the real thing
`nebula` consumes. That is what this integration check proves, against the
box's real `nebula-cert`/`nebula` 1.10.3, in a throwaway `/tmp` directory —
**never** the real `/var/lib/nebula-ca` or `/etc/nebula-ca`.

**Deploy-permission note.** `./deploy.sh`/`./run-tests.sh` (which rsync to
`/opt/nebula-ca/src`) are a separate, deliberate deploy step rather than
something this check triggers itself,
so — exactly as `tests/integration/backup-ca.md` did before it — this check
instead copies only the pieces `rotate-ca` actually needs (`box/lib/causb/` and
`box/handlers/rotate-ca`) into an isolated `/tmp` workdir and runs entirely from
there. This is equally valid proof of the real `nebula-cert` round trip (the
handler's only external dependency besides `causb` is the `nebula-cert`/`nebula`
binary on `PATH`) and never touched `/opt/nebula-ca/src` or any real state.

## What was run

Non-root, over SSH, on `<operator>@<box>` (Python 3.13.5,
nebula-cert 1.10.3):

```bash
WORKDIR="$(mktemp -d /tmp/causb-rotateca-it.XXXXXX)"
# scp'd from the dev checkout (NOT /opt/nebula-ca/src):
#   box/lib/causb        -> $WORKDIR/causb
#   box/handlers/rotate-ca -> $WORKDIR/rotate-ca
#   driver.py            -> $WORKDIR/driver.py   (shown below)
python3 "$WORKDIR/driver.py" "$WORKDIR"
rm -rf "$WORKDIR"   # cleanup
```

`driver.py` (the throwaway integration driver):

```python
import base64, importlib.machinery, importlib.util, json, os, subprocess, sys

WORKDIR = sys.argv[1]
CA_DIR = os.path.join(WORKDIR, "ca"); OUT_DIR = os.path.join(WORKDIR, "out")
REGISTRY = os.path.join(CA_DIR, "registry.json"); ROTATE_CA = os.path.join(WORKDIR, "rotate-ca")
os.makedirs(CA_DIR, mode=0o700, exist_ok=True); os.makedirs(OUT_DIR, exist_ok=True)
sys.path.insert(0, WORKDIR)
from causb import registry

def run(*argv):
    r = subprocess.run(list(argv), capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr

def fp_of(crt):
    rc, out, err = run("nebula-cert", "print", "-json", "-path", crt); assert rc == 0, err
    data = json.loads(out); data = data[0] if isinstance(data, list) else data
    return data["fingerprint"]

# 1. Real CA (v1) + one real host, signed by that CA.
old_ca_crt = os.path.join(CA_DIR, "ca.crt"); old_ca_key = os.path.join(CA_DIR, "ca.key")
assert run("nebula-cert", "ca", "-name", "it-ca", "-curve", "25519", "-version", "1",
           "-duration", "43800h", "-out-crt", old_ca_crt, "-out-key", old_ca_key)[0] == 0
os.chmod(old_ca_key, 0o400); os.chmod(old_ca_crt, 0o444)
host_pub = os.path.join(WORKDIR, "web1.pub"); host_key = os.path.join(WORKDIR, "web1.key")
assert run("nebula-cert", "keygen", "-curve", "25519", "-out-pub", host_pub, "-out-key", host_key)[0] == 0
old_host_crt = os.path.join(WORKDIR, "web1-old.crt")
assert run("nebula-cert", "sign", "-ca-crt", old_ca_crt, "-ca-key", old_ca_key, "-in-pub", host_pub,
           "-name", "web1", "-networks", "10.42.0.10/16", "-duration", "8760h",
           "-version", "1", "-out-crt", old_host_crt)[0] == 0
pub_bytes = open(host_pub, "rb").read(); old_host_fp = fp_of(old_host_crt)

# 2. Registry carrying the host's pubkey (exactly as sign-hosts would leave it).
reg = registry.record({"overlay_cidr": "10.42.0.0/16", "hosts": {}}, "web1", "10.42.0.10",
                      pub_bytes, old_host_fp, "2027-06-01T00:00:00Z", ["servers"])
registry.save(reg, REGISTRY)
old_ca_key_bytes = open(old_ca_key, "rb").read(); old_ca_crt_bytes = open(old_ca_crt, "rb").read()

# 3. Run the REAL rotate-ca (real nebulacli defaults; compromise mode).
loader = importlib.machinery.SourceFileLoader("rotate_ca_it", ROTATE_CA)
mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader)); loader.exec_module(mod)
rc = mod.run({"job_id": "it", "operation": "rotate-ca", "args": {"compromise": True}, "payload": [], "seq": 7},
             None, OUT_DIR, ca_dir=CA_DIR, registry_path=REGISTRY)
assert rc == mod.EXIT_OK, f"rotate-ca rc={rc}"

new_ca_crt = os.path.join(CA_DIR, "ca.crt"); new_ca_key = os.path.join(CA_DIR, "ca.key")
archived_old = os.path.join(CA_DIR, "archive", "ca-7.crt")
new_host_crt = os.path.join(OUT_DIR, "web1.crt"); bundle = os.path.join(OUT_DIR, "ca-bundle.crt")

# 4a. Old ca.key destroyed; 4b. old ca.crt archived byte-for-byte.
new_ca_key_bytes = open(new_ca_key, "rb").read()
assert new_ca_key_bytes != old_ca_key_bytes and old_ca_key_bytes not in new_ca_key_bytes
assert open(archived_old, "rb").read() == old_ca_crt_bytes

# 4c. Re-signed host VERIFIES vs NEW ca.crt, NOT vs OLD.
assert run("nebula-cert", "verify", "-ca", new_ca_crt, "-crt", new_host_crt)[0] == 0
assert run("nebula-cert", "verify", "-ca", archived_old, "-crt", new_host_crt)[0] != 0

# 4d. The trust bundle verifies BOTH old- and new-CA-signed host certs.
assert run("nebula-cert", "verify", "-ca", bundle, "-crt", old_host_crt)[0] == 0
assert run("nebula-cert", "verify", "-ca", bundle, "-crt", new_host_crt)[0] == 0
assert open(bundle, "rb").read() == old_ca_crt_bytes + open(new_ca_crt, "rb").read()

# 4e. blocklist.json is the real nebula pki.blocklist shape; feed it to `nebula -test`.
bl = json.load(open(os.path.join(OUT_DIR, "blocklist.json")))
assert bl == {"pki": {"blocklist": [old_host_fp]}}, bl
cfg = os.path.join(WORKDIR, "nebula-test.yml")
open(cfg, "w").write(
    f"pki:\n  ca: {new_ca_crt}\n  cert: {new_host_crt}\n  key: {host_key}\n"
    f"  blocklist:\n    - {old_host_fp}\n"
    "static_host_map: {}\nlighthouse:\n  am_lighthouse: false\n"
    "listen:\n  host: 0.0.0.0\n  port: 0\ntun:\n  disabled: true\n"
    "firewall:\n  outbound:\n    - port: any\n      proto: any\n      host: any\n"
    "  inbound:\n    - port: any\n      proto: any\n      host: any\n")
assert run("nebula", "-test", "-config", cfg)[0] == 0   # nebula accepts our blocklist fingerprint

# 4f. No ca.key anywhere under out_dir; no key bytes leaked.
for r, _d, fs in os.walk(OUT_DIR):
    for n in fs:
        assert n != "ca.key" and not n.endswith(".key")
        data = open(os.path.join(r, n), "rb").read()
        assert old_ca_key_bytes not in data and new_ca_key_bytes not in data
print("INTEGRATION PASS")
```

## Real output (verbatim, this run)

```
rotate-ca rc = 0 (EXIT_OK)
old ca.key destroyed; new ca.key in place (mode 400)
old ca.crt archived at archive/ca-7.crt
verify re-signed host vs NEW ca.crt: rc=0 (pass); vs OLD ca.crt: rc=1 (correctly rejected)
bundle verifies OLD host cert: rc=0; NEW host cert: rc=0 (bundle contains both CAs)
bundle bytes == old ca.crt ++ new ca.crt
blocklist.json = {"pki": {"blocklist": ["acd936b24d26c3e3721bf21f93e1cacc1ae3ad3289939a59a3079e5c922dccb7"]}}
nebula -test with our blocklist fingerprint: rc=0 (config accepted)
out_dir: ['alloc-web1.json', 'blocklist.json', 'ca-bundle.crt', 'rotate-receipt.json', 'web1.crt'] -- no ca.key, no key bytes
receipt: {"compromise": true, "hosts_resigned": 1, "new_ca_fingerprint": "ea09566150b1d8b80715d0b1967191d886af64b15fb20d3abd93836fbe2ea130", "old_ca_fingerprint": "50447dbd0bdbc9f19678d097eec489db7708fb0de167e156a9fab83c49586716", "skipped": []}
INTEGRATION PASS
```

The 42-test unit suite was additionally run on the box's real Python 3.13.5
(Debian 13 target), mirroring the repo layout in a second throwaway `/tmp` dir:
`Ran 42 tests ... OK`.

Post-run cleanup, independently confirmed:

```
$ rm -rf /tmp/causb-rotateca-it.M7tc8b /tmp/causb-rotateca-ut.sHjUFh
$ ls -d /tmp/causb-rotateca-*
ls: cannot access '/tmp/causb-rotateca-*': No such file or directory
$ ls -la /var/lib/nebula-ca/ca/ca.key
ls: cannot access '/var/lib/nebula-ca/ca/ca.key': Permission denied   # never had access
```

The last line confirms this SSH session never had — and so structurally could
not have used — write access to the real state directory; every path `run()`
touched (`ca_dir`, `registry_path`, `out_dir`) was an explicit throwaway-tmpdir
override the whole time.

## What this proves (that the unit tests cannot)

- **The real crypto.** A host cert this handler re-signed against the
  freshly-minted CA genuinely verifies against the NEW `ca.crt` (`nebula-cert
  verify` rc=0) and is genuinely rejected by the OLD, archived `ca.crt` (rc=1)
  — the actual signature chain changed, not just a fake fingerprint string.
- **The trust bundle is a real both-CA `pki.ca`.** `nebula-cert verify -ca
  ca-bundle.crt` accepts BOTH a cert signed by the old CA and one signed by the
  new CA — the transition trust window works as intended during a rollout.
- **The blocklist format is exactly what nebula consumes.** `nebula -test`
  loads a real config whose `pki.blocklist` is the fingerprint from our
  `blocklist.json` and exits 0 (config accepted). Confirmed against the source
  too (`pki.go`: `bl := c.GetStringSlice("pki.blocklist", …)` → each entry
  `caPool.BlocklistFingerprint(fp)`) — `pki.blocklist` is a `[]string` of
  cert-fingerprint hex strings, precisely the `nebula-cert print -json`
  `fingerprint` value `causb.registry` stores per host. `rotate-ca` emits it as
  the ready-to-merge config fragment `{"pki": {"blocklist": [...]}}` (JSON is
  valid YAML, so it drops straight into a nebula config / `config.d`).
- **The old `ca.key` is genuinely gone** and no `ca.key` (old or new) nor any
  key bytes appear anywhere under `out_dir` — proven against the REAL minted
  keys, not fixtures.

## Scope / what this does NOT cover

- **The raw-disk shred.** The in-place overwrite of the retired old key's inode
  is best-effort against forensic recovery and, on a journaling/CoW filesystem,
  not guaranteed to overwrite the original physical blocks (see the handler's
  module docstring). No integration check can portably prove
  a block-level wipe; this check proves the observable guarantee (old key gone
  from the namespace, new key live, no leak).
- **The mid-resign wedge / bad-manifest / not-bootstrapped paths.** Exhaustively
  covered by the unit suite against injected fakes (`TestWedgeSafety`,
  `TestBadManifest`, `TestNotBootstrapped`), which is where a `nebula_sign`
  failure can be induced deterministically; re-triggering them against the real
  binary would add nothing and risks a flaky test.
- **`caj`/`caj-recv` delivery of the deliverables back to the Mac.** Out of
  scope here — the existing `causb.collect`/`commitlog`/`mac/caj-recv`
  pipeline owns getting `out_dir`'s contents onto the outbox (mirrors
  `ca-bootstrap.md`/`backup-ca.md`'s identical scope note).
