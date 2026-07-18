# `backup-ca`: integration notes

No hardware dependency (no LED/K1/USB stick) -- this handler's only
real-world surface is the `age` binary itself, so the one thing unit tests
(injected fake `age_run`) cannot prove is that the REAL `age` binary,
called with this handler's exact argv (`age -R <recipient_path> -o
<out_path> <in_path>`), produces a ciphertext that a real, independently
generated `age` identity can actually decrypt back to the original bytes.
That is what this integration check proves, against the box's real
`age`/`age-keygen`, in a throwaway directory under `/tmp` -- **never** the
real `/var/lib/nebula-ca` or `/etc/nebula-ca`.

**Deploy-permission note.** `./deploy.sh`/`./run-tests.sh` (which rsync to
`/opt/nebula-ca/src`) are a separate, deliberate deploy step rather than
something this check triggers itself, so — unlike `tests/integration/ca-bootstrap.md`'s precedent, which
ran straight out of an already-deployed `/opt/nebula-ca/src` checkout —
this check instead copies only the two pieces `backup-ca` actually needs
(`box/lib/causb/` and `box/handlers/backup-ca`) into an isolated `/tmp`
workdir and runs entirely from there. This is equally valid proof of the
real `age` round trip (the handler's only external dependency besides
`causb.config` is the `age` binary on `PATH`) and never touched
`/opt/nebula-ca/src` at all.

## What was run

Non-root, over SSH, on `<operator>@<box>`:

```bash
WORKDIR="$(mktemp -d /tmp/causb-backupca-it.XXXXXX)"
# scp'd from the dev checkout (NOT /opt/nebula-ca/src): box/lib/causb -> $WORKDIR/causb,
# box/handlers/backup-ca -> $WORKDIR/backup-ca

python3 "$WORKDIR/driver.py" "$WORKDIR"    # driver.py shown below
```

`driver.py` (the throwaway integration driver):

```python
import importlib.machinery, importlib.util, os, subprocess, sys

WORKDIR = sys.argv[1]
CA_DIR = os.path.join(WORKDIR, "ca")
RECIPIENT_PATH = os.path.join(WORKDIR, "recipient.age")
OUT_DIR = os.path.join(WORKDIR, "out")
PAYLOAD_DIR = os.path.join(WORKDIR, "payload")
IDENTITY_PATH = os.path.join(WORKDIR, "identity.txt")
BACKUP_CA_PATH = os.path.join(WORKDIR, "backup-ca")
FAKE_KEY_BYTES = b"FAKE-CA-PRIVATE-KEY-INTEGRATION-TEST-MATERIAL-do-not-leak-7f3a91\n"

os.makedirs(CA_DIR, exist_ok=True); os.makedirs(OUT_DIR, exist_ok=True); os.makedirs(PAYLOAD_DIR, exist_ok=True)
with open(os.path.join(CA_DIR, "ca.key"), "wb") as f:
    f.write(FAKE_KEY_BYTES)

# 1. A throwaway age identity + its recipient -- age-keygen prints
# "Public key: age1..." to stderr and writes the private identity to -o.
keygen = subprocess.run(["age-keygen", "-o", IDENTITY_PATH], capture_output=True, text=True, timeout=30)
assert keygen.returncode == 0, keygen.stderr
recipient = [l for l in keygen.stderr.splitlines() if "Public key:" in l][0].split("Public key:", 1)[1].strip()
with open(RECIPIENT_PATH, "w") as f:
    f.write(recipient + "\n")

# 2. Point causb.config at throwaway paths BEFORE loading backup-ca (its
# run() defaults bind at module-definition time).
sys.path.insert(0, WORKDIR)
from causb import config
config.CA_DIR = CA_DIR
config.BACKUP_RECIPIENT = RECIPIENT_PATH

loader = importlib.machinery.SourceFileLoader("backup_ca_integration", BACKUP_CA_PATH)
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

# 3. age_run is NOT overridden -- this calls the REAL mod._age_encrypt,
# which shells out to the REAL age binary.
rc = mod.run({}, PAYLOAD_DIR, OUT_DIR)
assert rc == mod.EXIT_OK, f"rc={rc}"

out_ciphertext_path = os.path.join(OUT_DIR, "ca.key.age")
assert os.path.isfile(out_ciphertext_path)

# 4. Mutation-proof: walk the WHOLE out_dir tree for a plaintext leak.
found = [os.path.join(r, n) for r, _d, fs in os.walk(OUT_DIR) for n in fs]
for path in found:
    assert os.path.basename(path) != "ca.key"
    with open(path, "rb") as f:
        assert FAKE_KEY_BYTES not in f.read()

# 5. Real round trip.
decrypted_path = os.path.join(WORKDIR, "decrypted.key")
decrypt = subprocess.run(["age", "-d", "-i", IDENTITY_PATH, "-o", decrypted_path, out_ciphertext_path],
                          capture_output=True, text=True, timeout=30)
assert decrypt.returncode == 0, decrypt.stderr
with open(decrypted_path, "rb") as f:
    assert f.read() == FAKE_KEY_BYTES

with open(out_ciphertext_path, "rb") as f:
    assert FAKE_KEY_BYTES not in f.read()  # genuinely encrypted, not copied
print("INTEGRATION PASS")
```

```bash
rm -rf "$WORKDIR"   # cleanup
```

## Real output (verbatim, this run)

```
generated recipient: age1h3hx09sg54aj8v8j4w7ftvutm9xyu67y8xzrwccjq2zdfs24h35qnf98pm
run() rc = 0 (EXIT_OK=0)
out_dir contents: ['ca.key.age'] -- no plaintext leak
age -d round-trip: decrypted bytes match the original fake ca.key exactly
ciphertext (265 bytes) does not contain the plaintext -- genuinely encrypted
INTEGRATION PASS
```

Post-run cleanup, independently confirmed:

```
$ rm -rf /tmp/causb-backupca-it.Yp3lH0
$ ls /tmp/causb-backupca-it.Yp3lH0
ls: cannot access '/tmp/causb-backupca-it.Yp3lH0': No such file or directory
$ pgrep -fl 'age|driver.py'
(no output -- no lingering processes)
$ ls /etc/nebula-ca
ls: cannot open directory '/etc/nebula-ca': Permission denied
$ ls /var/lib/nebula-ca
ls: cannot open directory '/var/lib/nebula-ca': Permission denied
```

The last two confirm this SSH session never had — and so structurally
could not have used — write access to the real state directories; every
path `run()` touched (`ca_dir`, `recipient_path`, `out_dir`) was an
explicit throwaway-tmpdir override the whole time.

## What this proves

- The REAL `age` binary, invoked exactly as `box/handlers/backup-ca`'s
  `_age_encrypt` builds it (`age -R <recipient_path> -o <out_path>
  <in_path>`), produces a ciphertext that a real, independently generated
  `age-keygen` identity decrypts back to the **exact original bytes**
  (step 5) — the round trip that no unit test (injected fake `age_run`)
  can prove on its own.
- The ciphertext genuinely does not contain the plaintext verbatim (step
  5's last assertion) — `age` encrypted rather than merely copied/wrapped
  the input.
- `out_dir` ends up holding exactly one file, `ca.key.age`; no file named
  `ca.key`, and the plaintext key bytes appear nowhere under `out_dir`
  (step 4) — proven against the REAL encrypted output, not a fake.

## Scope / what this does NOT cover

- **The manifest-recipient-ignored guarantee.** Already exhaustively
  proven by `tests/unit/test_handler_backup_ca.py`'s
  `TestManifestRecipientIgnored` (an injected fake makes this trivial and
  precise to assert); re-proving it against the real binary would add
  nothing this integration check's own driver doesn't already fix by
  construction (it never reads `job["args"]` at all — see the handler's
  module docstring).
- **`age`/`AgeError` failure-mode mapping (nonzero exit / timeout / missing
  binary).** Covered by `tests/unit/test_handler_backup_ca.py`'s
  `TestAgeEncryptWrapper`/`TestAgeErrorMapping` against injected fakes;
  deliberately not re-triggered against the real binary here (there is no
  safe way to make the REAL `age` time out or go missing without either a
  flaky test or actually uninstalling the box's tooling).
- **Root ownership / `config.BACKUP_RECIPIENT`'s real `0644` file at
  `/etc/nebula-ca/backup-recipient.age`.** Not exercised here — this check
  has no root access and never touches `/etc/nebula-ca` at all (confirmed
  `Permission denied` above); the real
  install-time recipient file's ownership/mode is `box/install.sh`'s
  concern (already covered by `tests/integration/install_root.sh`'s
  `check_stat "$BACKUP_RECIPIENT" "root root 644"`), not this handler's.
- **`caj`/`caj-recv` delivery of `ca.key.age` back to the operator's Mac.**
  Out of scope here — the existing `causb.collect`/`commitlog`/
  `mac/caj-recv` pipeline already owns getting `out_dir`'s contents onto
  the outbox and back to the Mac (mirrors `ca-bootstrap.md`'s identical
  scope note).
