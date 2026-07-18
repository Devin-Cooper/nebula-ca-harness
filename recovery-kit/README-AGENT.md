# Nebula CA box — cold-agent bootstrap (recovery kit)

You are an operator (human or AI) with **zero prior context**. This file is
the complete USB command contract for the air-gapped Nebula CA box named
**`nebula-ca`**. Everything needed to build, sign, deliver, and read back a
job is in THIS kit. The box has no network; the only channel is a USB stick.

---

## What's in this kit

- `caj`, `caj-recv` — the Mac/Linux-side job builder and result reader.
- `causb/` — the Python package `caj`/`caj-recv` import (`__init__.py`,
  `config.py`, `manifest.py`). Keep it as a **sibling directory of `caj`** so
  `import causb` resolves (Python puts a script's own directory on
  `sys.path`, so run `caj` from inside this kit directory).
- `allowed_signers`, `breakglass_signers` — the box's PUBLIC trust anchors.
- `ca.crt` — the CA certificate (present only if the box is bootstrapped).
- `box-info.json` — `{"box", "seq", "bootstrapped"}`. **The next job's `seq`
  = `box-info.json`'s `seq` + 1.**
- `registry.json` — issued hosts / IPs (present ONLY if the operator gave the
  distinct second K1 confirmation; sensitive — it is mesh topology).
- `TOOL-VERSIONS.md` — the `nebula-cert` / `age` / `python3` versions to
  match when rebuilding the box.
- `setup-new-stick.sh` — turn a raw USB stick into a job stick.
- `README-OPERATOR.md`, `RECOVERY-CEREMONY.md`.

---

## 0. Prerequisites on your machine

- **Python 3** (stdlib only — no pip packages are needed to run
  `caj`/`caj-recv`).
- **OpenSSH `ssh-keygen`** (for signing).
- **An authorised operator private key** whose public half is a principal in
  `allowed_signers` (normally `~/.ssh/id_ed25519`, passphrase-protected, held
  in a password manager). Without it you cannot sign a normal job — see
  `RECOVERY-CEREMONY.md` for the break-glass path.
- A **FAT/vfat** USB stick with an `inbox/` directory. Build one with
  `setup-new-stick.sh` if you lost the transfer stick.
- A FAT stick cannot store the Unix execute bit, so after copying the kit off
  the stick, run: `chmod +x caj caj-recv setup-new-stick.sh`.

---

## 1. Write a job spec

A spec is plain `key: value` lines (no YAML, no quoting, no `eval`). Blank
lines and `#` comments are ignored:

```
# example: sign two host public keys
operation:     sign-hosts
payload:       alice.pub, bob.pub
args.groups:   servers
args.duration: 8760h
```

- `operation` (required) — one of `sign-hosts`, `ca-bootstrap`, `backup-ca`,
  `rotate-ca`, `rotate-job-signers`, `run-script`, `set-time`, `status`.
- `payload` (optional) — comma-separated basenames of files staged **next to
  the spec file** (e.g. host `*.pub` public keys, or a `run-script`'s script
  file). Each name may appear once.
- `box` (optional) — defaults to `nebula-ca`.
- `entrypoint` (`run-script` only) — which payload file to execute.
- `args.<name>: <value>` — operation arguments. A bare `true` or `false`
  (exact, unquoted) is sent as a JSON boolean — required for `args.privileged`
  on a privileged `run-script` and `args.compromise` on `rotate-ca`, the only
  two boolean args the box has. Every other value is a plain string (e.g. a
  value containing commas, such as multiple nebula groups, is passed through
  verbatim, which is exactly what `nebula-cert -groups` expects).
- `args.privileged: true` (`run-script` only) — request root execution
  instead of the confined `nebula-job` account. This REQUIRES a break-glass
  co-signature: build with `caj --breakglass <breakglass-key>`, in addition
  to the usual `--key`, or the box refuses the job as `cosign_failed` (after
  K1, before anything runs).

Put the spec and its payload files together in one staging directory.

---

## 2. Build + sign + deliver onto the stick

```
./caj build --spec ./job.spec --stick /path/to/mounted/stick \
      --key ~/.ssh/id_ed25519
```

`caj` will, atomically and under a lock:

1. compute `seq` = `box-info.json`'s `seq` + 1 (tracked locally in
   `ca-state/`; see §5),
2. assemble `manifest.json` + `payload/` and pack `job.tar` with clean member
   names,
3. **sign it**:
   `ssh-keygen -Y sign -f <key> -n nebula-ca-job job.tar`
   — an Ed25519 SSH signature in the namespace **`nebula-ca-job`** (the exact
   namespace the box verifies against) → `job.tar.sig`,
4. write `inbox/job.tar` then `inbox/job.tar.sig` (signature LAST, so an
   interrupted copy fails closed on the box rather than pairing a good sig
   with a truncated tar).

Flags: `--retry <JOB_ID>` reuses an exact prior `job_id` (idempotent
redelivery; still advances `seq`); `--key` defaults to `~/.ssh/id_ed25519`.

---

## 3. Run it on the box

Carry the stick to the box, insert it, watch the LED, and press **K1** when
it blinks **READY** (fast). See `README-OPERATOR.md`. The box writes results
to `outbox/` and lights **SAFE TO REMOVE**; then pull the stick.

---

## 4. Read the result back

```
./caj-recv --stick /path/to/mounted/stick
```

`caj-recv` independently recomputes the SHA-256 of every declared output in
`outbox/<job_id>/` (refusing symlinks), and only on a full match places
outputs into your repo:

- `ca.crt`        → `ca-state/ca.crt`
- `registry.json` → `ca-state/registry.json`
- `<name>.crt`    → `hosts/<name>/<name>.crt`

It also reconciles your local `ca-state/last-seq` forward from the
box-reported `status.json["seq"]` (it only ever moves forward, never back).
There is no signature on `outbox/` — it is public data the box reports about
its own prior action.

---

## 5. seq / replay rules (read this)

- **The next job's `seq` MUST be `box-info.json`'s `seq` + 1.** The box
  refuses any job whose `seq` is ≤ the last one it committed (`stale_seq`).
- `caj` tracks `seq` for you in `ca-state/`: `last-seq` (last box-confirmed,
  reconciled by `caj-recv`) and `last-built-seq` (highest built). Each build
  uses `max(last-seq, last-built-seq) + 1`.
- If you are rebuilding from scratch and `ca-state/` is empty, read the `seq`
  in `box-info.json` and seed it: `printf '%s' "<seq>" > ca-state/last-seq`.
  Your next job then gets `seq + 1`.
- Each `job_id` is single-use: re-running a committed `job_id` **replays the
  same result bytes** (idempotent) — it does not run twice.
- `box` must equal `nebula-ca`, and the box clock must be sane (year ≥ 2026)
  or the job is refused `clock_insane` — repair with a signed `set-time` job.

---

## If you have NO authorised key

You cannot sign a normal job. Recovery depends on whether the PRIMARY key
still exists (see `RECOVERY-CEREMONY.md` for the full tree):

- **Primary still available (e.g. you lost only the Mac):** rebuild `caj`
  from this kit and submit a **co-signed** `rotate-job-signers` — the primary
  signature PLUS a `caj --breakglass` co-signature — to install a fresh
  primary. This is the working path.
- **Primary truly lost, break-glass intact:** a break-glass signature
  **alone** now installs a fresh primary. Build a
  `rotate-job-signers` job whose payload `allowed_signers` names a new primary
  key and sign it with the break-glass key in the primary slot:
  `caj build --spec <spec> --stick <mnt> --key <breakglass-key>` (use `--key`,
  not `--breakglass` — the break-glass key is the sole signer). The box
  accepts a break-glass-only signature for `rotate-job-signers` ONLY, applies
  the `allowed_signers` change, and is still K1/seq/box-gated; a bg-alone job
  cannot change `breakglass_signers` or run any other operation.
- **Break-glass ALSO lost:** recover via the **physical serial console**
  (`serial-getty@ttyFIQ0`, login as the box account) to edit
  `/etc/nebula-ca/allowed_signers` by hand, or restore from the `backup-ca`
  age backup onto a fresh box.

The break-glass private key is offline; its location is on the PAPER
**OFFLINE-SECRETS-MAP** kept with the box (never on a stick).
