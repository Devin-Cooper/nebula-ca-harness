# Recovery ceremonies — decision tree

Pick the row that matches what you lost. Every path assumes you have THIS kit
(the box wrote it to a blank stick after an insert + K1). The
**OFFLINE-SECRETS-MAP is on PAPER, kept with the box** — it names *where* the
break-glass key, the `age` backup key, and the primary key (in a password manager) live, and
*which* public key is break-glass. It is never on a stick (evil-maid opsec).

---

## Quick table

| You lost… | Box status | Do this |
|---|---|---|
| The transfer **stick** | box fine | Rebuild a job stick with `setup-new-stick.sh`, then build with `caj` |
| The **Mac** (primary key survives elsewhere, e.g. a password manager) | box fine | Rebuild `caj`/`caj-recv` from this kit on new hardware; resume signing normally |
| The primary operator **key**, but it still exists somewhere | box fine | **Co-signed** `rotate-job-signers` (current primary sig + `caj --breakglass` co-signature) rotates in a new primary — see below |
| The primary key **truly lost** (no copy anywhere), break-glass intact | box fine | **Break-glass-alone** `rotate-job-signers` installs a new primary — sign with `caj build --key <breakglass-key>`; see below. Fallback: serial console / `backup-ca` restore |
| A **cold operator/agent** (no context) | box fine | Read `README-OPERATOR.md` (physical) + `README-AGENT.md` (contract); drive a normal job |
| A **new agent** that HAS a key | box fine | `README-AGENT.md`; remember `seq = box-info.seq + 1` |
| The **box** is dead (hardware) | box lost | This kit CANNOT restore `ca.key`; rebuild a box, restore from `ca.key.age` + the offline `age` key |
| **All signer keys** (primary AND break-glass) | un-commandable | Box can't be commanded again; rebuild the CA from the `age` backup on a fresh box |

---

## Lost the transfer stick

1. Get any USB stick and a **Linux** machine with `parted` and `dosfstools`
   (`mkfs.vfat`).
2. Run `sudo ./setup-new-stick.sh /dev/sdX` (replace `/dev/sdX` with YOUR
   stick). It wipes the stick and creates an MSDOS partition table + one vfat
   partition + `inbox/` and `outbox/`.
   - **Why the partition table matters:** the box's udev rule triggers on a
     *partition* (`sdX1`), not on a raw / "superfloppy" stick formatted
     directly. A stick without a partition table will NOT be picked up.
3. Build a job onto it with `caj` (see `README-AGENT.md`) and carry it to the
   box.

## Lost the Mac, or the primary operator key

Two different situations here, with two different recoveries. The dividing
line is whether a working copy of the CURRENT primary key still exists
anywhere (even off the dead Mac, e.g. restored from a password manager onto new
hardware) — not whether the Mac itself is the thing you lost.

### (a) The primary key still exists somewhere

If you still hold a working copy of the current primary key — you just lost
the Mac it lived on, or you want to retire the key out of caution — rebuild
`caj`/`caj-recv` from this kit on any machine and resume signing normally.
No ceremony needed for that alone.

To actually ROTATE the primary key (install a new one and retire the old),
today's supported path is a **co-signed** `rotate-job-signers` job — the
current primary signs, and the break-glass key ALSO co-signs the same
job.tar (this is the working co-signed rotation drill; see
`tests/integration/rotate-drill.md`):

1. Rebuild `caj` / `caj-recv` from this kit on any machine (plain Python;
   `chmod +x` them; keep `causb/` beside them).
2. Generate a NEW operator key, e.g. `ssh-keygen -t ed25519 -C nebula-ca`.
3. Build a `rotate-job-signers` job whose payload's `allowed_signers` names
   the new key, **sign it with the CURRENT primary key**
   (`caj build ... --key <current-primary-key>`), **and co-sign the SAME
   job.tar with the break-glass key** (`caj build ... --breakglass
   <breakglass-key>`). Both signatures are required on THIS path: the box
   verifies the primary signature against `allowed_signers` FIRST, so a stick
   whose only signature is a break-glass CO-signature (`--breakglass`, a
   `.bg.sig`) with no valid primary is rejected here. (If the primary is truly
   gone, do NOT use this co-signed path — use the break-glass-ALONE path in
   §(b) below, which puts the break-glass key in the PRIMARY slot via `--key`.)
4. Deliver the stick and press **K1** on the box. From then on, sign normal
   jobs with the new primary. Retire / revoke the old key.

### (b) The primary key is truly LOST — recover with the BREAK-GLASS key alone

**This now works over USB.** A `rotate-job-signers` job signed
by the **break-glass key alone** — no operator primary signature — installs a
fresh primary. The box accepts a break-glass-only signature for
`rotate-job-signers` and ONLY that operation; every other operation still
requires the primary. The bg-alone job may change ONLY `allowed_signers`
(install/replace the primary); it cannot touch `breakglass_signers` or do
anything else. It is still gated on a physical **K1** press, a fresh `seq`,
and the right box — exactly like a normal job.

1. Rebuild `caj` / `caj-recv` from this kit on any machine (plain Python;
   `chmod +x` them; keep `causb/` beside them). Retrieve the offline
   break-glass private key (its location is on the paper
   **OFFLINE-SECRETS-MAP**).
2. Generate a NEW operator key, e.g. `ssh-keygen -t ed25519 -C nebula-ca`.
3. Build a `rotate-job-signers` job whose payload's `allowed_signers` names
   the new key, and **sign it with the BREAK-GLASS key in the primary slot**:
   `caj build --spec <spec> --stick <mnt> --key <breakglass-key>`. (Use
   `--key`, NOT `--breakglass` — here the break-glass key IS the sole signer;
   there is no separate co-signature.)
4. Deliver the stick and press **K1** on the box. The box verifies the
   signature against `breakglass_signers`, applies the `allowed_signers`
   change, and installs your new primary. From then on, sign normal jobs
   with the new primary; retire the old anchor.

**Fallbacks** (if the break-glass key is ALSO lost, or you prefer a physical
route):

- **Physical serial console.** The box retains `serial-getty@ttyFIQ0`,
  the physical UART login, as a local rescue. Attach a serial cable, log in
  locally (the box's own account), and hand-edit
  `/etc/nebula-ca/allowed_signers` directly — no stick, no signature, because
  you are already locally authenticated. This works even if BOTH signer keys
  are gone.
- **Restore from the `backup-ca` age backup onto a fresh box** (see "Dead
  box" below) — provision a new box, restore the CA from the encrypted
  `ca.key.age` backup + the offline `age` key, and set fresh anchors during
  its (pre-air-gap) install.

## Cold operator or fresh agent (nothing lost, no context)

Everything you need is in this kit. `README-OPERATOR.md` is the physical
button + LED guide; `README-AGENT.md` is the exact build / sign / verify
contract. The one hard rule to remember: **next `seq` = `box-info.json.seq`
+ 1.**

## Dead box (hardware failure)

This kit is PUBLIC material only — it does **not** contain `ca.key` and
cannot restore the CA by itself. To rebuild:

1. Provision a new box (re-run the harness install).
2. Restore the CA private key from the encrypted backup `ca.key.age`
   (produced earlier by a `backup-ca` job) using the **offline `age` private
   key** — its location is on the paper secrets map.
3. Reinstall the trust anchors and resume the normal flow.

## Lost every signer key (primary AND break-glass)

The box can no longer be commanded — nothing can produce a signature it
trusts. Recover the CA material itself from the `age` backup onto a fresh box
and re-establish signers from scratch. This is the worst case the design
plans for; the `age` backup plus its offline key (paper secrets map) are the
last line of defence.

---

## What this kit deliberately does NOT contain

- **No `ca.key`** or any private key — ever. The kit is public / topology
  data only.
- **No `OFFLINE-SECRETS-MAP.md`** — it is paper-only, kept with the box.
- **`registry.json` only on the distinct second K1 confirmation** — mesh
  topology is sensitive, so a single-K1 recovery omits it.
