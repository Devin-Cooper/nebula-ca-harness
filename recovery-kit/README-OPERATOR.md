# Nebula CA box — operator guide (recovery kit)

The air-gapped Nebula CA box (**`nebula-ca`**) wrote this kit to a blank USB
stick when you inserted the stick and pressed the CONFIRM button (**K1**).
This is your cold-start manual: everything a human needs to command the box
again after losing the normal transfer stick or the Mac tooling.

The box has **no screen, no keyboard, no network**. Its only I/O is a USB
stick, one status LED, and one button.

---

## The two buttons — press K1, NEVER press MASK

> **Template — insert a top-down photo of _your_ box here**, with both buttons
> circled and labelled: **K1** = the CONFIRM button (`gpio-keys`, keycode 257 /
> `BTN_1`); **MASK** = the do-NOT-press button (`adc-keys`, keycode 158 /
> `KEY_BACK`). Mark clearly which physical button is which, so a cold operator
> can never confuse them.

- **K1 (CONFIRM)** — the *only* button you ever press. One press = "yes, do
  it" during the confirm window. A second, distinct press (offered by a
  distinct LED) is the extra confirmation that ALSO copies the sensitive
  `registry.json` into a recovery kit.
- **MASK (do NOT press)** — a recovery/maintenance button deliberately
  excluded from the harness. Pressing it never confirms anything. Treat it
  as "not a button."

---

## LED legend

There is one user status LED (`user_led`). A separate LED (`sys_led`) is just
the system heartbeat ("still alive") — ignore it. `user_led` shows one of
these states (rhythms match the box's `causb.led` table):

| LED behaviour | on / off | State | What you do |
|---|---|---|---|
| Off | — | **IDLE** — nothing happening | insert a stick |
| Slow blink |  0.33 s / 0.33 s (~1.5 Hz) | **VERIFYING** — checking the job | wait |
| Fast blink | 0.125 s / 0.125 s (~4 Hz) | **READY** — waiting for you | **press K1 now** |
| Solid on | — | **RUNNING** — job in progress | wait |
| Steady even blink | 1.0 s / 1.0 s (~0.5 Hz), held | **SAFE TO REMOVE** — done | pull the stick |
| Frantic flicker | 0.05 s / 0.05 s (~10 Hz) | **ERROR** — job refused / failed | pull stick; see README-AGENT.md |
| Quick blink | 0.25 s / 0.25 s (~2 Hz) | **BUSY** — another job is still running | wait, retry shortly |

Rule of thumb: **fast blink (~4 Hz) = act now, press K1; slow steady blink
held = safe to pull; frantic flicker = error.** (A "cold-human LED reading"
test — can a stranger reliably pick READY and SAFE-TO-REMOVE — is part of the
pre-air-gap gate.)

---

## The normal loop

1. Insert the transfer stick (the one whose `inbox/` holds a signed
   `job.tar` + `job.tar.sig`). If you instead insert a **blank** stick, the
   box offers to (re)write THIS recovery kit — see `RECOVERY-CEREMONY.md`.
2. LED goes **VERIFYING** (slow) while the box checks the signature,
   freshness, and replay protections.
3. LED goes **READY** (fast). Press **K1** once within the confirm window
   (about 60 s) to authorise the operation.
4. LED goes **RUNNING** (solid), then **SAFE TO REMOVE** (steady even blink,
   held) once the result is written to `outbox/` and the stick is unmounted.
5. Pull the stick. Read the result on your Mac with `caj-recv` (see
   `README-AGENT.md`).

If the LED never leaves VERIFYING and drops to ERROR without offering READY,
the job was refused (bad signature, wrong box, stale/replayed seq, or an
insane clock). `README-AGENT.md` explains each and how to fix it.

---

## Where the secrets map is — ON PAPER, never on any stick

The **OFFLINE-SECRETS-MAP** — which lists *where* the break-glass private
key, the `age` backup private key, and the primary key (in a password manager) live, and
*which* public key is the break-glass signer — is **paper only**. It is
deliberately **NOT written to this or any USB stick** (evil-maid opsec).
It is kept **physically with the box** (the sealed envelope / steel card
stored with the unit). If you cannot find it, whoever provisioned the box
moved it — it is not, and must never be, on removable media.

---

## Coin cell / clock

The box keeps its own clock on a coin cell (there is no network time after
air-gap). If the clock resets to an implausible date, jobs are refused as
`clock_insane` until you run a signed `set-time` job (see `README-AGENT.md`).
Replace the coin cell with the box powered off.
