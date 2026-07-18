# Dispatch + run-script + status: integration notes

Unlike the physical-confirmation checklists (`10-hw.md`, `12-trigger.md`,
`13-usbguard.md`), this one has **no physical/hardware dependency** --
no LED, no K1 button, no real USB stick, no signing ceremony. Every
security-critical property the spec asks for (privilege drop via
`setpriv`, the `ca.key` DAC boundary, scrubbed-env confinement, the
`privileged`+cosign gate, the audit log, per-op timeout + process-group
kill) is fully exercised by a real, unprivileged-vs-root process boundary
on this exact box, so it is proven by **`tests/integration/dispatch_root.py`**
(run as root) rather than deferred to an operator checklist:

```
sudo python3 tests/integration/dispatch_root.py
```

5/5 cases, reproduced 2x:

1. A non-privileged `run-script` `cat`ing a dummy `root:root 0400` file at
   the real `config.CA_DIR/ca.key` runs as `nebula-job` (confirmed via a
   captured `id`), gets `Permission denied`, returns the real nonzero exit
   code, and the key's bytes never appear in `out_dir`.
2. The identical script, `privileged` + `cosigned=True`, runs as root
   (`uid=0`), reads the key, and its sha256+byte-length land in the real
   `/var/lib/nebula-ca/audit.log` (mode `0600`).
3. `privileged` + `cosigned=False` raises `DispatchError("cosign_failed")`
   and never even creates an output file -- nothing ran.
4. A script trying to dump `env` sees only `PATH`/`HOME`/(shell-native)
   `PWD` -- an injected parent-process env var never crosses the boundary.
5. A script that backgrounds a detached, 20s-sleeping grandchild before
   itself sleeping is killed at a 1.5s `timeout_s` override, and the
   grandchild is confirmed dead (not just the direct child) -- proves the
   process-GROUP kill, not just a child kill.

The dummy `ca.key` is planted only if no real one exists yet (refuses to
run otherwise) and is always removed in a `finally` block, confirmed
removed both by the script's own output and by an independent root `ls`
after each run. The 2 test-run entries this leaves in the real
`audit.log` are expected, harmless residue on this still-pre-air-gap,
dummy-anchors bring-up box (same category as the dummy anchors themselves)
-- this test's cleanup instruction is scoped to the dummy
`ca.key`, not the audit trail whose durability this test is specifically
proving.

## Genuinely deferred (scope boundaries, not physical gaps)

- **`box/handlers/status`'s `bootstrapped: true` branch** (`ca_fingerprint`/
  `curve`/`overlay_cidr` extraction from a real `ca.crt`) is intentionally
  left unimplemented beyond returning `null` -- no `ca-bootstrap` handler
  exists in this codebase yet to create a real CA to test against. See
  `box/handlers/status`'s own module docstring.
- **`config.OP_TIMEOUT_S`'s real 300s value** is never waited out for real
  (case 5 above overrides it to 1.5s via `dispatch.run(..., timeout_s=...)`)
  -- the mechanism is identical regardless of the configured duration, and
  waiting out 300 real seconds would not prove anything the short-override
  case doesn't already.
- **Vetted CA-operation handlers** (`ca-bootstrap`, `sign-hosts`,
  `backup-ca`, `rotate-ca`, `rotate-job-signers`, `set-time`) are follow-on
  deliverables; `causb.dispatch`'s vetted-handler
  lookup/exec path is proven generically (unit tests use a synthetic
  handler file), not against any of these specific future handlers.
