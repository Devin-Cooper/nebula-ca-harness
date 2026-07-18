BOX_NAME = "nebula-ca"

STATE_DIR = "/var/lib/nebula-ca"
CA_DIR = f"{STATE_DIR}/ca"

# Mesh overlay addressing (causb.registry, S8). OVERLAY_CIDR is the default
# /16 a fresh box bootstraps into; causb.ca-bootstrap may override it
# per-job (registry.py's allocate()/reconcile() both accept an explicit
# overlay_cidr= for exactly that reason). LIGHTHOUSE_RESERVED holds back
# host offsets 1..9 (X.X.0.1-X.X.0.9) for statically-addressed lighthouses
# so sequential host allocation never collides with them; the first
# sequentially-allocated host lands at X.X.0.10.
# Chosen 2026-07-16 after an explicit collision check against common defaults:
# avoids 192.168.x (home routers), 10.0/10.1 (corp VPN), 172.17-31 (Docker),
# k8s ranges (k3s 10.42/10.43, flannel 10.244, kubeadm 10.96, Calico 192.168),
# Parallels (10.211.55 shared / 10.37.129 host-only), and ProtonVPN (10.2.0.0/24).
# NOTE: 10.66.0.0/16 does sit inside Mullvad's WireGuard pool 10.64.0.0/10 -- a
# non-issue unless a mesh node runs Mullvad.
OVERLAY_CIDR = "10.66.0.0/16"
LIGHTHOUSE_RESERVED = 9
REGISTRY = f"{CA_DIR}/registry.json"
CA_CRT = f"{CA_DIR}/ca.crt"
CA_KEY = f"{CA_DIR}/ca.key"

# ca-bootstrap's default CA certificate lifetime (~5 years) -- passed to
# nebulacli.ca()'s `duration` argument when a job manifest's own
# `args.duration` doesn't override it. Deliberately long: this CA cannot be
# rotated without re-signing every host in the fleet (no rotate-ca yet), so
# the default should outlive any realistic operational window rather than
# forcing an early, disruptive re-bootstrap.
CA_DURATION = "87600h"  # ~10 years (operator choice, 2026-07-16)

# sign-hosts' default HOST certificate lifetime (~5 years) -- passed to
# nebulacli.sign()'s `duration` argument when a job manifest's own
# `args.duration` doesn't override it (S8).
# Deliberately much shorter than CA_DURATION: re-signing an existing host
# name is cheap and idempotent (sign-hosts keeps its stable IP via
# causb.registry), so a shorter default bounds the blast radius of a lost
# or compromised host key without requiring any CA rotation.
HOST_CERT_DURATION = "43800h"  # ~5 years (operator choice, 2026-07-16); note the
# trade-off: a longer leaf lifetime means a lost/compromised host key is trusted
# longer -- mitigate a specific compromise with `rotate-ca --compromise` (emits a
# nebula blocklist of the old leaf fingerprints) rather than waiting for expiry.

# The mesh-side clock-skew tolerance sign-hosts' issued certs are meant to
# absorb (5 minutes). NOT currently wired into any nebula-cert invocation --
# verified LIVE against the box (v1.10.3): `nebula-cert sign -h` exposes only
# -ca-crt/-ca-key/-duration/-groups/-in-pub/-ip/-name/-networks/-out-crt/
# -out-key/-out-qr/-subnets/-unsafe-networks/-version -- no -notBefore or
# backdate flag of any kind exists to pass this to. `causb.nebulacli.sign()`
# has no such parameter either, so
# box/handlers/sign-hosts cannot honor this constant today even though it is
# defined. It documents the box's actual policy instead: every issued host
# cert's notBefore is real wall-clock "now" at signing time (confirmed live:
# a signed cert's notBefore matched the signing instant exactly), and a peer
# whose own clock is up to BACKDATE early/late is expected to still accept
# the cert mesh-side (nebula's own handshake clock tolerance) -- not because
# this box pre-dated it. Kept here, rather than deleted, so a future task
# that adds real backdating support (once/if nebulacli.sign() grows a
# parameter for it) has an obvious, already-reviewed home for the value.
BACKDATE = "5m"

RESULTS_DIR = f"{STATE_DIR}/results"
AUDIT_LOG = f"{STATE_DIR}/audit.log"

ALLOWED = "/etc/nebula-ca/allowed_signers"
BREAKGLASS = "/etc/nebula-ca/breakglass_signers"
BACKUP_RECIPIENT = "/etc/nebula-ca/backup-recipient.age"

# set-time's plausibility bounds (S8/R5). A
# `set-time` job is the ONE operation exempt from causb.freshness's
# year>=2026 clock-sanity gate (it exists specifically to repair the box's
# clock when the RTC coin cell dies and the CURRENT clock is itself
# insane) -- but it still refuses an implausible TARGET, so a malicious or
# fat-fingered manifest cannot rewind the box to some arbitrary past/future
# date. TIME_MIN mirrors causb.freshness.clock_sane's own floor (this
# harness cannot have been built/deployed before 2026); TIME_MAX is a
# generous, arbitrary-but-sane far bound -- a CA legitimately operating
# past 2050 is not a scenario this harness plans for. Both are ISO-8601
# strings (parsed the same way box/handlers/set-time parses a manifest's
# own args.time) rather than datetime objects, so this module keeps its
# existing "plain literals only" style (every other constant here is a str/
# int/dict literal, never a computed value).
TIME_MIN = "2026-01-01T00:00:00+00:00"
TIME_MAX = "2050-01-01T00:00:00+00:00"

NS = "nebula-ca-job"

# Wire-contract schema versions (S6): the manifest schema (D8 pins it at 1,
# enforced by causb.manifest.parse) and the status.json schema (also 1,
# enforced by mac/caj-recv). Kept HERE as the single source of truth so the
# status handler's box-info.json and causb.recovery's box-info.json can both
# reference the same dict rather than each hardcoding a literal that could
# drift.
SCHEMA_VERSIONS = {"manifest": 1, "status": 1, "error": 1}

# Coarse triage tags for the on-stick pre-commit error breadcrumb
# (outbox/ERROR.json, S-errlog / 2026-07-16 design). A breadcrumb is written
# ONLY for a failure that occurs AFTER signature verification but BEFORE commit
# -- i.e. an authenticated job that aborts before it runs -- and `phase` names
# which pipeline stage rejected it. Single source of truth shared by the box
# writer (ca-usb-run._write_error_breadcrumb) and mac/caj-recv's validator.
ERROR_PHASES = ("extract", "manifest", "freshness", "dispatch")

# Privilege-separation identities (S12, R2). There is no "nebula-ca" user
# (R2 dropped it) -- vetted handlers run as root; only run-script drops to
# this unprivileged system account (install.sh creates it).
JOB_USER = "nebula-job"

# Vetted handler executables live here once installed (install.sh
# rsyncs box/handlers/* to this exact path). causb.dispatch also falls back
# to a repo-relative box/handlers/ so it works from an uninstalled checkout.
HANDLERS_DIR = "/usr/local/lib/ca-usb/handlers"

CAPS = {
    "manifest_bytes": 65536,
    "jobs": 1,
    "payload_files": 16,
    "tar_bytes": 8 * 1024 * 1024,
    "tar_files": 64,
    "depth": 4,
    "tmpfs_mb": 32,
}

K1_WINDOW_S = 60
OP_TIMEOUT_S = 300
