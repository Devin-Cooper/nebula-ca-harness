"""Tests for causb.recovery: the K1-gated, public-only recovery-kit writer
(design S7A, D15, R8).

`recovery.write(mp, confirm2, ...)` is pure filesystem logic: given an
already-mounted-rw stick path `mp`, a boolean `confirm2` (the DISTINCT second
K1 confirmation, resolved by the orchestrator in Task 16), and injectable
`src`/`state_dir`/`anchors_dir`/`ca_dir` seams, it assembles `<mp>/CA-RECOVERY/`
from a TRUSTED staged source tree plus the box's own PUBLIC trust material.
It never touches hardware, so every property below is exercised here with
tmpdirs -- no LED, no button, no real block device.

THE load-bearing test is `test_ca_key_is_never_copied`: the writer must copy
CA artifacts by strict allowlist ({ca.crt, registry.json}) and MUST NEVER
sweep `ca_dir` (where `ca.key` sits 0400 right next to `ca.crt`). That test
plants a real `ca.key` and fails loudly if any byte of it -- or a file named
`ca.key` -- ever lands in the kit, so a regression to `copytree(ca_dir, ...)`
is caught immediately.
"""

import json
import os
import shutil
import tempfile
import unittest

from causb import config
from causb import recovery
from causb.recovery import RecoveryError


# Distinctive planted bytes so a leak is unambiguous in an assertion message.
_KEY_BYTES = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
    b"SECRET-CA-KEY-MUST-NEVER-LEAK-ONTO-A-STICK-0123456789\n"
    b"-----END OPENSSH PRIVATE KEY-----\n"
)
_CRT_BYTES = (
    b"-----BEGIN NEBULA CERTIFICATE-----\n"
    b"PUBLIC-CA-CERT-safe-to-distribute\n"
    b"-----END NEBULA CERTIFICATE-----\n"
)
_REG_BYTES = b'[{"name": "alice", "ip": "10.42.0.1/16", "groups": ["admins"]}]\n'
_ALLOWED_BYTES = b"nebula-ca-operator ssh-ed25519 AAAAOPERATORKEY operator\n"
_BREAKGLASS_BYTES = b"nebula-ca-breakglass ssh-ed25519 BBBBGLASSKEY breakglass\n"


class _RecoveryBase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="test-recovery-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

        # Fake already-mounted-rw stick.
        self.mp = os.path.join(self.root, "stick")
        os.makedirs(self.mp)

        # Fake TRUSTED staged source tree (what install.sh assembles at
        # RECOVERY_SRC): caj, caj-recv, causb/{...}.py, recovery-kit/<tmpl>.
        self.src = os.path.join(self.root, "recovery-src")
        self._build_src(self.src)

        # Fake box state / anchors / ca dirs.
        self.state_dir = os.path.join(self.root, "state")
        self.anchors_dir = os.path.join(self.root, "anchors")
        self.ca_dir = os.path.join(self.root, "ca")
        for d in (self.state_dir, self.anchors_dir, self.ca_dir):
            os.makedirs(d)

        # Public anchors are normally present on a provisioned box.
        self._write(os.path.join(self.anchors_dir, "allowed_signers"), _ALLOWED_BYTES)
        self._write(os.path.join(self.anchors_dir, "breakglass_signers"), _BREAKGLASS_BYTES)

    # -- fixture builders -----------------------------------------------
    def _build_src(self, src):
        os.makedirs(os.path.join(src, "recovery-kit"))
        os.makedirs(os.path.join(src, "causb"))
        for name in recovery.TEMPLATES:
            mode = 0o755 if name.endswith(".sh") else 0o644
            self._write(os.path.join(src, "recovery-kit", name),
                        f"FAKE TEMPLATE: {name}\n".encode(), mode=mode)
        for name in recovery.TOOLS:
            self._write(os.path.join(src, name),
                        f"#!/usr/bin/env python3\n# fake {name}\n".encode(), mode=0o755)
        for name in recovery.CAUSB_MODULES:
            self._write(os.path.join(src, "causb", name),
                        f"# fake causb/{name}\n".encode())

    def _write(self, path, data, mode=0o644):
        # Re-planting a read-only fixture (e.g. ca.crt at 0444) must not hit a
        # permission error on overwrite, so make it writable first.
        if os.path.exists(path):
            os.chmod(path, 0o600)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)

    def _plant_seq(self, n):
        self._write(os.path.join(self.state_dir, "seq"), f"{n}\n".encode())

    def _plant_ca_crt(self):
        self._write(os.path.join(self.ca_dir, "ca.crt"), _CRT_BYTES, mode=0o444)

    def _plant_ca_key(self):
        self._write(os.path.join(self.ca_dir, "ca.key"), _KEY_BYTES, mode=0o400)

    def _plant_registry(self):
        self._write(os.path.join(self.ca_dir, "registry.json"), _REG_BYTES)

    # -- helpers --------------------------------------------------------
    def _write_kit(self, confirm2):
        recovery.write(
            self.mp, confirm2,
            src=self.src, state_dir=self.state_dir,
            anchors_dir=self.anchors_dir, ca_dir=self.ca_dir,
        )
        return os.path.join(self.mp, "CA-RECOVERY")

    def _all_files(self, root):
        out = []
        for d, _dirs, files in os.walk(root):
            for f in files:
                out.append(os.path.join(d, f))
        return out

    def _read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def _make_stub_bin(self, name, tools):
        """Create a fake PATH directory `name` holding stub executables.
        `tools` maps a tool name -> its shell-script body. Returns the dir, to
        be passed as the `path=` seam so shutil.which finds the stubs instead
        of (or absent) the box's real binaries."""
        d = os.path.join(self.root, name)
        os.makedirs(d)
        for tool, body in tools.items():
            p = os.path.join(d, tool)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        return d


class CaKeyNeverCopiedTest(_RecoveryBase):
    def test_ca_key_is_never_copied(self):
        # The most permissive path: ca.crt + registry present, confirm2=True,
        # and a real ca.key planted right beside ca.crt (its true on-box
        # location, 0400).
        self._plant_seq(3)
        self._plant_ca_crt()
        self._plant_registry()
        self._plant_ca_key()

        kit = self._write_kit(confirm2=True)

        files = self._all_files(kit)
        # Sanity: the allowlisted public files DID get copied, so this test is
        # not vacuously passing on an empty kit (a copytree regression would
        # have to bring ca.key along with these).
        self.assertTrue(os.path.isfile(os.path.join(kit, "ca.crt")))
        self.assertTrue(os.path.isfile(os.path.join(kit, "registry.json")))

        # 1) No file anywhere in the kit is named ca.key (or any *.key).
        for p in files:
            base = os.path.basename(p)
            self.assertNotEqual(base, "ca.key", f"ca.key present in kit: {p}")
            self.assertFalse(base.endswith(".key"), f"private key file in kit: {p}")

        # 2) No file's CONTENT contains the planted secret bytes (catches a
        #    copy that renamed ca.key, or embedded it).
        for p in files:
            data = self._read(p)
            self.assertNotIn(_KEY_BYTES, data, f"ca.key bytes leaked into {p}")
            self.assertNotIn(b"SECRET-CA-KEY-MUST-NEVER-LEAK", data,
                             f"ca.key marker leaked into {p}")


class RegistryGateTest(_RecoveryBase):
    def test_registry_absent_without_confirm2_present_with(self):
        self._plant_ca_crt()
        self._plant_registry()

        kit = self._write_kit(confirm2=False)
        self.assertFalse(os.path.exists(os.path.join(kit, "registry.json")),
                         "registry.json must be omitted without the 2nd confirmation")

        # Re-run with confirm2=True on the SAME stick (also exercises idempotency).
        kit = self._write_kit(confirm2=True)
        reg = os.path.join(kit, "registry.json")
        self.assertTrue(os.path.isfile(reg))
        self.assertEqual(self._read(reg), _REG_BYTES)

    def test_registry_absent_when_missing_even_with_confirm2(self):
        # No registry.json planted in ca_dir.
        self._plant_ca_crt()
        kit = self._write_kit(confirm2=True)
        self.assertFalse(os.path.exists(os.path.join(kit, "registry.json")))


class SecretsMapNeverWrittenTest(_RecoveryBase):
    def test_offline_secrets_map_never_present(self):
        for confirm2 in (False, True):
            self._plant_ca_crt()
            self._plant_registry()
            kit = self._write_kit(confirm2)
            names = [os.path.basename(p) for p in self._all_files(kit)]
            self.assertNotIn("OFFLINE-SECRETS-MAP.md", names)
            self.assertFalse(any("SECRETS-MAP" in n for n in names),
                             f"a secrets-map-like file was written: {names}")


class BoxInfoTest(_RecoveryBase):
    def test_box_info_bootstrapped_true_seq_from_file(self):
        self._plant_seq(7)
        self._plant_ca_crt()
        kit = self._write_kit(confirm2=False)
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertEqual(info["box"], config.BOX_NAME)
        self.assertEqual(info["seq"], 7)
        self.assertIs(info["bootstrapped"], True)

    def test_box_info_bootstrapped_false_seq_default_zero(self):
        # No seq file, no ca.crt.
        kit = self._write_kit(confirm2=False)
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertEqual(info["box"], config.BOX_NAME)
        self.assertEqual(info["seq"], 0)
        self.assertIs(info["bootstrapped"], False)


class CaCrtGateTest(_RecoveryBase):
    def test_ca_crt_included_iff_exists(self):
        # Absent -> not in kit, bootstrapped False.
        kit = self._write_kit(confirm2=True)
        self.assertFalse(os.path.exists(os.path.join(kit, "ca.crt")))
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertIs(info["bootstrapped"], False)

        # Present -> copied verbatim, bootstrapped True.
        self._plant_ca_crt()
        kit = self._write_kit(confirm2=True)
        crt = os.path.join(kit, "ca.crt")
        self.assertTrue(os.path.isfile(crt))
        self.assertEqual(self._read(crt), _CRT_BYTES)
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertIs(info["bootstrapped"], True)


class ContentsPresentTest(_RecoveryBase):
    def test_templates_tools_causb_anchors_present(self):
        kit = self._write_kit(confirm2=False)

        for name in recovery.TEMPLATES:
            self.assertTrue(os.path.isfile(os.path.join(kit, name)),
                            f"template missing from kit: {name}")
        for name in recovery.TOOLS:
            self.assertTrue(os.path.isfile(os.path.join(kit, name)),
                            f"tool missing from kit: {name}")
        for name in recovery.CAUSB_MODULES:
            self.assertTrue(os.path.isfile(os.path.join(kit, "causb", name)),
                            f"causb module missing from kit: {name}")

        # Brief item 6 calls out causb/config.py specifically.
        self.assertTrue(os.path.isfile(os.path.join(kit, "causb", "config.py")))

        # Public anchors copied by exact name.
        self.assertTrue(os.path.isfile(os.path.join(kit, "allowed_signers")))
        self.assertTrue(os.path.isfile(os.path.join(kit, "breakglass_signers")))
        self.assertEqual(self._read(os.path.join(kit, "allowed_signers")), _ALLOWED_BYTES)
        self.assertEqual(self._read(os.path.join(kit, "breakglass_signers")), _BREAKGLASS_BYTES)

        # Tooling copied byte-for-byte from the trusted src (not the stick).
        self.assertEqual(self._read(os.path.join(kit, "caj")),
                         self._read(os.path.join(self.src, "caj")))
        self.assertEqual(self._read(os.path.join(kit, "caj-recv")),
                         self._read(os.path.join(self.src, "caj-recv")))

    def test_tool_versions_present(self):
        kit = self._write_kit(confirm2=False)
        p = os.path.join(kit, "TOOL-VERSIONS.md")
        self.assertTrue(os.path.isfile(p))
        text = self._read(p).decode()
        self.assertIn("nebula-cert", text)
        self.assertIn("age", text)
        self.assertIn("python", text.lower())


class IdempotencyTest(_RecoveryBase):
    def test_rerun_replaces_kit_cleanly(self):
        self._plant_ca_crt()
        self._plant_registry()

        kit = self._write_kit(confirm2=True)
        self.assertTrue(os.path.exists(os.path.join(kit, "registry.json")))

        # Plant a stale leftover as if a prior kit had extra files.
        stale = os.path.join(kit, "STALE-LEFTOVER.txt")
        self._write(stale, b"stale")

        # Re-run WITHOUT the 2nd confirmation: registry.json AND the stale
        # file must be gone, no crash, kit still complete.
        kit = self._write_kit(confirm2=False)
        self.assertFalse(os.path.exists(stale), "stale file survived a rewrite")
        self.assertFalse(os.path.exists(os.path.join(kit, "registry.json")),
                         "registry.json survived a confirm2=False rewrite")
        self.assertTrue(os.path.isfile(os.path.join(kit, "README-AGENT.md")))
        self.assertTrue(os.path.isfile(os.path.join(kit, "box-info.json")))
        self.assertTrue(os.path.isfile(os.path.join(kit, "caj")))


class HostileDestTest(_RecoveryBase):
    def test_dest_is_a_plain_file(self):
        dest = os.path.join(self.mp, "CA-RECOVERY")
        self._write(dest, b"i am a file, not a directory")

        with self.assertRaises(RecoveryError) as cm:
            self._write_kit(confirm2=True)
        self.assertEqual(cm.exception.reason, "unsafe_dest")

        # Fail closed: the pre-existing file is untouched, nothing else written.
        self.assertTrue(os.path.isfile(dest))
        self.assertEqual(self._read(dest), b"i am a file, not a directory")

    def test_dest_is_a_symlink(self):
        target = os.path.join(self.root, "elsewhere")
        os.makedirs(target)
        dest = os.path.join(self.mp, "CA-RECOVERY")
        os.symlink(target, dest)

        with self.assertRaises(RecoveryError) as cm:
            self._write_kit(confirm2=True)
        self.assertEqual(cm.exception.reason, "unsafe_dest")

        # The symlink target directory was NOT written into (never followed).
        self.assertEqual(os.listdir(target), [])


class SymlinkedCaCrtCannotExfilTest(_RecoveryBase):
    def test_symlinked_ca_crt_does_not_leak_ca_key(self):
        # Defense in depth: even if ca.crt in ca_dir were a symlink pointing
        # at ca.key, the writer must not follow it and copy the key out.
        self._plant_ca_key()
        os.symlink(os.path.join(self.ca_dir, "ca.key"),
                   os.path.join(self.ca_dir, "ca.crt"))

        # Must not crash; simply treats the non-regular ca.crt as absent.
        kit = self._write_kit(confirm2=True)

        self.assertFalse(os.path.exists(os.path.join(kit, "ca.crt")))
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertIs(info["bootstrapped"], False)
        for p in self._all_files(kit):
            self.assertNotIn(_KEY_BYTES, self._read(p),
                             f"ca.key bytes leaked via symlinked ca.crt into {p}")


class SrcAndErrorHandlingTest(_RecoveryBase):
    def test_missing_staged_src_file_fails_closed(self):
        os.remove(os.path.join(self.src, "caj"))
        with self.assertRaises(RecoveryError) as cm:
            self._write_kit(confirm2=False)
        self.assertEqual(cm.exception.reason, "src_missing")
        # The stick was never touched (src validated before any dest write).
        self.assertFalse(os.path.exists(os.path.join(self.mp, "CA-RECOVERY")))

    def test_oserror_maps_to_write_failed(self):
        # mp is a plain FILE, so makedirs(<mp>/CA-RECOVERY) raises OSError.
        bad_mp = os.path.join(self.root, "not-a-dir")
        self._write(bad_mp, b"x")
        with self.assertRaises(RecoveryError) as cm:
            recovery.write(
                bad_mp, False,
                src=self.src, state_dir=self.state_dir,
                anchors_dir=self.anchors_dir, ca_dir=self.ca_dir,
            )
        self.assertEqual(cm.exception.reason, "write_failed")

    def test_recovery_error_carries_reason(self):
        err = RecoveryError("unsafe_dest")
        self.assertEqual(err.reason, "unsafe_dest")
        self.assertIsInstance(err, Exception)


class RealTemplatesExistTest(_RecoveryBase):
    def test_repo_recovery_kit_has_the_four_templates(self):
        # Guard the actual deliverables: when the test runs from the repo
        # checkout (the normal case: PYTHONPATH=box/lib), the repo's
        # recovery-kit/ must hold the four non-empty templates.
        repo_root = os.path.abspath(
            os.path.join(os.path.dirname(recovery.__file__), "..", "..", "..")
        )
        kit_src = os.path.join(repo_root, "recovery-kit")
        if not os.path.isdir(kit_src):
            self.skipTest(f"repo recovery-kit/ not co-located at {kit_src}")
        for name in recovery.TEMPLATES:
            p = os.path.join(kit_src, name)
            self.assertTrue(os.path.isfile(p), f"real template missing: {p}")
            self.assertGreater(os.path.getsize(p), 0, f"real template empty: {p}")


class SeqReadRobustnessTest(_RecoveryBase):
    """Review fix 1: a malformed {state_dir}/seq must degrade to 0, never
    escape write() as a raw ValueError with no .reason."""

    def test_empty_seq_file_yields_zero(self):
        self._write(os.path.join(self.state_dir, "seq"), b"")
        kit = self._write_kit(confirm2=False)  # must not raise
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertEqual(info["seq"], 0)

    def test_garbage_seq_file_yields_zero(self):
        self._write(os.path.join(self.state_dir, "seq"), b"abc\n")
        kit = self._write_kit(confirm2=False)  # must not raise
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertEqual(info["seq"], 0)


class Confirm2StrictBoolTest(_RecoveryBase):
    """Review fix 2: registry.json disclosure is gated on `confirm2 is True`,
    not truthiness -- a stray truthy value must NOT leak mesh topology."""

    def test_only_literal_true_includes_registry(self):
        self._plant_ca_crt()
        self._plant_registry()
        for val in (1, "yes", "true", [1], 2.0):
            kit = self._write_kit(confirm2=val)
            self.assertFalse(
                os.path.exists(os.path.join(kit, "registry.json")),
                f"registry.json leaked for truthy non-bool confirm2={val!r}",
            )
        kit = self._write_kit(confirm2=True)
        self.assertTrue(os.path.isfile(os.path.join(kit, "registry.json")))


class BoxInfoEnrichmentTest(_RecoveryBase):
    """Review fix 3: box-info.json carries the §5 fields, derived where
    possible and degrading gracefully otherwise."""

    def test_enriched_fields_when_not_bootstrapped(self):
        self._plant_seq(4)
        kit = self._write_kit(confirm2=False)
        info = json.loads(self._read(os.path.join(kit, "box-info.json")))
        self.assertEqual(info["box"], config.BOX_NAME)
        self.assertEqual(info["seq"], 4)
        self.assertIs(info["bootstrapped"], False)
        self.assertEqual(info["curve"], "25519")
        self.assertEqual(info["schema_versions"], {"manifest": 1, "status": 1, "error": 1})
        self.assertIsInstance(info["rtc_ok"], bool)
        self.assertIsNone(info["ca_fingerprint"])
        self.assertIsNone(info["overlay_cidr"])
        self.assertIn("ca_fingerprint", info["pending_bootstrap"])
        self.assertIn("overlay_cidr", info["pending_bootstrap"])
        self.assertTrue(info["nebula_cert_version"] is None
                        or isinstance(info["nebula_cert_version"], str))

    def test_fingerprint_populated_with_stub_cert(self):
        self._plant_ca_crt()  # regular file -> bootstrapped True
        binp = self._make_stub_bin("nc-ok", {
            "nebula-cert": (
                "#!/bin/sh\n"
                'case "$1" in\n'
                "  print) printf '[{\"details\":{\"curve\":\"CURVE25519\"},"
                "\"fingerprint\":\"deadbeefcafe\"}]\\n' ;;\n"
                "  *) printf 'Version: 9.9.9\\n' ;;\n"
                "esac\n"
            ),
        })
        info = recovery._build_box_info(self.state_dir, self.ca_dir, True, path=binp)
        self.assertEqual(info["ca_fingerprint"], "deadbeefcafe")
        self.assertNotIn("ca_fingerprint", info["pending_bootstrap"])
        self.assertEqual(info["nebula_cert_version"], "9.9.9")
        self.assertEqual(info["curve"], "25519")

    def test_fingerprint_null_on_parse_failure(self):
        self._plant_ca_crt()
        binp = self._make_stub_bin("nc-bad", {
            "nebula-cert": "#!/bin/sh\nprintf 'not json at all\\n'\n",
        })
        info = recovery._build_box_info(self.state_dir, self.ca_dir, True, path=binp)
        self.assertIsNone(info["ca_fingerprint"])  # graceful degrade, no crash
        self.assertNotIn("ca_fingerprint", info["pending_bootstrap"])  # box IS bootstrapped


class ToolVersionsEnrichmentTest(_RecoveryBase):
    """Review fix 3: TOOL-VERSIONS.md records version + on-box SHA256 + URL for
    present tools, and "not installed" for absent ones."""

    def test_sha256_present_and_not_installed_absent(self):
        binp = self._make_stub_bin("tv", {
            "nebula-cert": "#!/bin/sh\nprintf 'Version: 1.2.3\\n'\n",
            "nebula": "#!/bin/sh\nprintf 'Version: 1.2.3\\n'\n",
            # deliberately NO age / age-keygen -> "not installed"
        })
        out = os.path.join(self.root, "TOOL-VERSIONS.md")
        recovery._write_tool_versions(out, path=binp)
        text = self._read(out).decode()

        # present tool: version string + a 64-hex sha256 + upstream URL
        self.assertIn("1.2.3", text)
        self.assertRegex(text, r"nebula-cert[\s\S]*?[0-9a-f]{64}")
        self.assertIn("github.com/slackhq/nebula/releases", text)
        # absent tool: not installed, but its URL is still recorded
        self.assertIn("not installed", text)
        self.assertIn("github.com/FiloSottile/age/releases", text)
        # our own interpreter version is still noted
        self.assertIn("python", text.lower())


if __name__ == "__main__":
    unittest.main()
