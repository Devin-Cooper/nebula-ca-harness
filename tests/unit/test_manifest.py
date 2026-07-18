import json
import unittest
import uuid

from causb import config
from causb.manifest import ManifestError, parse


def _manifest(**overrides):
    """Build a valid single-job manifest dict, overridable per-test."""
    manifest = {
        "schema_version": 1,
        "bundle_id": "bundle-1",
        "box": "nebula-ca",
        "seq": 7,
        "jobs": [
            {
                "job_id": str(uuid.uuid4()),
                "operation": "sign-hosts",
                "args": {},
                "payload": ["alice.pub"],
                "entrypoint": None,
            }
        ],
    }
    manifest.update(overrides)
    return manifest


class TestManifestParse(unittest.TestCase):
    def test_valid_single_job_manifest_parses(self):
        manifest = _manifest()
        raw = json.dumps(manifest).encode()

        result = parse(raw, payload_names={"alice.pub"})

        assert result["schema_version"] == 1
        assert result["box"] == "nebula-ca"
        assert len(result["jobs"]) == 1
        assert result["jobs"][0]["operation"] == "sign-hosts"
        assert result["jobs"][0]["payload"] == ["alice.pub"]

    def test_jobs_length_not_one_is_rejected(self):
        manifest = _manifest()
        manifest["jobs"] = manifest["jobs"] * 2  # len(jobs) == 2
        raw = json.dumps(manifest).encode()

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"alice.pub"})
        assert cm.exception.reason == "jobs_gt_1"

    def test_oversize_manifest_is_rejected(self):
        raw = b" " * (config.CAPS["manifest_bytes"] + 1)

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names=set())
        assert cm.exception.reason == "oversize"

    def test_payload_path_traversal_is_rejected(self):
        manifest = _manifest()
        manifest["jobs"][0]["payload"] = ["../secret.pub"]
        raw = json.dumps(manifest).encode()

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"secret.pub"})
        assert cm.exception.reason == "path_traversal"

    def test_payload_name_with_embedded_nul_is_path_traversal(self):
        # A NUL in a payload basename would pass the "/"/"."/".." checks and,
        # once causb.dispatch joins it into a path, raise a raw uncaught
        # ValueError('embedded null byte') out of Popen -- reject it here as
        # path_traversal (same class as "/") so nothing downstream ever sees
        # a control byte in a path component.
        manifest = _manifest()
        manifest["jobs"][0]["payload"] = ["alice\x00.pub"]
        raw = json.dumps(manifest).encode()

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"alice\x00.pub"})
        assert cm.exception.reason == "path_traversal"

    def test_payload_name_with_other_control_char_is_path_traversal(self):
        manifest = _manifest()
        manifest["jobs"][0]["payload"] = ["alice\x1f.pub"]
        raw = json.dumps(manifest).encode()

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"alice\x1f.pub"})
        assert cm.exception.reason == "path_traversal"

    def test_payload_entry_missing_from_payload_names_is_rejected(self):
        manifest = _manifest()
        manifest["jobs"][0]["payload"] = ["ghost.pub"]
        raw = json.dumps(manifest).encode()

        # "ghost.pub" is a well-formed basename but no such file was
        # actually extracted from payload/ -- the manifest's own claim is
        # inconsistent with reality, which is a bad_manifest, not a cap.
        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"alice.pub"})
        assert cm.exception.reason == "bad_manifest"

    def test_unknown_schema_version_is_rejected(self):
        manifest = _manifest(schema_version=2)
        raw = json.dumps(manifest).encode()

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"alice.pub"})
        assert cm.exception.reason == "bad_manifest"

    def test_non_json_is_rejected(self):
        raw = b"not-json-at-all {{{"

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names=set())
        assert cm.exception.reason == "bad_manifest"

    def test_nested_json_bomb_is_rejected(self):
        # Review fix 1: a deeply-nested but under-cap JSON array bomb must
        # fail closed with bad_manifest, not crash parse() with an uncaught
        # RecursionError. json.loads recurses once per nesting level.
        depth = 32000
        raw = (b"[" * depth) + (b"]" * depth)
        # Stay under the byte cap so this exercises json.loads (and its
        # RecursionError), not the oversize length guard.
        assert len(raw) <= config.CAPS["manifest_bytes"]

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names=set())
        assert cm.exception.reason == "bad_manifest"

    def test_jobs_wrong_type_is_bad_manifest(self):
        # Review fix 4: a non-list `jobs` (or a missing one) is a schema
        # violation like any other wrong-typed field -> bad_manifest, not
        # jobs_gt_1 (which is reserved for an actual list of wrong length,
        # covered by test_jobs_length_not_one_is_rejected above).
        wrong_type_cases = {
            "bare_job_dict": _manifest()["jobs"][0],
            "string": "sign-hosts",
            "int": 42,
            "bool": True,
            "null": None,
        }
        for label, bad_jobs in wrong_type_cases.items():
            with self.subTest(case=label):
                manifest = _manifest()
                manifest["jobs"] = bad_jobs
                raw = json.dumps(manifest).encode()
                with self.assertRaises(ManifestError) as cm:
                    parse(raw, payload_names={"alice.pub"})
                assert cm.exception.reason == "bad_manifest"

        with self.subTest(case="missing"):
            manifest = _manifest()
            del manifest["jobs"]
            raw = json.dumps(manifest).encode()
            with self.assertRaises(ManifestError) as cm:
                parse(raw, payload_names={"alice.pub"})
            assert cm.exception.reason == "bad_manifest"

    def test_unlisted_payload_file_on_disk_is_rejected(self):
        # Review fix 3: the S6 allowlist is symmetric. A file physically
        # present in payload/ that the manifest's payload[] does not list
        # rejects the whole bundle, even though every listed name is present.
        manifest = _manifest()
        manifest["jobs"][0]["payload"] = ["alice.pub"]
        raw = json.dumps(manifest).encode()

        with self.assertRaises(ManifestError) as cm:
            parse(raw, payload_names={"alice.pub", "bob.pub"})
        assert cm.exception.reason == "bad_manifest"


if __name__ == "__main__":
    unittest.main()
