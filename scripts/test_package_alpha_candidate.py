import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from package_alpha_candidate import package_candidate

COMMIT = "1" * 40


class PackageAlphaTest(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name)
        self.images = {"R1": root / "tested.zip", "R2": root / "tested.bin"}
        self.output = root / "output"
        self.report_path = root / "actor.json"
        devices = {}
        for index, role in enumerate(("R1", "R2", "ADMIN", "ACTOR"), 1):
            devices[role] = {"key_fingerprint": f"{index:012x}"}
            if role in self.images:
                data = f"test image {role}".encode()
                self.images[role].write_bytes(data)
                devices[role].update(configured_firmware_git_sha=COMMIT,
                                     configured_firmware_sha256=hashlib.sha256(data).hexdigest())
        samples = []
        for sender, observer, forwarded in (("ADMIN", "ACTOR", True), ("ACTOR", "ADMIN", True),
                                            ("ACTOR", "ADMIN", False), ("ADMIN", "ACTOR", True),
                                            ("ACTOR", "ADMIN", True)):
            samples.append({
                "sender": sender, "observer": observer, "expect_forward": forwarded,
                "adverts": {"sample": {"direct": True, "paths": [["aa"], ["bb"]] if forwarded else []}},
                "deltas": {role: {"flood_tx": int(forwarded), "flood_rx": 1, "identity": int(not forwarded)}
                           for role in self.images},
            })
        self.report = {"status": "PASS", "operation": "actor", "repeater_profile": "hardened",
                       "isolated_rf": True, "run_id": "a" * 32, "devices": devices,
                       "cases": [{"name": "actor", "status": "PASS", "samples": samples,
                                  "cleanup": {"R1": "removed", "R2": "removed"}}]}

    def package(self, commit=COMMIT):
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        package_candidate(self.report_path, commit, self.images, self.output)

    def test_package_preserves_both_images_and_records_evidence(self):
        self.package()
        for role, filename in (("R1", "RAK_3401_repeater.zip"), ("R2", "ThinkNode_M5_Repeater.bin")):
            self.assertEqual((self.output / filename).read_bytes(), self.images[role].read_bytes())
        evidence = json.loads((self.output / "alpha-evidence.json").read_text())
        self.assertEqual(evidence["source_commit"], COMMIT)
        self.assertEqual(evidence["actor_report_sha256"], hashlib.sha256(self.report_path.read_bytes()).hexdigest())
        manifest = (self.output / "SHA256SUMS.txt").read_text().splitlines()
        self.assertEqual(len(manifest), 3)
        for line in manifest:
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())

    def test_refuses_skipped_report_or_missing_rx_evidence(self):
        self.report["status"] = "SKIP"
        with self.assertRaisesRegex(ValueError, "passing isolated"):
            self.package()
        self.report["status"] = "PASS"
        self.report["cases"][0]["samples"][2]["deltas"]["R2"]["flood_rx"] = 0
        with self.assertRaisesRegex(ValueError, "identity drops"):
            self.package()
        self.assertFalse(self.output.exists())

    def test_refuses_different_artifact_or_source(self):
        with self.assertRaisesRegex(ValueError, "firmware commit"):
            self.package(commit="2" * 40)
        self.images["R2"].write_bytes(b"unverified firmware")
        with self.assertRaisesRegex(ValueError, "image SHA-256"):
            self.package()
        self.assertFalse(self.output.exists())
