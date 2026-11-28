import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from run import RAW_RX, ROLES, Skip, decode_advert, decode_public_text, find_unacknowledged_deny, pin_keys, write_report
from run import CONTACT_INFO, CONTACT_MESSAGE, CONTACT_MESSAGE_V3, Failure, decode_cli_reply, find_unacknowledged_rule
from run import test_remote_acl as run_remote_acl
from run import pairs, test_shared_rule_recovery as run_shared_rule_recovery


class AdvertTest(unittest.TestCase):
    def test_same_advert_across_paths(self):
        key = bytes(range(32))
        stamp = 1795000020
        payload = key + stamp.to_bytes(4, "little") + bytes(64) + b"\x81test"
        direct = decode_advert(bytes((RAW_RX, 0, 0, 0x11, 0)) + payload, key)
        routed = decode_advert(bytes((RAW_RX, 0, 0, 0x10, 1, 2, 3, 4, 0x41, 0xab, 0xcd)) + payload,
                               key)
        self.assertEqual(direct["path"], [])
        self.assertEqual(routed["path"], ["abcd"])
        self.assertEqual(routed["stamp"], stamp)
        self.assertEqual(direct["advert"], routed["advert"])

    def test_rejects_unrelated_and_incomplete_events(self):
        prefix = bytes((RAW_RX, 0, 0, 0x11, 0))
        key = bytes(range(32))
        self.assertIsNone(decode_advert(prefix + key, key))
        self.assertIsNone(decode_advert(prefix + bytes(101), key))
        self.assertIsNone(decode_advert(bytes((RAW_RX, 0, 0)), key))


class CleanupTest(unittest.TestCase):
    def test_lost_acknowledgment_without_commit(self):
        class Device:
            def cli(self, command):
                return "rev=4 capacity=24"

        self.assertIsNone(find_unacknowledged_deny(Device(), "12" * 32, 4))

    def test_lost_acknowledgment_with_exact_local_rule(self):
        key = "12" * 32
        rule_id = "34" * 16

        class Device:
            def cli(self, command):
                return {
                    "rules status": "rev=5 capacity=24",
                    "rules list 0": f"next=1 {rule_id} deny client {key} local",
                    "rules list 1": "End",
                }[command]

        self.assertEqual(find_unacknowledged_deny(Device(), key, 4), rule_id)

    def test_lost_acknowledgment_recovers_only_the_expected_scope(self):
        key = "12" * 32
        rule_id = "34" * 16

        class Device:
            name = "R1"

            def cli(self, command):
                return {
                    "rules status": "rev=5 capacity=24",
                    "rules list 0": f"next=1 {rule_id} deny client {key} global:bench",
                    "rules list 1": "End",
                }[command]

        self.assertEqual(find_unacknowledged_rule(Device(), "deny", key, 4, "global:bench"), rule_id)
        with self.assertRaisesRegex(Failure, "could not confirm"):
            find_unacknowledged_deny(Device(), key, 4)


class SharedRuleTest(unittest.TestCase):
    def test_deletion_waits_for_reconnection_and_restores_forwarding(self):
        rule_id = "ab" * 16
        state = {"R1": False, "R2": False, "R1_session": True, "R2_session": True}

        class Repeater:
            def __init__(self, name, key):
                self.name, self.key = name, key

            def cli(self, command):
                if command == "rules sync status":
                    return "domain=bench"
                if command.startswith("rules authority "):
                    return "global=allowed"
                if command.startswith("rules peer status domain "):
                    return "peer=authenticated" if state[self.name + "_session"] else "peer=offline"
                if command.startswith("rules device client "):
                    return "trust=denied" if state[self.name] else "trust=unknown"
                if command == "rules status":
                    return "rev=1"
                if command.startswith("rules add deny client "):
                    state["R1"] = state["R2"] = True
                    return f"OK {rule_id}"
                if command == f"rules show {rule_id}":
                    return rule_id if state[self.name] else "Err - no active rule"
                if command.startswith("rules peer disconnect domain "):
                    state[self.name + "_session"] = False
                    return "OK"
                if command == f"rules delete {rule_id}":
                    if state["R1_session"] or state["R2_session"]:
                        raise AssertionError("deny deleted before the domain session went offline")
                    state["R1"] = False
                    return "OK"
                if command.startswith("rules peer connect domain "):
                    state["R1_session"] = state["R2_session"] = True
                    state["R2"] = state["R1"]
                    return "OK"
                raise AssertionError(command)

        def wait(device, command, expected):
            self.assertEqual(pairs(device.cli(command)), expected)

        devices = {"R1": Repeater("R1", "11" * 32), "R2": Repeater("R2", "22" * 32),
                   "ACTOR": SimpleNamespace(key="33" * 32)}
        report = {"samples": [], "cleanup": {}, "temporary_rules": {}}
        with patch("run.wait_for_policy", side_effect=wait), patch("run.sample") as sample:
            run_shared_rule_recovery(devices, report)
        self.assertEqual([call.args[3] for call in sample.call_args_list], [False, True])
        self.assertEqual(report["cleanup"], {"shared deny": "removed"})
        self.assertEqual(report["temporary_rules"], {"shared deny": rule_id})


class FilterEvidenceTest(unittest.TestCase):
    def test_public_text_payload_fingerprint_survives_forwarding(self):
        payload = bytes((0x11, 0x1f, 0x34)) + bytes(16)
        direct = decode_public_text(bytes((RAW_RX, 0, 0, 0x15, 0)) + payload)
        relayed = decode_public_text(bytes((RAW_RX, 0, 0, 0x15, 0x41, 0xab, 0xcd)) + payload)
        self.assertEqual(direct[0], relayed[0])
        self.assertEqual(direct[1], [])
        self.assertEqual(relayed[1], ["abcd"])
        self.assertIsNone(decode_public_text(bytes((RAW_RX, 0, 0, 0x15, 0)) + payload[:-1]))


class RemoteAclTest(unittest.TestCase):
    def test_decodes_only_cli_replies_from_the_expected_contact(self):
        key = bytes(range(32))
        payload = key[:6] + bytes((0xff, 1)) + bytes(4) + b"OK"
        self.assertEqual(decode_cli_reply(bytes((CONTACT_MESSAGE,)) + payload, key), "OK")
        v3 = bytes((CONTACT_MESSAGE_V3, 0, 0, 0)) + payload
        self.assertEqual(decode_cli_reply(v3, key), "OK")
        self.assertIsNone(decode_cli_reply(v3[:-2], key))
        self.assertIsNone(decode_cli_reply(v3, bytes(32)))
        self.assertIsNone(decode_cli_reply(v3[:11] + bytes(1) + v3[12:], key))

    def test_requires_explicit_denial_on_both_repeaters(self):
        class Companion:
            test_only_inbox = True

            def __init__(self, name, denial):
                self.name = name
                self.denial = denial

            def request(self, payload, expected):
                if expected != CONTACT_INFO:
                    raise AssertionError("expected contact lookup")
                return bytes((CONTACT_INFO,)) + payload[1:]

            def repeater_reply(self, repeater, command):
                if command == b"rules status":
                    return "rev=7 mode=normal"
                if command != b"rules mode normal":
                    raise AssertionError("unexpected remote command")
                return self.denial

        devices = {"ADMIN": Companion("ADMIN", "OK"),
                   "ACTOR": Companion("ACTOR", "Err - write permission required")}
        for index, role in enumerate(("R1", "R2"), 1):
            devices[role] = SimpleNamespace(key=f"{index:064x}", cli=lambda command: "rev=7 mode=normal")
        report = {"samples": []}
        run_remote_acl(devices, report)
        self.assertEqual([sample["repeater"] for sample in report["samples"]], ["R1", "R2"])
        devices["ACTOR"].denial = "OK"
        with self.assertRaisesRegex(Failure, "explicitly deny"):
            run_remote_acl(devices, {"samples": []})


class ReportTest(unittest.TestCase):
    def test_keeps_individual_pass_fail_and_skip_results(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bench"
            report = {"status": "FAIL", "reason": "see cases", "run_id": "test", "started": "test",
                      "operation": "all", "devices": {}, "samples": [], "cleanup": {},
                      "cases": [{"name": "actor", "status": "PASS", "reason": "verified"},
                                {"name": "filtering", "status": "FAIL", "reason": "no path"},
                                {"name": "sync", "status": "SKIP", "reason": "bench not ready"}]}
            write_report(path, report)
            suite = ET.parse(path.with_suffix(".xml")).getroot()
            self.assertEqual(suite.attrib["tests"], "3")
            self.assertEqual(suite.attrib["failures"], "1")
            self.assertEqual(suite.attrib["skipped"], "1")
            self.assertIsNotNone(suite.find("testcase[@name='filtering']/failure"))
            self.assertIsNotNone(suite.find("testcase[@name='sync']/skipped"))


class PinTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "hil_config.local.json"
        self.devices = {role: SimpleNamespace(key=f"{i + 1:064x}") for i, role in enumerate(ROLES)}
        self.config = {"roles": {role: {"serial_number": role, "public_key": ""} for role in ROLES}}
        self.path.write_text(json.dumps(self.config))

    def test_writes_every_pin_and_keeps_usb_selectors(self):
        pin_keys(self.path, self.devices, self.config)
        stored = json.loads(self.path.read_text())
        for role in ROLES:
            self.assertEqual(stored["roles"][role]["public_key"], self.devices[role].key)
            self.assertEqual(stored["roles"][role]["serial_number"], role)

    def test_existing_key_change_leaves_config_unchanged(self):
        self.config["roles"]["ACTOR"]["public_key"] = "ff" * 32
        self.path.write_text(json.dumps(self.config))
        before = self.path.read_bytes()
        with self.assertRaisesRegex(Skip, "ACTOR key changed"):
            pin_keys(self.path, self.devices, self.config)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
