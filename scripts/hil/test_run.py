import json
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from run import RAW_RX, ROLES, Skip, decode_advert, decode_public_text, find_unacknowledged_deny, pin_keys, write_report
from run import CONTACT_INFO, CONTACT_MESSAGE, CONTACT_MESSAGE_V3, Device, Failure, decode_cli_reply, find_unacknowledged_rule
from run import test_manual_onboarding as run_manual_onboarding, test_remote_acl as run_remote_acl
from run import test_peer_onboarding as run_peer_onboarding
from run import decode_quiet_receipt, quiet_criteria, quiet_summary, run_scenarios, pairs, test_shared_rule_recovery as run_shared_rule_recovery

from setup_bench import observer_secret


class ObserverSettingsTest(unittest.TestCase):
    def test_secret_is_private_and_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "observer.txt"
            first = observer_secret(path)
            self.assertEqual(len(first), 16)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(observer_secret(path), first)
            path.chmod(0o644)
            with self.assertRaisesRegex(Failure, "private file"):
                observer_secret(path)


class AdvertPolicyTest(unittest.TestCase):
    def test_direct_only_fixture_skips_flood_advert_suite_before_running(self):
        report = {"cases": [], "samples": [], "temporary_rules": {}, "cleanup": {}}
        run_scenarios({}, report, ("actor",), direct_adverts_only=True)
        self.assertEqual(report["cases"][0]["status"], "SKIP")
        self.assertIn("direct adverts only", report["cases"][0]["reason"])
        self.assertEqual(report["samples"], [])


    def test_private_only_fixture_skips_public_filter_suite(self):
        report = {"cases": [], "samples": [], "temporary_rules": {}, "cleanup": {}}
        run_scenarios({}, report, ("filtering",), private_channel_only=True)
        self.assertEqual(report["cases"][0]["status"], "SKIP")
        self.assertIn("private channels only", report["cases"][0]["reason"])
        self.assertEqual(report["samples"], [])


class QuietDeliveryTest(unittest.TestCase):
    def test_receipt_matches_stock_channel_frame_and_ignores_other_messages(self):
        timestamp = 1795000020
        text = b"HIL quiet 82fa0a29"
        data = bytes((0, 0x42, 0)) + timestamp.to_bytes(4, "little") + b"Bench: " + text
        self.assertEqual(decode_quiet_receipt(bytes((8,)) + data, text, timestamp), 2)
        self.assertEqual(decode_quiet_receipt(bytes((17, 0, 0, 0)) + data, text, timestamp), 2)
        self.assertIsNone(decode_quiet_receipt(bytes((17, 0)) + data, text, timestamp))
        self.assertIsNone(decode_quiet_receipt(bytes((8,)) + data, text, timestamp + 1))
        self.assertIsNone(decode_quiet_receipt(bytes((8,)) + data, b"unrelated", timestamp))

    def test_quiet_thresholds_keep_missed_sends_in_the_denominator(self):
        def results(good, seconds):
            return quiet_summary([{"delivered": trial < good, "latency_s": seconds}
                                  for trial in range(20)])

        baseline = results(20, 5)
        acceptable = quiet_criteria(results(19, 7), baseline)
        self.assertEqual(acceptable, {"p95_limit_s": 7, "delivery_pass": True, "latency_pass": True})
        self.assertFalse(quiet_criteria(results(18, 5), baseline)["delivery_pass"])
        self.assertFalse(quiet_criteria(results(20, 7.1), baseline)["latency_pass"])
        self.assertEqual(quiet_criteria(results(20, 12), results(20, 10))["p95_limit_s"], 12)


class RepeaterPreflightTest(unittest.TestCase):
    def repeater(self, policy):
        response = {"get role": "> repeater", "get public.key": "> " + "ab" * 32,
                    "get radio": "> 869.525, 250, 10, 5", "board": "RAK3401",
                    "ver": "test", "rules status": policy, "filter": "> 1byte off, data on, public off"}
        return SimpleNamespace(name="R1", cli=response.__getitem__)

    def test_baseline_exposes_inherited_filters(self):
        repeater = self.repeater("Unknown command")
        Device.identify(repeater, baseline=True)
        self.assertEqual(repeater.details["filters"], {"1byte": "off", "data": "on", "public": "off"})
        self.assertEqual(repeater.details["radio"], [869525, 250000, 10, 5])
        with self.assertRaisesRegex(Skip, "Hardened rule store"):
            Device.identify(repeater)

    def test_hardened_requires_its_own_profile(self):
        repeater = self.repeater("rev=8 mode=normal")
        with self.assertRaisesRegex(Skip, "baseline CLI"):
            Device.identify(repeater, baseline=True)
        Device.identify(repeater)
        self.assertEqual(repeater.details["policy"], {"rev": "8", "mode": "normal"})


class ManualOnboardingTest(unittest.TestCase):
    def test_hold_probe_precedes_review_and_commit(self):
        token = "0000000702"
        pending = "subnet=bench onboarding=pending source=manual transit=held"
        active = "subnet=bench onboarding=active source=manual transit=available"

        class Joining:
            state = pending
            revision = 7

            def cli(self, command):
                if command == f"rules onboarding commit {token}":
                    self.state = active
                    self.revision = 8
                    return "OK - committed rev=8 transit=available"
                return {
                    "rules onboarding": self.state,
                    "rules status": f"rev={self.revision}",
                    "rules onboarding review": f"review={token} subnet=bench mode=normal filters=0/1/0 repeat=on",
                }[command]

        joining = Joining()
        devices = {"R1": SimpleNamespace(cli=lambda command: active), "R2": joining}
        report = {"samples": [], "cleanup": {}}
        observed = []

        def observe(devices, sender, observer, forward, report, held_repeater=None):
            observed.append((joining.state, forward, held_repeater))

        with patch("run.sample", side_effect=observe):
            run_manual_onboarding(devices, report)
        self.assertEqual(observed, [(pending, True, "R2"), (active, True, None)])
        self.assertEqual(report["samples"][0]["revision_after"], "8")

    def test_no_probe_or_write_if_already_active(self):
        active = "subnet=bench onboarding=active source=manual transit=available"
        devices = {role: SimpleNamespace(cli=lambda command: active) for role in ("R1", "R2")}
        with patch("run.sample") as sample, self.assertRaisesRegex(Skip, "set up R2"):
            run_manual_onboarding(devices, {})
        sample.assert_not_called()


class PeerOnboardingTest(unittest.TestCase):
    def test_snapshot_is_staged_with_matching_policy_before_activation(self):
        provider_key, joining_key = "11" * 32, "22" * 32
        mode = "subnet=bench mode=normal rev=0000000000000007 local=normal effective=normal"
        fetch = f"rules onboarding peer fetch {provider_key}"

        def provider_cli(command):
            return {
                "rules onboarding": "subnet=bench onboarding=active source=manual transit=available",
                f"rules peer status subnet {joining_key}": "peer=authenticated",
                f"rules authority {provider_key}": "subnet=allowed",
                "rules subnet mode": mode,
            }[command]

        def joining_cli(command):
            if command == fetch:
                requests.append(command)
                return "OK - policy snapshot request queued"
            if command == "rules onboarding":
                source = "peer" if requests else "manual"
                return f"subnet=bench onboarding=pending source={source} transit=held"
            if command == "rules onboarding peer":
                return next(transfer)
            return {
                f"rules peer status subnet {provider_key}": "peer=authenticated",
                f"rules authority {provider_key}": "subnet=allowed",
                "rules subnet mode": mode,
            }[command]

        requests = []
        transfer = iter(("peer=idle received=0 transit=held", "peer=pending received=0 transit=held",
                         "peer=staged received=150 transit=held"))
        devices = {"R1": SimpleNamespace(key=provider_key, cli=provider_cli),
                   "R2": SimpleNamespace(key=joining_key, cli=joining_cli)}
        report = {"samples": [], "cleanup": {}}
        with patch("run.activate_onboarding") as activate, patch("run.time.sleep"):
            run_peer_onboarding(devices, report)
        self.assertEqual(requests, [fetch])
        activate.assert_called_once_with(devices, report,
                                        {"subnet": "bench", "onboarding": "pending",
                                         "source": "peer", "transit": "held"})
        self.assertEqual(report["samples"][0]["received"], 150)


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
