#!/usr/bin/env python3
"""Observe four stock MeshCore/Hardened devices on an isolated RF bench."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
from glob import glob
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import sys
import time
import uuid
import xml.etree.ElementTree as ET

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    sys.exit("Install pyserial in CLion's Python interpreter: python -m pip install pyserial")

ROLES = ("R1", "R2", "ADMIN", "ACTOR")
REPEATERS = ROLES[:2]
KEY = re.compile(r"[0-9a-fA-F]{64}")
RULE = re.compile(r"OK ([0-9a-fA-F]{32})")
CONFIG = Path(__file__).with_name("hil_config.local.json")
DEVICE_QUERY = 22
APP_START = 1
SEND_SELF_ADVERT = 7
DEVICE_INFO = 13
SELF_INFO = 5
RAW_RX = 0x88


class Skip(Exception):
    """Missing bench prerequisites."""


class Failure(Exception):
    """Observed failure or inconclusive RF evidence."""


def pairs(text):
    return dict(re.findall(r"([\w-]+)=([^\s]+)", text))


def fingerprint(key):
    return sha256(bytes.fromhex(key)).hexdigest()[:12]


def decode_advert(frame, origin):
    """Extract only signed-advert routing metadata from a stock raw RX event."""
    if not frame or frame[0] != RAW_RX or len(frame) < 5:
        return None
    raw = frame[3:]
    header = raw[0]
    route = header & 3
    if header >> 6 or ((header >> 2) & 15) != 4 or route not in (0, 1):
        return None
    cursor = 5 if route == 0 else 1
    if len(raw) <= cursor:
        return None
    size = (raw[cursor] >> 6) + 1
    count = raw[cursor] & 63
    path_end = cursor + 1 + size * count
    if size > 3 or path_end + 100 > len(raw):
        return None
    if raw[path_end:path_end + 32] != origin:
        return None
    stamp = int.from_bytes(raw[path_end + 32:path_end + 36], "little")
    # Group copies of an identical signed advert, independent of the path.
    advert = sha256(raw[path_end:]).hexdigest()[:16]
    path = [raw[i:i + size].hex() for i in range(cursor + 1, path_end, size)]
    return {"stamp": stamp, "advert": advert, "path": path}


def ports():
    return list(list_ports.comports())


def select_ports(config):
    by_id = {str(Path(path).resolve()): path for path in glob("/dev/serial/by-id/*")}
    visible = ports()
    selected = {}
    roles = config.get("roles", {})
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise Skip("Configure exactly R1, R2, ADMIN and ACTOR.")
    for role in ROLES:
        settings = roles[role]
        if not isinstance(settings, dict):
            raise Skip(f"{role} configuration must be an object.")
        stable_path = settings.get("by_id")
        serial_number = settings.get("serial_number")
        location = settings.get("location")
        vid_pid = settings.get("vid_pid")
        if not (stable_path or serial_number or (location and vid_pid)):
            raise Skip(f"{role} needs by_id, serial_number, or location plus vid_pid.")
        if stable_path and stable_path not in by_id.values():
            raise Skip(f"{role} stable USB path is absent.")
        matches = []
        for port in visible:
            address = str(Path(port.device).resolve())
            if stable_path and by_id.get(address) != stable_path:
                continue
            if serial_number and port.serial_number != serial_number:
                continue
            if location and port.location != location:
                continue
            if vid_pid and (port.vid is None or port.pid is None
                            or f"{port.vid:04x}:{port.pid:04x}" != vid_pid.lower()):
                continue
            if port.device.startswith("/dev/tty.") and sys.platform == "darwin":
                continue
            matches.append(stable_path or by_id.get(address, port.device))
        if len(matches) != 1 or matches[0] in selected.values():
            raise Skip(f"{role} did not resolve to one unique USB device.")
        selected[role] = matches[0]
    return selected


class Device:
    def __init__(self, name, port):
        self.name = name
        self.usb = serial.Serial(port=None, baudrate=115200, timeout=0.1, write_timeout=1,
                                 exclusive=True)
        self.usb.port = port
        self.usb.dtr = True
        self.usb.rts = False
        self.usb.open()
        self.buffer = bytearray()

    def cli(self, command):
        self.usb.reset_input_buffer()
        self.usb.write((command + "\r").encode("ascii"))
        end = time.monotonic() + 3
        while time.monotonic() < end:
            line = self.usb.readline().decode("ascii", errors="replace").strip()
            if line.startswith("->"):
                return line[2:].strip()
        raise Failure(f"{self.name} timed out on {command.split()[0]}.")

    def frame(self):
        self.buffer.extend(self.usb.read(min(self.usb.in_waiting or 1, 4096)))
        while self.buffer:
            start = self.buffer.find(b">")
            if start < 0:
                self.buffer.clear()
                return None
            del self.buffer[:start]
            if len(self.buffer) < 3:
                break
            size = int.from_bytes(self.buffer[1:3], "little")
            if not 1 <= size <= 512:
                del self.buffer[0]
                continue
            if len(self.buffer) < size + 3:
                break
            frame = bytes(self.buffer[3:3 + size])
            del self.buffer[:3 + size]
            return frame
        return None

    def request(self, payload, expected):
        self.usb.write(b"<" + struct.pack("<H", len(payload)) + payload)
        end = time.monotonic() + 4
        while time.monotonic() < end:
            frame = self.frame()
            if frame and frame[0] == expected:
                return frame
            if frame and frame[0] == 1:
                raise Failure(f"{self.name} rejected companion command {payload[0]}.")
        raise Failure(f"{self.name} did not answer companion command {payload[0]}.")

    def identify(self):
        if self.name in REPEATERS:
            if self.cli("get role").lstrip("> ") != "repeater":
                raise Skip(f"{self.name} is not running repeater firmware.")
            key = self.cli("get public.key").lstrip("> ")
            radio = self.cli("get radio").lstrip("> ").split(",")
            self.details = {
                "board": self.cli("board"), "version": self.cli("ver"),
                "radio": [round(float(radio[0]) * 1000), round(float(radio[1]) * 1000),
                          int(radio[2]), int(radio[3])],
                "policy": pairs(self.cli("rules status")),
            }
            if not self.details["policy"].get("rev"):
                raise Skip(f"{self.name} does not expose the Hardened rule store.")
        else:
            info = self.request(bytes((DEVICE_QUERY, 3)), DEVICE_INFO)
            state = self.request(bytes((APP_START,)) + bytes(7) + b"Hardened HIL", SELF_INFO)
            if len(info) < 80 or len(state) < 58 or state[1] != 1:
                raise Skip(f"{self.name} did not report a supported companion identity.")
            key = state[4:36].hex()
            self.details = {
                "board": info[20:60].split(b"\0", 1)[0].decode("ascii", "replace"),
                "version": info[60:80].split(b"\0", 1)[0].decode("ascii", "replace"),
                "radio": list(struct.unpack_from("<IIBB", state, 48)),
            }
            if len(info) > 80 and info[80]:
                raise Skip(f"{self.name} has companion repeating enabled.")
        if not KEY.fullmatch(key):
            raise Skip(f"{self.name} returned an invalid public key.")
        self.key = key.lower()
        self.details["key_fingerprint"] = fingerprint(self.key)

    def stats(self):
        counters = json.loads(self.cli("stats-packets"))
        drops = pairs(self.cli("rules drops"))
        return {key: int(value) for key, value in (
            ("flood_tx", counters["flood_tx"]), ("flood_rx", counters["flood_rx"]),
            ("identity", drops["identity"]))}


def sample(devices, sender, observer, expect_forward, report):
    before = {role: devices[role].stats() for role in REPEATERS}
    rx, tx = devices[observer], devices[sender]
    rx.usb.reset_input_buffer()
    rx.buffer.clear()
    tx.request(bytes((SEND_SELF_ADVERT, 1)), 0)
    end = time.monotonic() + 10
    adverts = {}
    while time.monotonic() < end:
        observation = decode_advert(rx.frame(), bytes.fromhex(tx.key))
        if observation:
            path = observation["path"]
            advert = adverts.setdefault(observation["advert"], {"direct": False, "paths": []})
            if path and path not in advert["paths"]:
                advert["paths"].append(path)
            elif not path:
                advert["direct"] = True
    after = {role: devices[role].stats() for role in REPEATERS}
    deltas = {role: {key: (after[role][key] - before[role][key]) & 0xffffffff
                     for key in before[role]} for role in REPEATERS}
    report["samples"].append({"sender": sender, "observer": observer,
                              "expect_forward": expect_forward, "adverts": adverts, "deltas": deltas})
    if len(adverts) != 1:
        raise Failure(f"{observer} did not capture exactly one signed advert from {sender}.")
    advert = next(iter(adverts.values()))
    for role in REPEATERS:
        hop = any(path[-1] == devices[role].key[:len(path[-1])] for path in advert["paths"])
        if expect_forward:
            if not hop or deltas[role]["flood_tx"] == 0:
                raise Failure(f"No matching path and TX count proved {role} forwarded {sender}.")
        elif (not advert["direct"] or hop or deltas[role]["flood_tx"]
              or not deltas[role]["flood_rx"] or not deltas[role]["identity"]):
            raise Failure(f"Could not prove that {role} dropped the received {sender} advert.")


def find_unacknowledged_deny(device, key, revision):
    # Only recover a lost acknowledgment when exactly one policy change
    # occurred and the newly visible rule matches this isolated trial.
    status = pairs(device.cli("rules status"))
    if int(status["rev"]) == revision:
        return None
    if int(status["rev"]) != revision + 1:
        raise Failure(f"{device.name} policy changed unexpectedly.")
    cursor = 0
    matches = []
    while cursor < int(status["capacity"]):
        fields = device.cli(f"rules list {cursor}").split()
        if fields == ["End"]:
            break
        next_field, rule_id, kind, subject, value, scope = fields
        next_cursor = int(next_field.removeprefix("next="))
        if next_cursor <= cursor:
            raise Failure(f"{device.name} returned an invalid rule cursor.")
        if (kind, subject, value.lower(), scope) == ("deny", "client", key, "local"):
            matches.append(rule_id)
        cursor = next_cursor
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-fA-F]{32}", matches[0]):
        raise Failure(f"{device.name} could not confirm the temporary deny ID.")
    return matches[0]


def test(devices, report):
    actor = devices["ACTOR"].key
    added = {}
    try:
        sample(devices, "ADMIN", "ACTOR", True, report)
        sample(devices, "ACTOR", "ADMIN", True, report)
        for role in REPEATERS:
            device = devices[role]
            revision = int(pairs(device.cli("rules status"))["rev"])
            report["cleanup"][role] = "deny write not yet confirmed; inspect rules list"
            try:
                reply = device.cli(f"rules add deny client {actor} local")
                rule = RULE.fullmatch(reply)
                rule_id = rule[1] if rule else find_unacknowledged_deny(device, actor, revision)
            except (Failure, OSError, serial.SerialException):
                try:
                    rule_id = find_unacknowledged_deny(device, actor, revision)
                except (Failure, KeyError, ValueError, OSError, serial.SerialException):
                    report["cleanup"][role] = "temporary deny state unknown; inspect rules list"
                    raise Failure(f"{role} did not confirm the deny write or its policy state.") from None
            if not rule_id:
                report["cleanup"].pop(role)
                raise Failure(f"{role} did not create a temporary deny rule.")
            added[role] = rule_id
            report["temporary_rules"][role] = rule_id
            decision = pairs(device.cli(f"rules device client {actor}"))
            if decision.get("trust") != "denied":
                raise Failure(f"{role} did not apply the ACTOR deny.")
        sample(devices, "ACTOR", "ADMIN", False, report)
        sample(devices, "ADMIN", "ACTOR", True, report)
    finally:
        for role, rule_id in added.items():
            try:
                if not devices[role].cli(f"rules delete {rule_id}").startswith("OK"):
                    raise Failure("deletion not acknowledged")
                decision = pairs(devices[role].cli(f"rules device client {actor}"))
                if decision.get("trust") == "denied":
                    raise Failure("deny still active")
                report["cleanup"][role] = "removed"
            except (Failure, OSError, serial.SerialException):
                report["cleanup"][role] = f"manual cleanup required: rules delete {rule_id}"
        if any(value != "removed" for value in report["cleanup"].values()):
            raise Failure("A temporary deny could not be confirmed removed. See report cleanup.")
    sample(devices, "ACTOR", "ADMIN", True, report)


def preflight(devices, config):
    keys = [devices[role].key for role in ROLES]
    if len(set(keys)) != 4 or keys[0][:2] == keys[1][:2]:
        raise Skip("Public keys must be unique, including both repeater path prefixes.")
    for role, device in devices.items():
        pinned = config["roles"][role].get("public_key", "")
        if pinned.lower() != device.key:
            raise Skip(f"{role} key is unpinned or changed. Run --identify and verify the mapping.")
        if device.details["radio"] != devices["R1"].details["radio"]:
            raise Skip(f"{role} radio settings differ from R1.")
    for role in REPEATERS:
        device = devices[role]
        policy = device.details["policy"]
        if policy.get("mode") not in ("normal", "open"):
            raise Skip(f"{role} must start in Normal.")
        if int(policy["active"]) + int(policy["deleted"]) >= int(policy["capacity"]):
            raise Skip(f"{role} needs one available rule slot.")
        for peer in ("ADMIN", "ACTOR"):
            decision = pairs(device.cli(f"rules device client {devices[peer].key}"))
            if decision.get("trust") not in ("allowed", "unknown"):
                raise Skip(f"{role} already denies {peer} or lacks rules device support.")
        if json.loads(device.cli("stats-core")).get("queue_len") != 0:
            raise Skip(f"{role} outbound queue is active. Wait for an isolated, quiet bench.")


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    suite = ET.Element("testsuite", name="MeshCore four-device bench", tests="1",
                       failures=str(int(report["status"] == "FAIL")),
                       skipped=str(int(report["status"] == "SKIP")))
    case = ET.SubElement(suite, "testcase", name=report["operation"])
    if report["status"] != "PASS":
        ET.SubElement(case, "failure" if report["status"] == "FAIL" else "skipped",
                      message=report["reason"])
    ET.ElementTree(suite).write(path.with_suffix(".xml"), encoding="utf-8", xml_declaration=True)
    rows = ["# MeshCore four-device bench", "", f"**{report['status']}** — {report['reason']}",
            "", f"Run: {report['run_id']}", f"Started: {report['started']}", "",
            f"Observed RF trials: {len(report['samples'])}"]
    rows.extend(f"- {role}: {device['board']} ({device['version']})"
                for role, device in report["devices"].items())
    rows.extend(f"- Cleanup {role}: {message}" for role, message in report["cleanup"].items())
    path.with_suffix(".md").write_text("\n".join(rows) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--list", action="store_true", help="List USB devices without opening ports.")
    actions.add_argument("--identify", action="store_true", help="Display full public keys for local pinning.")
    actions.add_argument("--preflight", action="store_true", help="Check bench prerequisites without transmitting.")
    actions.add_argument("--smoke", action="store_true", help="Run the five-advert deny and cleanup scenario.")
    actions.add_argument("--suite", choices=("actor", "acl", "filtering", "security", "sync", "identity"))
    actions.add_argument("--all", action="store_true", help="Run the only implemented RF scenario and list gaps.")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--report", type=Path, default=Path("out/hil/actor"))
    parser.add_argument("--isolated-rf", action="store_true",
                        help="Confirm legal settings and RF isolation and authorize temporary local policy writes.")
    args = parser.parse_args()
    if args.list:
        for port in ports():
            if port.vid is not None and port.pid is not None:
                print(f"{port.device}  {port.product or port.description}  "
                      f"{port.vid:04x}:{port.pid:04x}  serial={port.serial_number}  location={port.location}")
        return 0

    report = {"run_id": uuid.uuid4().hex, "started": datetime.now(timezone.utc).isoformat(),
              "operation": args.suite or ("preflight" if args.preflight else "identify" if args.identify else "actor"),
              "devices": {}, "samples": [], "temporary_rules": {}, "cleanup": {}}
    stage = "preflight"
    try:
        if not args.config.is_file():
            raise Skip("Copy hil_config.example.json to your local config and fill in the USB selectors.")
        config = json.loads(args.config.read_text())
        with ExitStack() as stack:
            devices = {}
            for role, port in select_ports(config).items():
                device = Device(role, port)
                stack.callback(device.usb.close)
                devices[role] = device
            time.sleep(1)
            failed_identities = []
            for role, device in devices.items():
                try:
                    device.identify()
                except (Skip, Failure, ValueError, OSError, serial.SerialException) as err:
                    failed_identities.append(f"{role}: {err}")
                    continue
                commit = config["roles"][role].get("firmware_git_sha", "")
                if re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                    device.details["configured_firmware_git_sha"] = commit
                report["devices"][role] = device.details
                if args.identify:
                    print(f"{role} {device.details['board']}: {device.key}")
            if failed_identities:
                raise Skip("; ".join(failed_identities))
            if args.identify:
                report.update(status="PASS", reason="Four USB application identities read. RF not run.")
            else:
                preflight(devices, config)
                if args.preflight:
                    report.update(status="PASS", reason="Four-device preflight passed. RF not run.")
                else:
                    if args.suite not in (None, "actor", "acl"):
                        raise Skip(f"The {args.suite} suite is not implemented in this runner.")
                    if not args.isolated_rf:
                        raise Skip("RF trials require --isolated-rf for the shielded or attenuated bench.")
                    stage = "RF"
                    try:
                        test(devices, report)
                        report.update(status="PASS", reason="Five stock adverts verified temporary deny, allowed forwarding and cleanup.")
                        if args.all or args.suite == "acl":
                            report["unrun"] = ["full ACL", "filtering", "security", "sync", "identity"]
                            report.update(status="SKIP", reason="Actor scenario passed. Remaining release coverage was not run.")
                    finally:
                        for role in REPEATERS:
                            try:
                                report["devices"][role]["final_policy"] = pairs(devices[role].cli("rules status"))
                            except (Failure, OSError, serial.SerialException):
                                report["devices"][role]["final_policy"] = "unavailable"
    except Skip as err:
        report.update(status="SKIP", reason=str(err))
    except (Failure, KeyError, TypeError, ValueError, OSError, serial.SerialException) as err:
        report.update(status="FAIL" if stage == "RF" else "SKIP", reason=f"{stage}: {err}")
    except KeyboardInterrupt:
        report.update(status="FAIL", reason="Interrupted; check cleanup and stored rule IDs.")
    write_report(args.report, report)
    print(f"{report['status']} — {report['reason']}")
    print(args.report.with_suffix(".json"))
    return {"PASS": 0, "FAIL": 1, "SKIP": 2}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
