#!/usr/bin/env python3
"""Observe four stock MeshCore/Hardened devices on an isolated RF bench."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
from glob import glob
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import struct
import sys
import time
import tempfile
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
SEND_CONTACT_TEXT = 2
SEND_CHANNEL_TEXT = 3
NEXT_MESSAGE = 10
GET_CONTACT = 30
GET_CHANNEL = 31
CONTACT_INFO = 3
TEXT_SENT = 6
CONTACT_MESSAGE = 7
CHANNEL_MESSAGE = 8
NO_MORE_MESSAGES = 10
CONTACT_MESSAGE_V3 = 16
CHANNEL_MESSAGE_V3 = 17
CLI_REPLY = 1
CLI_COMMAND = 3
CHANNEL_INFO = 18
PUBLIC_KEY = bytes.fromhex("8b3387e9c5cd6a6ac9e5edbaa115cd72")
DEVICE_INFO = 13
SELF_INFO = 5
RAW_RX = 0x88
QUIET_TRIALS = 20
QUIET_INTERVAL_SECONDS = 60


class Skip(Exception):
    """Missing bench prerequisites."""


class Failure(Exception):
    """Observed failure or inconclusive RF evidence."""


def pairs(text):
    return dict(re.findall(r"([\w-]+)=([^\s]+)", text))


def fingerprint(key):
    return sha256(bytes.fromhex(key)).hexdigest()[:12]


def decode_flood(frame, payload_type, minimum):
    if not frame or frame[0] != RAW_RX or len(frame) < 5:
        return None
    raw = frame[3:]
    header = raw[0]
    route = header & 3
    if header >> 6 or ((header >> 2) & 15) != payload_type or route not in (0, 1):
        return None
    cursor = 5 if route == 0 else 1
    if len(raw) <= cursor:
        return None
    size = (raw[cursor] >> 6) + 1
    count = raw[cursor] & 63
    path_end = cursor + 1 + size * count
    if size > 3 or path_end + minimum > len(raw):
        return None
    path = [raw[i:i + size].hex() for i in range(cursor + 1, path_end, size)]
    return raw[path_end:], path


def decode_advert(frame, origin):
    """Extract signed-advert routing metadata from a stock raw RX event."""
    observation = decode_flood(frame, 4, 100)
    if not observation:
        return None
    payload, path = observation
    if payload[:32] != origin:
        return None
    stamp = int.from_bytes(payload[32:36], "little")
    # Group copies of an identical signed advert, independent of the path.
    advert = sha256(payload).hexdigest()[:16]
    return {"stamp": stamp, "advert": advert, "path": path}


def decode_public_text(frame):
    observation = decode_flood(frame, 5, 19)
    if not observation:
        return None
    payload, path = observation
    if payload[0] != 0x11 or (len(payload) - 3) % 16:
        return None
    return sha256(payload).hexdigest()[:16], path


def decode_quiet_receipt(frame, text, timestamp):
    if not frame or frame[0] not in (CHANNEL_MESSAGE, CHANNEL_MESSAGE_V3):
        return None
    offset = 4 if frame[0] == CHANNEL_MESSAGE_V3 else 1
    if len(frame) <= offset + 7 or frame[offset] != 0 or frame[offset + 2] != 0:
        return None
    path = frame[offset + 1]
    if path == 0xff or struct.unpack_from("<I", frame, offset + 3)[0] != timestamp:
        return None
    if not frame[offset + 7:].endswith(b": " + text):
        return None
    return path & 63


def decode_cli_reply(frame, repeater_key):
    if not frame or frame[0] not in (CONTACT_MESSAGE, CONTACT_MESSAGE_V3):
        return None
    offset = 4 if frame[0] == CONTACT_MESSAGE_V3 else 1
    if len(frame) <= offset + 12 or frame[offset:offset + 6] != repeater_key[:6]:
        return None
    if frame[offset + 7] != CLI_REPLY:
        return None
    return frame[offset + 12:].decode("ascii", errors="replace")


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
        accepted = (expected,) if isinstance(expected, int) else expected
        self.usb.write(b"<" + struct.pack("<H", len(payload)) + payload)
        end = time.monotonic() + 4
        while time.monotonic() < end:
            frame = self.frame()
            if frame and frame[0] in accepted:
                return frame
            if frame and frame[0] == 1:
                raise Failure(f"{self.name} rejected companion command {payload[0]}.")
        raise Failure(f"{self.name} did not answer companion command {payload[0]}.")

    def repeater_reply(self, repeater, command):
        key = bytes.fromhex(repeater.key)
        header = bytes((SEND_CONTACT_TEXT, CLI_COMMAND, 0)) + struct.pack("<I", 0)
        self.request(header + key[:6] + command, TEXT_SENT)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            frame = self.request(bytes((NEXT_MESSAGE,)),
                                 (NO_MORE_MESSAGES, CONTACT_MESSAGE, CONTACT_MESSAGE_V3, 8, 17))
            if frame[0] == NO_MORE_MESSAGES:
                time.sleep(0.5)
                continue
            reply = decode_cli_reply(frame, key)
            if reply is None:
                raise Failure(f"{self.name} returned a message unrelated to the test request.")
            return reply
        raise Failure(f"{self.name} did not receive a CLI reply from {repeater.name}.")

    def identify(self, baseline=False):
        if self.name in REPEATERS:
            if self.cli("get role").lstrip("> ") != "repeater":
                raise Skip(f"{self.name} is not running repeater firmware.")
            key = self.cli("get public.key").lstrip("> ")
            radio = self.cli("get radio").lstrip("> ").split(",")
            self.details = {
                "board": self.cli("board"), "version": self.cli("ver"),
                "radio": [round(float(radio[0]) * 1000), round(float(radio[1]) * 1000),
                          int(radio[2]), int(radio[3])],
            }
            status = self.cli("rules status")
            if baseline:
                if status != "Unknown command":
                    raise Skip(f"{self.name} did not report the SaveMeshcore baseline CLI.")
            else:
                policy = pairs(status)
                if not policy.get("rev"):
                    raise Skip(f"{self.name} does not expose the Hardened rule store.")
                self.details["policy"] = policy
            filters = re.fullmatch(r"1byte (on|off), data (on|off), public (on|off)",
                                   self.cli("filter").lstrip("> "))
            if not filters:
                raise Skip(f"{self.name} did not report the inherited packet filters.")
            self.details["filters"] = dict(zip(("1byte", "data", "public"), filters.groups()))
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
            ("identity", drops["identity"]), ("probation", drops.get("probation", 0)),
            ("locked", drops.get("locked", 0)), ("filter", drops.get("filter", 0)))}


def sample(devices, sender, observer, expect_forward, report, drop_reason="identity", held_repeater=None):
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
    if held_repeater:
        report["samples"][-1]["held_repeater"] = held_repeater
    if len(adverts) != 1:
        raise Failure(f"{observer} did not capture exactly one signed advert from {sender}.")
    advert = next(iter(adverts.values()))
    for role in REPEATERS:
        hop = any(path[-1] == devices[role].key[:len(path[-1])] for path in advert["paths"])
        if role == held_repeater:
            if not advert["direct"] or hop or deltas[role]["flood_tx"] or not deltas[role]["flood_rx"]:
                raise Failure(f"Could not prove that {role} held the received {sender} advert.")
        elif expect_forward:
            if not hop or deltas[role]["flood_tx"] == 0:
                raise Failure(f"No matching path and TX count proved {role} forwarded {sender}.")
        elif (not advert["direct"] or hop or deltas[role]["flood_tx"]
              or not deltas[role]["flood_rx"] or not deltas[role][drop_reason]):
            raise Failure(f"Could not prove that {role} dropped the received {sender} advert.")


def find_unacknowledged_deny(device, key, revision):
    return find_unacknowledged_rule(device, "deny", key, revision)


def find_unacknowledged_rule(device, expected_kind, key, revision, expected_scope="local"):
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
        if (kind, subject, value.lower(), scope) == (expected_kind, "client", key, expected_scope):
            matches.append(rule_id)
        cursor = next_cursor
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-fA-F]{32}", matches[0]):
        raise Failure(f"{device.name} could not confirm the temporary {expected_kind} ID.")
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


def test_remote_acl(devices, report):
    admin, actor = devices["ADMIN"], devices["ACTOR"]
    if not admin.test_only_inbox or not actor.test_only_inbox:
        raise Skip("The ACL case needs companion inboxes reserved for test replies.")
    for role in REPEATERS:
        repeater = devices[role]
        key = bytes.fromhex(repeater.key)
        for companion in (admin, actor):
            try:
                contact = companion.request(bytes((GET_CONTACT,)) + key, CONTACT_INFO)
            except Failure:
                raise Skip(f"{companion.name} needs {role} imported as a stock repeater contact.") from None
            if contact[1:33] != key:
                raise Skip(f"{companion.name} did not return the pinned {role} contact.")
    for role in REPEATERS:
        repeater = devices[role]
        before = pairs(repeater.cli("rules status"))
        if before.get("mode") != "normal":
            raise Skip(f"{role} must start and remain in Normal for the ACL case.")
        if admin.repeater_reply(repeater, b"rules mode normal") != "OK":
            raise Failure(f"{role} did not acknowledge ADMIN's existing Normal setting.")
        readable = pairs(actor.repeater_reply(repeater, b"rules status"))
        if readable.get("rev") != before["rev"] or readable.get("mode") != "normal":
            raise Failure(f"{role} did not return its policy status to the provisioned read-only client.")
        denied = actor.repeater_reply(repeater, b"rules mode normal")
        after = pairs(repeater.cli("rules status"))
        if denied != "Err - write permission required":
            raise Failure(f"{role} did not explicitly deny the read-only client's admin command.")
        if after.get("rev") != before["rev"] or after.get("mode") != "normal":
            raise Failure(f"{role} changed the policy during the ACL case.")
        report["samples"].append({"type": "stock remote authorization", "repeater": role,
                                  "admin_acknowledged": True, "actor_denied": True,
                                  "revision_before": before["rev"], "revision_after": after["rev"]})


def test_modes(devices, report):
    actor, admin = devices["ACTOR"].key, devices["ADMIN"].key
    for role in REPEATERS:
        info = pairs(devices[role].cli(f"rules device client {actor}"))
        if info.get("trust") != "unknown" or "probation-hours" in info:
            raise Skip(f"{role} needs ACTOR to be unknown with no existing probation.")
        if "probation" not in pairs(devices[role].cli("rules drops")):
            raise Skip(f"{role} does not expose the required mode diagnostics.")

    added = {}
    touched = []
    try:
        for role in REPEATERS:
            device = devices[role]
            if pairs(device.cli(f"rules device client {admin}")).get("trust") == "allowed":
                continue
            revision = int(pairs(device.cli("rules status"))["rev"])
            report["cleanup"][f"{role} admin allow"] = "unconfirmed; inspect rules list"
            try:
                reply = device.cli(f"rules add allow client {admin} local")
            except (Failure, OSError, serial.SerialException):
                reply = ""
            match = RULE.fullmatch(reply)
            rule_id = match[1] if match else find_unacknowledged_rule(device, "allow", admin, revision)
            if not rule_id:
                report["cleanup"].pop(f"{role} admin allow")
                raise Failure(f"{role} did not create an ADMIN allow rule.")
            added[role] = rule_id
            report["temporary_rules"][f"{role} admin allow"] = rule_id

        for mode, counter in (("protected", "probation"), ("locked", "locked")):
            for role in REPEATERS:
                device = devices[role]
                if role not in touched:
                    touched.append(role)
                report["cleanup"][f"{role} mode"] = "must restore Normal"
                if device.cli(f"rules mode {mode}") != "OK" or pairs(device.cli("rules mode"))["mode"] != mode:
                    raise Failure(f"{role} did not confirm {mode} mode.")
            sample(devices, "ACTOR", "ADMIN", False, report, drop_reason=counter)
            if mode == "protected":
                for role in REPEATERS:
                    info = pairs(devices[role].cli(f"rules device client {actor}"))
                    if info.get("probation-hours") != "72":
                        raise Failure(f"{role} did not record ACTOR's initial probation.")
            sample(devices, "ADMIN", "ACTOR", True, report)
    finally:
        for role in touched:
            try:
                device = devices[role]
                device.cli("rules mode normal")
                if pairs(device.cli("rules mode")).get("mode") != "normal":
                    raise Failure("mode restore not confirmed")
                report["cleanup"][f"{role} mode"] = "removed"
            except (Failure, OSError, serial.SerialException):
                report["cleanup"][f"{role} mode"] = "manual cleanup required: rules mode normal"
        for role, rule_id in added.items():
            try:
                device = devices[role]
                if not device.cli(f"rules delete {rule_id}").startswith("OK"):
                    raise Failure("deletion not acknowledged")
                if pairs(device.cli(f"rules device client {admin}")).get("trust") != "unknown":
                    raise Failure("allow still active")
                report["cleanup"][f"{role} admin allow"] = "removed"
            except (Failure, OSError, serial.SerialException):
                report["cleanup"][f"{role} admin allow"] = f"manual cleanup required: rules delete {rule_id}"
        if any(value != "removed" for value in report["cleanup"].values()):
            raise Failure("Temporary mode or allow cleanup failed. See report cleanup.")
    sample(devices, "ACTOR", "ADMIN", True, report)


def sample_public_text(devices, expect_forward, report):
    before = {role: devices[role].stats() for role in REPEATERS}
    observer, sender = devices["ADMIN"], devices["ACTOR"]
    observer.usb.reset_input_buffer()
    observer.buffer.clear()
    text = f"HIL filter {uuid.uuid4().hex[:12]}".encode("ascii")
    sender.request(bytes((SEND_CHANNEL_TEXT, 0, 0)) + struct.pack("<I", int(time.time())) + text, 0)
    frames = {}
    end = time.monotonic() + 10
    while time.monotonic() < end:
        observation = decode_public_text(observer.frame())
        if observation:
            digest, path = observation
            frames.setdefault(digest, []).append(path)
    after = {role: devices[role].stats() for role in REPEATERS}
    deltas = {role: {key: (after[role][key] - before[role][key]) & 0xffffffff
                     for key in before[role]} for role in REPEATERS}
    report["samples"].append({"sender": "ACTOR", "observer": "ADMIN", "type": "Public text",
                              "expect_forward": expect_forward, "frames": frames, "deltas": deltas})
    if len(frames) != 1:
        raise Failure("Did not capture one unambiguous Public text packet.")
    paths = next(iter(frames.values()))
    for role in REPEATERS:
        hop = any(path and path[-1] == devices[role].key[:len(path[-1])] for path in paths)
        counters = deltas[role]
        if expect_forward:
            if not hop or not counters["flood_tx"]:
                raise Failure(f"No path and TX evidence of {role} forwarding Public text.")
        elif [] not in paths or hop or counters["flood_tx"] or not counters["flood_rx"] or not counters["filter"]:
            raise Failure(f"No direct observation and filter-drop evidence from {role}.")


def quiet_summary(samples):
    latencies = sorted(sample["latency_s"] for sample in samples if sample["delivered"])
    return {"attempted": len(samples), "delivered": len(latencies),
            "delivery_rate": len(latencies) / len(samples),
            "p95_s": latencies[math.ceil(len(latencies) * .95) - 1] if latencies else None}


def quiet_criteria(current, baseline):
    if baseline["p95_s"] is None:
        raise Failure("The baseline did not record a routed delivery.")
    limit = baseline["p95_s"] + max(2, baseline["p95_s"] * .20)
    return {"p95_limit_s": limit, "delivery_pass": current["delivery_rate"] >= .95,
            "latency_pass": current["p95_s"] is not None and current["p95_s"] <= limit}


def validate_quiet_baseline(baseline, current):
    if (baseline.get("status") != "PASS" or baseline.get("operation") != "quiet"
            or baseline.get("repeater_profile") != "savemeshcore"
            or len(baseline.get("samples", ())) != QUIET_TRIALS):
        raise Skip("A complete SaveMeshcore quiet comparison report is required.")
    for role in ROLES:
        old, new = baseline["devices"][role], current[role]
        keys = ("board", "radio", "key_fingerprint", "filters") if role in REPEATERS else (
            "board", "radio", "key_fingerprint", "version")
        if any(old.get(key) != new.get(key) for key in keys):
            raise Skip(f"{role} identity, radio settings, or comparison profile differs from the baseline.")
    return quiet_summary(baseline["samples"])


def run_quiet(devices, report, baseline_report):
    receiver = devices["ACTOR"]
    if not receiver.test_only_inbox:
        raise Skip("Quiet comparison requires a dedicated ACTOR inbox and test_only_inboxes=true.")
    for role in ("ADMIN", "ACTOR"):
        channel = devices[role].request(bytes((GET_CHANNEL, 0)), CHANNEL_INFO)
        if len(channel) < 50 or channel[34:50] != PUBLIC_KEY:
            raise Skip(f"{role} needs the stock Public channel in slot 0.")
    for role in REPEATERS:
        details = devices[role].details
        if not details.get("configured_firmware_sha256") or not details.get("configured_firmware_git_sha"):
            raise Skip(f"Record the installed {role} image hash and source commit in the local config.")
        if details["filters"]["public"] != "off":
            raise Skip(f"{role} must start with Public filtering off for quiet comparison.")
    reference = validate_quiet_baseline(baseline_report, report["devices"]) if baseline_report is not None else None

    for index in range(QUIET_TRIALS):
        sent_at = time.monotonic()
        report["samples"].append(quiet_trial(devices, index + 1))
        if index + 1 < QUIET_TRIALS:
            time.sleep(max(0, QUIET_INTERVAL_SECONDS - (time.monotonic() - sent_at)))
    summary = quiet_summary(report["samples"])
    report["quiet"] = summary
    if reference:
        result = quiet_criteria(summary, reference)
        report["quiet_comparison"] = dict(result, baseline=reference)
        if not result["delivery_pass"] or not result["latency_pass"]:
            raise Failure("Hardened missed the quiet delivery or latency threshold.")
    elif summary["delivered"] == 0:
        raise Failure("SaveMeshcore recorded no routed companion deliveries.")


def quiet_trial(devices, sequence):
    sender, receiver = devices["ADMIN"], devices["ACTOR"]
    before = {role: int(json.loads(devices[role].cli("stats-packets"))["flood_tx"]) for role in REPEATERS}
    text = f"HIL quiet {uuid.uuid4().hex[:8]}".encode("ascii")
    timestamp = int(time.time())
    started = time.monotonic()
    sender.request(bytes((SEND_CHANNEL_TEXT, 0, 0)) + struct.pack("<I", timestamp) + text, 0)
    hops, latency = None, None
    while time.monotonic() - started < 15:
        frame = receiver.request(bytes((NEXT_MESSAGE,)),
                                 (NO_MORE_MESSAGES, CHANNEL_MESSAGE, CHANNEL_MESSAGE_V3,
                                  CONTACT_MESSAGE, CONTACT_MESSAGE_V3))
        hops = decode_quiet_receipt(frame, text, timestamp)
        if hops is not None:
            latency = round(time.monotonic() - started, 3)
            break
        if frame[0] == NO_MORE_MESSAGES:
            time.sleep(.1)
    after = {role: int(json.loads(devices[role].cli("stats-packets"))["flood_tx"]) for role in REPEATERS}
    deltas = {role: (after[role] - before[role]) & 0xffffffff for role in REPEATERS}
    return {"trial": sequence, "sender": "ADMIN", "receiver": "ACTOR", "hops": hops,
            "flood_tx_delta": deltas, "latency_s": latency,
            "delivered": hops == len(REPEATERS) and all(n == 1 for n in deltas.values())}


def test_filtering(devices, report):
    for role in ("ADMIN", "ACTOR"):
        channel = devices[role].request(bytes((GET_CHANNEL, 0)), CHANNEL_INFO)
        if len(channel) < 50 or channel[34:50] != PUBLIC_KEY:
            raise Skip(f"{role} channel 0 needs the stock Public channel on the isolated bench.")
    for role in REPEATERS:
        if devices[role].cli("filter public").lstrip("> ") != "filter public off":
            raise Skip(f"{role} must start with the Public filter off.")
    touched = []
    try:
        sample_public_text(devices, True, report)
        for role in REPEATERS:
            device = devices[role]
            touched.append(role)
            report["cleanup"][f"{role} Public filter"] = "must restore off"
            device.cli("filter public on")
            if device.cli("filter public").lstrip("> ") != "filter public on":
                raise Failure(f"{role} did not confirm Public filtering.")
        sample_public_text(devices, False, report)
        sample(devices, "ADMIN", "ACTOR", True, report)
    finally:
        for role in touched:
            try:
                device = devices[role]
                device.cli("filter public off")
                if device.cli("filter public").lstrip("> ") != "filter public off":
                    raise Failure("filter restore not confirmed")
                report["cleanup"][f"{role} Public filter"] = "removed"
            except (Failure, OSError, serial.SerialException):
                report["cleanup"][f"{role} Public filter"] = "manual cleanup required: filter public off"
        if any(value != "removed" for value in report["cleanup"].values()):
            raise Failure("Temporary Public filter cleanup failed. See report cleanup.")
    sample_public_text(devices, True, report)


def wait_for_policy(device, command, expected, timeout=240):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        observed = pairs(device.cli(command))
        if all(observed.get(field) == value for field, value in expected.items()):
            return observed
        time.sleep(2)
    raise Failure(f"{device.name} did not report the expected policy state.")


def test_sync(devices, report):
    origin, peer = devices["R1"], devices["R2"]
    starting = [pairs(device.cli("rules subnet mode")) for device in (origin, peer)]
    if starting[0].get("subnet") in (None, "none") or starting[0].get("subnet") != starting[1].get("subnet"):
        raise Skip("R1 and R2 need the same preconfigured test subnet.")
    if any(state.get("mode") != "normal" or state.get("effective") != "normal" for state in starting):
        raise Skip("Both repeaters need committed Normal subnet policy before this case.")
    if starting[0].get("rev") != starting[1].get("rev"):
        raise Skip("Start from the same committed subnet revision on both repeaters.")
    for device, other in ((origin, peer), (peer, origin)):
        if pairs(device.cli("rules onboarding")).get("onboarding") != "active":
            raise Skip(f"{device.name} needs to complete onboarding before the sync case.")
        if pairs(device.cli(f"rules peer status subnet {other.key}")).get("peer") != "authenticated":
            raise Skip("Establish the authenticated subnet session before the sync case.")
        if pairs(device.cli(f"rules authority {origin.key}")).get("subnet") != "allowed":
            raise Skip(f"{device.name} needs R1's subnet publisher grant.")

    status_command = f"rules subnet peer {peer.key}"
    report["cleanup"]["subnet mode"] = "must restore Normal on both repeaters"
    try:
        started = time.monotonic()
        if origin.cli("rules subnet mode protected") != "OK":
            raise Failure("R1 did not acknowledge the signed mode update.")
        local = pairs(origin.cli("rules subnet mode"))
        if local.get("mode") != "protected" or local.get("rev") == starting[0]["rev"]:
            raise Failure("R1 did not commit a new Protected subnet revision.")
        applied = wait_for_policy(peer, "rules subnet mode", {"rev": local["rev"], "effective": "protected"})
        delay = round(time.monotonic() - started, 2)
        if not origin.cli(f"rules subnet peer query {peer.key}").startswith("OK"):
            raise Failure("R1 did not queue the applied-policy query.")
        confirmed = wait_for_policy(origin, status_command, {"confirmation": "confirmed", "rev": local["rev"]})
        report["samples"].append({"type": "signed subnet mode", "origin": local, "applied": applied,
                                  "confirmation": confirmed, "seconds_to_apply": delay})
    finally:
        try:
            if origin.cli("rules subnet mode normal") != "OK":
                raise Failure("Normal restore not acknowledged")
            restored = pairs(origin.cli("rules subnet mode"))
            wait_for_policy(peer, "rules subnet mode", {"rev": restored["rev"], "effective": "normal"})
            report["cleanup"]["subnet mode"] = "removed"
        except (Failure, KeyError, OSError, serial.SerialException):
            raise Failure("Restore signed Normal policy on R1 and confirm its application on R2.") from None


def onboarding_fixture(devices):
    origin, joining = devices["R1"], devices["R2"]
    ready = pairs(origin.cli("rules onboarding"))
    pending = pairs(joining.cli("rules onboarding"))
    subnet = pending.get("subnet")
    if not subnet or subnet == "none" or ready.get("subnet") != subnet:
        raise Skip("R1 and R2 need the same configured test subnet.")
    if ready.get("onboarding") != "active" or ready.get("transit") != "available":
        raise Skip("R1 must already have active transit as the forwarding control.")
    if pending != {"subnet": subnet, "onboarding": "pending", "source": "manual", "transit": "held"}:
        raise Skip("Use USB to set up R2 with pending onboarding and no staged snapshot.")
    return pending


def activate_onboarding(devices, report, pending):
    joining = devices["R2"]
    subnet = pending["subnet"]
    source = pending["source"]
    sample(devices, "ADMIN", "ACTOR", True, report, held_repeater="R2")
    before = pairs(joining.cli("rules status"))
    review = pairs(joining.cli("rules onboarding review"))
    token = review.get("review", "")
    if (review.get("subnet") != subnet or review.get("mode") != "normal" or review.get("repeat") != "on"
            or not re.fullmatch(r"[01]/[01]/[01]", review.get("filters", ""))
            or not re.fullmatch(r"[0-9a-f]{10}", token)
            or int(token[:8], 16) != int(before["rev"])):
        raise Failure("R2 did not return a complete Normal policy review for its current revision.")
    if pairs(joining.cli("rules onboarding")) != pending:
        raise Failure("R2 changed its forwarding hold before committing the review.")

    report["cleanup"]["R2 onboarding"] = "commit unconfirmed; inspect rules onboarding"
    reply = joining.cli(f"rules onboarding commit {token}")
    after = pairs(joining.cli("rules onboarding"))
    active = {"subnet": subnet, "onboarding": "active", "source": source, "transit": "available"}
    if after != active:
        raise Failure("R2 did not activate the reviewed policy and release its forwarding hold.")
    report["cleanup"]["R2 onboarding"] = "activated as intended"
    committed = pairs(reply)
    if not reply.startswith("OK - committed ") or committed.get("transit") != "available":
        raise Failure("R2 became active without acknowledging the reviewed commit.")
    expected_revision = str(int(before["rev"]) + 1)
    if committed.get("rev") != expected_revision or pairs(joining.cli("rules status")).get("rev") != expected_revision:
        raise Failure("R2 did not advance the acknowledged policy revision exactly once.")
    report["samples"].append({"type": f"{source} onboarding commit", "repeater": "R2",
                              "revision_before": before["rev"], "revision_after": committed["rev"],
                              "mode": review["mode"], "filters": review["filters"]})
    sample(devices, "ADMIN", "ACTOR", True, report)


def test_manual_onboarding(devices, report):
    activate_onboarding(devices, report, onboarding_fixture(devices))


def test_peer_onboarding(devices, report):
    pending = onboarding_fixture(devices)
    provider, joining = devices["R1"], devices["R2"]
    if pairs(joining.cli("rules onboarding peer")).get("peer") != "idle":
        raise Skip("R2 needs an idle peer onboarding slot.")
    for end, peer in ((provider, joining), (joining, provider)):
        if pairs(end.cli(f"rules peer status subnet {peer.key}")).get("peer") != "authenticated":
            raise Skip("Provision a fresh authenticated subnet session between R1 and R2.")
    for device in (provider, joining):
        if pairs(device.cli(f"rules authority {provider.key}")).get("subnet") != "allowed":
            raise Skip(f"{device.name} needs R1's subnet publisher grant.")
    policy = pairs(provider.cli("rules subnet mode"))
    revision = policy.get("rev", "")
    if (policy.get("mode") != "normal" or not re.fullmatch(r"[0-9a-f]{16}", revision)
            or int(revision, 16) == 0):
        raise Skip("R1 needs a signed Normal mode in the test subnet.")

    report["cleanup"]["R2 snapshot"] = "request unconfirmed; inspect rules onboarding peer"
    try:
        if joining.cli(f"rules onboarding peer fetch {provider.key}") != "OK - policy snapshot request queued":
            raise Failure("R2 did not accept a snapshot request from the approved R1 provider.")
        staged = wait_for_peer_snapshot(joining)
    except (Failure, OSError, serial.SerialException):
        try:
            if (pairs(joining.cli("rules onboarding peer")).get("peer") == "pending"
                    and joining.cli("rules onboarding peer cancel") != "OK - peer transfer cleared"):
                raise Failure("R2 did not acknowledge snapshot cancellation.")
            report["cleanup"]["R2 snapshot"] = "no pending transfer; inspect held policy before retry"
        except (Failure, OSError, serial.SerialException):
            report["cleanup"]["R2 snapshot"] = "check and cancel any pending transfer over USB"
        raise

    pending = dict(pending, source="peer")
    report["cleanup"]["R2 snapshot"] = "staged as intended"
    if pairs(joining.cli("rules onboarding")) != pending or staged.get("transit") != "held":
        raise Failure("R2 did not report a staged peer policy with transit held.")
    mode = pairs(joining.cli("rules subnet mode"))
    if mode.get("rev") != revision or mode.get("effective") != "normal":
        raise Failure("The staged R2 policy did not match the provider's signed Normal revision.")
    if int(staged["received"]) <= 0:
        raise Failure("R2 reported an empty snapshot transfer.")
    report["samples"].append({"type": "peer snapshot staged", "repeater": "R2", "provider": "R1",
                              "subnet_revision": revision, "received": int(staged["received"])})
    activate_onboarding(devices, report, pending)


def wait_for_peer_snapshot(joining):
    deadline = time.monotonic() + 51 * 60
    while time.monotonic() < deadline:
        status = pairs(joining.cli("rules onboarding peer"))
        state = status.get("peer")
        if state == "staged":
            return status
        if state != "pending" or status.get("transit") != "held":
            raise Failure("R2 did not keep the snapshot transfer pending with transit held.")
        time.sleep(10)
    raise Failure("R2 did not stage the snapshot within the transfer window.")


def test_shared_rule_recovery(devices, report):
    origin, peer = devices["R1"], devices["R2"]
    actor = devices["ACTOR"].key
    domain = pairs(origin.cli("rules sync status")).get("domain", "")
    if not re.fullmatch(r"[a-z0-9_-]{1,15}", domain):
        raise Skip("R1 needs a configured test policy domain.")
    peer_sync = pairs(peer.cli("rules sync status"))
    if peer_sync.get("domain") != domain:
        raise Skip("R1 and R2 need the same preconfigured test policy domain.")
    if pairs(peer.cli(f"rules authority {origin.key}")).get("global") != "allowed":
        raise Skip("R2 needs the R1 global publishing grant.")

    links = ((origin, peer), (peer, origin))
    for repeater, other in links:
        status = pairs(repeater.cli(f"rules peer status domain {other.key}"))
        if status.get("peer") != "authenticated":
            raise Skip("Establish the authenticated domain session on both repeaters before this case.")
    original = {device.name: pairs(device.cli(f"rules device client {actor}")).get("trust")
                for device, _ in links}
    if any(trust not in ("allowed", "unknown") for trust in original.values()):
        raise Skip("The shared-rule case needs ACTOR to start without a deny.")

    def reconnect():
        if not origin.cli(f"rules peer connect domain {peer.key}").startswith("OK"):
            raise Failure("R1 did not start re-establishing the domain session.")
        for device, other in links:
            wait_for_policy(device, f"rules peer status domain {other.key}", {"peer": "authenticated"})

    def check_deleted():
        for device, _ in links:
            wait_for_policy(device, f"rules device client {actor}", {"trust": original[device.name]})
            if device.cli(f"rules show {rule_id}") != "Err - no active rule":
                raise Failure(f"{device.name} still lists the temporary shared rule.")

    scope = f"global:{domain}"
    revision = int(pairs(origin.cli("rules status"))["rev"])
    rule_id = None
    report["cleanup"]["shared deny"] = "unconfirmed; inspect R1 global rules"
    try:
        try:
            reply = origin.cli(f"rules add deny client {actor} {scope}")
        except (Failure, OSError, serial.SerialException):
            reply = ""
        match = RULE.fullmatch(reply)
        rule_id = match[1] if match else find_unacknowledged_rule(origin, "deny", actor, revision, scope)
        if not rule_id:
            report["cleanup"].pop("shared deny")
            raise Failure("R1 did not create the temporary shared deny.")
        report["temporary_rules"]["shared deny"] = rule_id
        for device, _ in links:
            wait_for_policy(device, f"rules device client {actor}", {"trust": "denied"})
            if rule_id not in device.cli(f"rules show {rule_id}"):
                raise Failure(f"{device.name} did not commit the expected shared deny.")
        sample(devices, "ACTOR", "ADMIN", False, report)

        for device, other in links:
            if not device.cli(f"rules peer disconnect domain {other.key}").startswith("OK"):
                raise Failure(f"{device.name} did not disconnect the domain session.")
            if pairs(device.cli(f"rules peer status domain {other.key}")).get("peer") != "offline":
                raise Failure(f"{device.name} still reports the domain session active.")
        if not origin.cli(f"rules delete {rule_id}").startswith("OK"):
            raise Failure("R1 did not confirm deletion during the session outage.")
        if rule_id not in peer.cli(f"rules show {rule_id}"):
            raise Failure("R2 did not retain its last committed deny during the session outage.")
        reconnect()
        check_deleted()
        report["cleanup"]["shared deny"] = "removed"
        report["samples"].append({"type": "shared-rule session recovery", "rule_id": rule_id,
                                  "peer_retained_policy_offline": True, "both_deleted_after_reconnect": True})
    finally:
        if rule_id and report["cleanup"]["shared deny"] != "removed":
            report["cleanup"]["shared deny"] = f"inspect R1 and R2 after deleting {rule_id} on R1"
            try:
                if origin.cli(f"rules show {rule_id}") != "Err - no active rule":
                    if not origin.cli(f"rules delete {rule_id}").startswith("OK"):
                        raise Failure("temporary shared deny not removed on R1")
                for device, other in links:
                    device.cli(f"rules peer disconnect domain {other.key}")
                reconnect()
                check_deleted()
                report["cleanup"]["shared deny"] = "removed"
            except (Failure, KeyError, OSError, serial.SerialException):
                raise Failure("Temporary shared deny cleanup was not verified. See the report.") from None
    sample(devices, "ACTOR", "ADMIN", True, report)


def preflight(devices, config, baseline=False):
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
        if json.loads(device.cli("stats-core")).get("queue_len") != 0:
            raise Skip(f"{role} outbound queue is active. Wait for an isolated, quiet bench.")
        if baseline:
            continue
        policy = device.details["policy"]
        if policy.get("mode") not in ("normal", "open"):
            raise Skip(f"{role} must start in Normal.")
        available = int(policy["free"]) if "free" in policy else (
            int(policy["capacity"]) - int(policy["active"]) - int(policy["deleted"]))
        if available < 1:
            raise Skip(f"{role} needs one available rule slot.")
        for peer in ("ADMIN", "ACTOR"):
            decision = pairs(device.cli(f"rules device client {devices[peer].key}"))
            if decision.get("trust") not in ("allowed", "unknown"):
                raise Skip(f"{role} already denies {peer} or lacks rules device support.")


def pin_keys(path, devices, config):
    keys = [devices[role].key for role in ROLES]
    if len(set(keys)) != len(ROLES):
        raise Skip("The four USB application keys must be distinct.")
    for role in ROLES:
        settings = config["roles"][role]
        key = devices[role].key
        pinned = settings.get("public_key", "").lower()
        if pinned and pinned != key:
            raise Skip(f"{role} key changed. Verify the device before clearing the old pin.")
        settings["public_key"] = key
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            json.dump(config, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    cases = report.get("cases") or [{"name": report["operation"], "status": report["status"], "reason": report["reason"]}]
    suite = ET.Element("testsuite", name="MeshCore four-device bench", tests=str(len(cases)),
                       failures=str(sum(case["status"] == "FAIL" for case in cases)),
                       skipped=str(sum(case["status"] == "SKIP" for case in cases)))
    for result in cases:
        case = ET.SubElement(suite, "testcase", name=result["name"])
        if result["status"] != "PASS":
            ET.SubElement(case, "failure" if result["status"] == "FAIL" else "skipped", message=result["reason"])
    ET.ElementTree(suite).write(path.with_suffix(".xml"), encoding="utf-8", xml_declaration=True)
    rows = ["# MeshCore four-device bench", "", f"**{report['status']}** — {report['reason']}",
            "", f"Run: {report['run_id']}", f"Started: {report['started']}", "",
            f"Observed RF trials: {len(report['samples'])}"]
    rows.extend(f"- {role}: {device['board']} ({device['version']})"
                for role, device in report["devices"].items())
    if "quiet" in report:
        measured = report["quiet"]
        rows.extend(["", f"Routed deliveries: {measured['delivered']}/{measured['attempted']}",
                     f"Delivered-message p95 latency (seconds): {measured['p95_s']}"])
    rows.extend(f"- Cleanup {role}: {message}" for role, message in report["cleanup"].items())
    rows.extend(f"- {case['name']}: {case['status']} — {case['reason']}" for case in report.get("cases", []))
    path.with_suffix(".md").write_text("\n".join(rows) + "\n")


SCENARIOS = {
    "actor": (test, "Temporary attributable deny, legitimate forwarding, and cleanup verified."),
    "acl": (test_remote_acl, "ADMIN commands and read-only client denial verified over stock MeshCore."),
    "filtering": (test_filtering, "Public filter forwarding, drops, unaffected adverts, and cleanup verified."),
    "security": (test_modes, "Protected and Locked admission, legitimate forwarding, and cleanup verified."),
    "sync": (test_sync, "Signed subnet propagation, peer confirmation, and Normal restore verified."),
    "shared": (test_shared_rule_recovery, "Signed shared rule, outage retention, and deletion convergence verified."),
}

PREPARED_SCENARIOS = {
    "onboarding-manual": (test_manual_onboarding, "Manual policy review, commit, and forwarding verified."),
    "onboarding-peer": (test_peer_onboarding, "Peer snapshot staging, policy activation, and forwarding verified."),
}

REMAINING = ("remaining ACL cases", "complete filter regression", "physical partition",
             "manual and peer onboarding (separate setup)",
             "stock Android and room identity", "signed neighbour notices", "baseline comparison")


FLOOD_ADVERT_SUITES = {"actor", "filtering", "security", "shared", "onboarding-manual", "onboarding-peer"}


def run_scenarios(devices, report, selected, direct_adverts_only=False):
    for name in selected:
        result = {"name": name, "samples": [], "temporary_rules": {}, "cleanup": {}}
        callback, passed = (SCENARIOS | PREPARED_SCENARIOS)[name]
        try:
            if direct_adverts_only and name in FLOOD_ADVERT_SUITES:
                raise Skip("This suite requires flood adverts. The fixture allows direct adverts only.")
            callback(devices, result)
            result.update(status="PASS", reason=passed)
        except Skip as err:
            result.update(status="SKIP", reason=str(err))
        except (Failure, KeyError, ValueError, OSError, serial.SerialException) as err:
            result.update(status="FAIL", reason=str(err))
        report["cases"].append(result)
        report["samples"].extend(result["samples"])
        for category in ("temporary_rules", "cleanup"):
            report[category].update({f"{name}/{key}": value for key, value in result[category].items()})
        if result["status"] == "FAIL":
            break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--list", action="store_true", help="List USB devices without opening ports.")
    actions.add_argument("--identify", action="store_true", help="Display full public keys for local pinning.")
    actions.add_argument("--pin", action="store_true", help="Pin verified USB identities in the private config.")
    actions.add_argument("--preflight", action="store_true", help="Check bench prerequisites without transmitting.")
    actions.add_argument("--smoke", action="store_true", help="Run the five-advert deny and cleanup scenario.")
    actions.add_argument("--suite", choices=(*SCENARIOS, *PREPARED_SCENARIOS, "quiet", "identity"))
    actions.add_argument("--all", action="store_true", help="Run implemented live scenarios and record remaining coverage.")
    parser.add_argument("--baseline", action="store_true",
                        help="Select the SaveMeshcore firmware profile for preflight or quiet measurement.")
    parser.add_argument("--baseline-report", type=Path, help="Use a prior SaveMeshcore quiet JSON report.")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--report", type=Path, default=Path("out/hil/actor"))
    parser.add_argument("--isolated-rf", action="store_true",
                        help="Confirm legal settings and RF isolation and authorize temporary local bench settings.")
    args = parser.parse_args()
    if args.baseline and not (args.preflight or args.suite == "quiet"):
        parser.error("--baseline requires --preflight or --suite quiet")
    if args.suite == "quiet" and args.baseline == bool(args.baseline_report):
        parser.error("Quiet measurement requires either --baseline or --baseline-report")
    if args.baseline_report and args.suite != "quiet":
        parser.error("--baseline-report requires --suite quiet")
    if args.list:
        for port in ports():
            if port.vid is not None and port.pid is not None:
                print(f"{port.device}  {port.product or port.description}  "
                      f"{port.vid:04x}:{port.pid:04x}  serial={port.serial_number}  location={port.location}")
        return 0

    report = {"run_id": uuid.uuid4().hex, "started": datetime.now(timezone.utc).isoformat(),
              "operation": args.suite or ("baseline-preflight" if args.baseline else "preflight" if args.preflight
                                          else "identify" if args.identify
                                          else "pin" if args.pin else "all" if args.all else "actor"),
              "repeater_profile": "savemeshcore" if args.baseline else "hardened",
              "isolated_rf": False,
              "devices": {}, "cases": [], "samples": [], "temporary_rules": {}, "cleanup": {}}
    stage = "preflight"
    try:
        if args.pin and args.config.name != "hil_config.local.json":
            raise Skip("Pinning requires a private file named hil_config.local.json.")
        if not args.config.is_file():
            raise Skip("Copy hil_config.example.json to your local config and fill in the USB selectors.")
        config = json.loads(args.config.read_text())
        with ExitStack() as stack:
            devices = {}
            for role, port in select_ports(config).items():
                device = Device(role, port)
                device.test_only_inbox = config.get("test_only_inboxes") is True
                stack.callback(device.usb.close)
                devices[role] = device
            time.sleep(1)
            failed_identities = []
            for role, device in devices.items():
                try:
                    device.identify(baseline=args.baseline)
                except (Skip, Failure, ValueError, OSError, serial.SerialException) as err:
                    failed_identities.append(f"{role}: {err}")
                    continue
                commit = config["roles"][role].get("firmware_git_sha", "")
                if re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                    device.details["configured_firmware_git_sha"] = commit
                image_hash = config["roles"][role].get("firmware_sha256", "")
                if re.fullmatch(r"[0-9a-fA-F]{64}", image_hash):
                    device.details["configured_firmware_sha256"] = image_hash
                report["devices"][role] = device.details
                if args.identify:
                    print(f"{role} {device.details['board']}: {device.key}")
            if failed_identities:
                raise Skip("; ".join(failed_identities))
            if args.identify:
                report.update(status="PASS", reason="Four USB application identities read. RF not run.")
            elif args.pin:
                pin_keys(args.config, devices, config)
                preflight(devices, config)
                report.update(status="PASS", reason="Four device keys pinned and preflight passed. RF not run.")
            else:
                preflight(devices, config, baseline=args.baseline)
                if args.preflight:
                    profile = "SaveMeshcore baseline" if args.baseline else "Hardened"
                    report.update(status="PASS", reason=f"Four-device {profile} preflight passed. RF not run.")
                elif args.suite == "quiet":
                    if not args.isolated_rf:
                        raise Skip("Quiet measurement requires the isolated four-device RF topology.")
                    baseline = json.loads(args.baseline_report.read_text()) if args.baseline_report else None
                    if args.baseline_report and not isinstance(baseline, dict):
                        raise Skip("The SaveMeshcore quiet report must be a JSON object.")
                    stage = "RF"
                    report["isolated_rf"] = True
                    run_quiet(devices, report, baseline)
                    report.update(status="PASS", reason="Quiet stock-client delivery measurement recorded.")
                else:
                    selected = tuple(SCENARIOS) if args.all else (args.suite or "actor",)
                    if any(name not in SCENARIOS and name not in PREPARED_SCENARIOS for name in selected):
                        raise Skip(f"The {args.suite} suite is not implemented in this runner.")
                    if not args.isolated_rf:
                        raise Skip("RF trials require --isolated-rf for the shielded or attenuated bench.")
                    stage = "RF"
                    report["isolated_rf"] = True
                    try:
                        run_scenarios(devices, report, selected,
                                      direct_adverts_only=config.get("direct_adverts_only") is True)
                        status = "PASS"
                        if any(case["status"] == "FAIL" for case in report["cases"]):
                            status = "FAIL"
                        elif args.all or any(case["status"] == "SKIP" for case in report["cases"]):
                            status = "SKIP"
                        covered = {case["name"] for case in report["cases"]}
                        report["cases"].extend(
                            {"name": name, "status": "SKIP", "reason": "Earlier scenario failed."}
                            for name in selected if name not in covered
                        )
                        if args.all:
                            report["unrun"] = list(REMAINING)
                            report["cases"].extend(
                                {"name": name, "status": "SKIP", "reason": "Release coverage still pending."}
                                for name in report["unrun"]
                            )
                        reason = f"{len(covered)} live scenario(s) recorded. See individual results."
                        report.update(status=status, reason=reason)
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
    if args.all and not report["cases"]:
        report["cases"] = [{"name": name, "status": "SKIP", "reason": report["reason"]}
                           for name in (*SCENARIOS, *REMAINING)]
    if report["cases"] and report["status"] == "FAIL" and not any(
        case["status"] == "FAIL" for case in report["cases"]
    ):
        report["cases"].append({"name": "bench", "status": "FAIL", "reason": report["reason"]})
    write_report(args.report, report)
    print(f"{report['status']} — {report['reason']}")
    print(args.report.with_suffix(".json"))
    return {"PASS": 0, "FAIL": 1, "SKIP": 2}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
