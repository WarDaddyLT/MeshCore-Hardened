#!/usr/bin/env python3
"""Provision the isolated four-device fixture over USB."""

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from secrets import token_bytes
import struct
import time

from run import (APP_START, CHANNEL_INFO, CONFIG, GET_CHANNEL, REPEATERS, ROLES, SELF_INFO,
                 SEND_CHANNEL_TEXT, Device, Failure, Skip, pin_keys, preflight, select_ports, serial)

RADIO = [869618, 62500, 8, 8]
SCOPE = b"hardened"
SCOPE_KEY = sha256(b"#" + SCOPE).digest()[:16]
CHANNEL = b"Hardened Bench"
NAMES = {"R1": "Hardened R1 RAK", "R2": "Hardened R2 M5",
         "ADMIN": "Hardened ADMIN", "ACTOR": "Hardened ACTOR"}
SET_NAME = 8
SET_RADIO = 11
SET_CHANNEL = 32
SET_SCOPE_OVERRIDE = 54
SET_DEFAULT_SCOPE = 63
GET_DEFAULT_SCOPE = 64
DEFAULT_SCOPE_INFO = 28


def observer_secret(path):
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise Failure("The observer settings must be a private file with mode 0600.")
        for line in path.read_text().splitlines():
            if line.startswith("Secret (hex): "):
                key = bytes.fromhex(line.split(": ", 1)[1])
                if len(key) == 16 and any(key):
                    return key
        raise Failure("The observer settings do not contain a valid 16-byte test key.")
    key = token_bytes(16)
    with os.fdopen(fd, "w") as output:
        output.write(f"Channel: {CHANNEL.decode()}\nSecret (hex): {key.hex()}\n"
                     "Scope: hardened\nFrequency: 869.618 MHz\nBandwidth: 62.5 kHz\n"
                     "Spreading factor: 8\nCoding rate: 4/8\n")
    return key


def set_private_channel(device, key):
    empty = None
    selected = None
    for slot in range(1, 40):
        try:
            record = device.request(bytes((GET_CHANNEL, slot)), CHANNEL_INFO)
        except Failure:
            break
        if len(record) < 50 or record[1] != slot:
            raise Failure(f"{device.name} returned a malformed channel slot.")
        name = record[2:34].split(b"\0", 1)[0]
        if name == CHANNEL:
            selected = slot
            break
        if empty is None and not name and not any(record[34:50]):
            empty = slot
    slot = selected if selected is not None else empty
    if slot is None:
        raise Failure(f"{device.name} needs a free slot for Hardened Bench.")
    device.request(bytes((SET_CHANNEL, slot)) + CHANNEL.ljust(32, b"\0") + key, 0)
    record = device.request(bytes((GET_CHANNEL, slot)), CHANNEL_INFO)
    if record[2:34].split(b"\0", 1)[0] != CHANNEL or record[34:50] != key:
        raise Failure(f"{device.name} did not verify the shared private channel.")
    return slot


def self_info(device):
    return device.request(bytes((APP_START,)) + bytes(7) + b"Hardened HIL", SELF_INFO)


def configure_companion(device, name, key):
    if device.details["radio"] != RADIO:
        device.request(bytes((SET_RADIO,)) + struct.pack("<IIBBB", *RADIO, 0), 0)
    device.request(bytes((SET_NAME,)) + name.encode(), 0)
    if not self_info(device).endswith(name.encode()):
        raise Failure(f"{device.name} did not verify its test name.")
    device.request(bytes((SET_DEFAULT_SCOPE,)) + SCOPE.ljust(31, b"\0") + SCOPE_KEY, 0)
    device.request(bytes((SET_SCOPE_OVERRIDE, 0)), 0)
    record = device.request(bytes((GET_DEFAULT_SCOPE,)), DEFAULT_SCOPE_INFO)
    if record[1:32].split(b"\0", 1)[0] != SCOPE or record[32:48] != SCOPE_KEY:
        raise Failure(f"{device.name} did not verify the hardened flood scope.")
    return set_private_channel(device, key)


def require_cli(device, command, expected=None):
    answer = device.cli(command)
    if (expected is not None and answer != expected) or (expected is None and answer.startswith("Err")):
        raise Failure(f"{device.name} did not confirm {command}.")
    return answer


def configure_repeater(device, name):
    reboot = device.details["radio"] != RADIO
    if reboot:
        require_cli(device, "set radio 869.618,62.5,8,8")
    require_cli(device, f"set name {name}")
    require_cli(device, "get name", f"> {name}")
    require_cli(device, "region default hardened", "default scope is now hardened")
    for region in require_cli(device, "region list allowed").split(","):
        if region.strip() != SCOPE.decode():
            require_cli(device, f"region denyf {region.strip()}", "OK")
    require_cli(device, "region denyf *", "OK")
    require_cli(device, "region save", "OK")
    require_cli(device, "set advert.interval 0")
    require_cli(device, "set flood.advert.interval 0")
    require_cli(device, "set dutycycle 10")
    require_cli(device, "set repeat on")
    return reboot


def open_devices(stack, config):
    devices = {}
    for role, port in select_ports(config).items():
        device = Device(role, port)
        stack.callback(device.usb.close)
        devices[role] = device
    time.sleep(1)
    for role, device in devices.items():
        try:
            device.identify()
        except (Failure, Skip, OSError, serial.SerialException) as error:
            raise Failure(f"{role} could not be identified: {error}") from None
    return devices


def check_channel(devices, slot):
    before = {role: devices[role].stats()["flood_tx"] for role in REPEATERS}
    payload = bytes((SEND_CHANNEL_TEXT, 0, slot)) + struct.pack("<I", int(time.time()))
    devices["ACTOR"].request(payload + b"ACTOR private channel check", 0)
    time.sleep(8)
    after = {role: (devices[role].stats()["flood_tx"] - before[role]) & 0xffffffff for role in REPEATERS}
    if any(count != 1 for count in after.values()):
        raise Failure(f"Expected one repeater TX each for the private message. Observed {after}.")
    print("ACTOR queued the private channel check. Both repeaters recorded one flood TX.")


def setup(config_path, observer, actor_serial, actor_name, images, check):
    if config_path.name != "hil_config.local.json":
        raise Failure("Use a private config named hil_config.local.json.")
    config = json.loads(config_path.read_text())
    if actor_serial:
        config["roles"]["ACTOR"] = {"serial_number": actor_serial, "display_name": actor_name}
    names = {role: config["roles"][role].get("display_name", NAMES[role]) for role in ROLES}
    for role, name in names.items():
        if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,30}", name):
            raise Failure(f"{role} needs a short ASCII device name.")
    for role, commit, path in images:
        if role not in ROLES or not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise Failure("Image provenance requires a role and full lowercase Git commit.")
        config["roles"][role].update(firmware_git_sha=commit, firmware_sha256=sha256(Path(path).read_bytes()).hexdigest())

    slots = {}
    with ExitStack() as stack:
        devices = open_devices(stack, config)
        keys = {role: device.key for role, device in devices.items()}
        for role, key in keys.items():
            pinned = config["roles"][role].get("public_key", "").lower()
            if pinned and pinned != key:
                raise Failure(f"{role} does not match its pinned public key.")
        if len(set(keys.values())) != len(ROLES) or keys["R1"][:2] == keys["R2"][:2]:
            raise Failure("The fixture needs four distinct keys and distinct repeater path prefixes.")
        if actor_serial and not self_info(devices["ACTOR"]).lower().endswith(actor_name.lower().encode()):
            raise Failure("The replacement ACTOR did not report the requested existing identity name.")
        key = observer_secret(observer)
        reboot = []
        for role, device in devices.items():
            if role in REPEATERS:
                if configure_repeater(device, names[role]):
                    reboot.append(role)
            else:
                slots[role] = configure_companion(device, names[role], key)
        for role in reboot:
            devices[role].usb.write(b"reboot\r")
            devices[role].usb.flush()

    if reboot:
        time.sleep(6)
    with ExitStack() as stack:
        devices = open_devices(stack, config)
        for role, device in devices.items():
            if device.key != keys[role] or device.details["radio"] != RADIO:
                raise Failure(f"{role} did not verify its original identity and EU/UK Narrow radio settings.")
            if role in REPEATERS:
                require_cli(device, "region default", "default scope is hardened")
                require_cli(device, "region list allowed", "hardened")
                require_cli(device, "get advert.interval", "> 0")
                require_cli(device, "get flood.advert.interval", "> 0")
                require_cli(device, "get dutycycle", "> 10.0%")
                require_cli(device, "get repeat", "> on")
            print(f"{role}: {names[role]} · {device.details['board']} · {device.details['version']}")
        config["bench_scope"] = SCOPE.decode()
        config["bench_channel_slots"] = slots
        config["direct_adverts_only"] = True
        pin_keys(config_path, devices, config)
        preflight(devices, config)
        if check:
            check_channel(devices, slots["ACTOR"])
    print(f"Four-device setup verified. Private observer settings are in {observer}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--observer", type=Path, required=True, help="Private observer settings file")
    parser.add_argument("--actor-serial", help="Replace the ACTOR with this exact USB serial")
    parser.add_argument("--actor-name", help="Verify and preserve this existing name on a replacement ACTOR")
    parser.add_argument("--record-image", action="append", nargs=3, metavar=("ROLE", "COMMIT", "PATH"), default=[])
    parser.add_argument("--check-channel", action="store_true", help="Send one ordinary private ACTOR test message")
    parser.add_argument("--isolated-rf", action="store_true", help="Confirm the RF bench is isolated")
    args = parser.parse_args()
    if args.check_channel and not args.isolated_rf:
        parser.error("--check-channel requires --isolated-rf")
    if bool(args.actor_serial) != bool(args.actor_name):
        parser.error("--actor-serial and --actor-name must be supplied together")
    try:
        setup(args.config, args.observer, args.actor_serial, args.actor_name, args.record_image, args.check_channel)
    except (Failure, Skip, KeyError, ValueError, OSError, serial.SerialException) as error:
        parser.exit(2, f"Bench setup incomplete: {error}\n")


if __name__ == "__main__":
    main()
