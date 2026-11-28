"""Package the exact two repeater images recorded by a passing Alpha bench run."""

import argparse
from hashlib import sha256 as hash_bytes
import json
from pathlib import Path
import re
import shutil
import tempfile

from build_repeaters import sha256, write_checksums

REPEATERS = {
    "R1": "RAK_3401_repeater.zip",
    "R2": "ThinkNode_M5_Repeater.bin",
}
ROLES = {*REPEATERS, "ADMIN", "ACTOR"}
ACTOR_SEQUENCE = (
    ("ADMIN", "ACTOR", True),
    ("ACTOR", "ADMIN", True),
    ("ACTOR", "ADMIN", False),
    ("ADMIN", "ACTOR", True),
    ("ACTOR", "ADMIN", True),
)


def verify_actor_report(report, commit):
    if (report["status"] != "PASS" or report["operation"] != "actor"
            or report["repeater_profile"] != "hardened" or report.get("isolated_rf") is not True):
        raise ValueError("A passing isolated Hardened actor report is required")
    if not re.fullmatch(r"[0-9a-f]{32}", report["run_id"]):
        raise ValueError("The actor report is missing a valid run ID")

    devices = report["devices"]
    if set(devices) != ROLES:
        raise ValueError("The report must contain all four physical roles")
    fingerprints = {device["key_fingerprint"] for device in devices.values()}
    if len(fingerprints) != len(ROLES) or any(not re.fullmatch(r"[0-9a-f]{12}", key) for key in fingerprints):
        raise ValueError("The report must contain four distinct verified device fingerprints")

    (case,) = report["cases"]
    if case["name"] != "actor" or case["status"] != "PASS":
        raise ValueError("The isolated actor case must pass")
    if case["cleanup"] != {role: "removed" for role in REPEATERS}:
        raise ValueError("Both repeaters must confirm temporary deny cleanup")
    samples = case["samples"]
    if len(samples) != len(ACTOR_SEQUENCE):
        raise ValueError("The actor report must contain the full forwarding and denial sequence")
    for sample, (sender, observer, forward) in zip(samples, ACTOR_SEQUENCE):
        if ((sample["sender"], sample["observer"]) != (sender, observer)
                or sample["expect_forward"] is not forward):
            raise ValueError("The actor samples do not match the required sequence")
        (advert,) = sample["adverts"].values()
        deltas = sample["deltas"]
        if forward:
            last_hops = {path[-1] for path in advert["paths"] if path}
            if len(last_hops) < len(REPEATERS) or any(deltas[role]["flood_tx"] <= 0 for role in REPEATERS):
                raise ValueError("Forwarded samples must show paths and TX evidence from both repeaters")
        elif (advert["direct"] is not True or advert["paths"]
              or any(deltas[role]["flood_tx"] != 0 or deltas[role]["flood_rx"] <= 0
                     or deltas[role]["identity"] <= 0 for role in REPEATERS)):
            raise ValueError("The denied advert must show direct reception and identity drops on both repeaters")

    hashes = {}
    for role in REPEATERS:
        device = devices[role]
        if device.get("configured_firmware_git_sha", "").lower() != commit:
            raise ValueError(f"{role} report firmware commit differs from the selected candidate")
        digest = device.get("configured_firmware_sha256", "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{role} is missing a recorded firmware SHA-256")
        hashes[role] = digest
    return hashes


def package_candidate(actor_report, commit, images, output):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected the full lowercase candidate Git commit")
    if output.exists() or output.is_symlink():
        raise ValueError(f"Output path already exists: {output}")
    report_bytes = actor_report.read_bytes()
    report = json.loads(report_bytes)
    hashes = verify_actor_report(report, commit)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".alpha-candidate-", dir=output.parent) as temp:
        stage = Path(temp) / "candidate"
        stage.mkdir()
        firmware = []
        for role, name in REPEATERS.items():
            image = images[role]
            if not image.is_file() or not image.stat().st_size or image.suffix.lower() != Path(name).suffix:
                raise ValueError(f"{role} requires its tested {Path(name).suffix} application image")
            copy = stage / name
            shutil.copyfile(image, copy)
            if sha256(copy) != hashes[role]:
                raise ValueError(f"{role} image SHA-256 differs from the physical report")
            firmware.append(copy)
        evidence = stage / "alpha-evidence.json"
        evidence.write_text(json.dumps({
            "source_commit": commit,
            "actor_run_id": report["run_id"],
            "actor_report_sha256": hash_bytes(report_bytes).hexdigest(),
            "images": {role: {"filename": name, "sha256": hashes[role]} for role, name in REPEATERS.items()},
        }, indent=2) + "\n", encoding="utf-8")
        write_checksums(stage, [*firmware, evidence])
        stage.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor-report", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--r1-zip", type=Path, required=True)
    parser.add_argument("--r2-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        package_candidate(args.actor_report, args.commit, {"R1": args.r1_zip, "R2": args.r2_bin}, args.output)
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, f"Alpha packaging failed: {error}\n")
    print(f"Prepared local Alpha candidate at {args.output}")


if __name__ == "__main__":
    main()
