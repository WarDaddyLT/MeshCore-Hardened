"""Verify and combine the repeater packages downloaded from GitHub Actions."""

import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile

from build_repeaters import CHECKSUMS, sha256, write_checksums


def collect(targets, artifacts, destination):
    if not targets or len(targets) != len(set(targets)):
        raise ValueError("Expected a nonempty list of unique repeater targets")
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Output path already exists: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".repeater-release-", dir=destination.parent) as temp:
        stage = Path(temp) / "firmware"
        stage.mkdir()
        for target in sorted(targets):
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", target):
                raise ValueError(f"Invalid repeater target: {target!r}")
            package = artifacts / f"repeater-{target}"
            listed = set()
            for line in (package / CHECKSUMS).read_text(encoding="utf-8").splitlines():
                checksum, separator, name = line.partition("  ")
                if (not separator or not re.fullmatch(r"[0-9a-f]{64}", checksum)
                        or not name.startswith(target + "-") or Path(name).name != name
                        or name in listed):
                    raise ValueError(f"Invalid checksum entry for {target}: {line!r}")
                source = package / name
                if not source.is_file() or not source.stat().st_size or sha256(source) != checksum:
                    raise ValueError(f"Missing, empty or invalid artifact: {source}")
                output = stage / name
                if output.exists():
                    raise ValueError(f"Duplicate release artifact: {name}")
                shutil.copyfile(source, output)
                listed.add(name)
            if not listed or listed != {p.name for p in package.iterdir()} - {CHECKSUMS}:
                raise ValueError(f"Artifact inventory does not match the checksums for {target}")

        files = list(stage.iterdir())
        write_checksums(stage, files)
        stage.rename(destination)
    print(f"Verified {len(files)} firmware files across {len(targets)} targets")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", required=True, help="JSON list of expected environments")
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        targets = json.loads(args.targets)
        if not isinstance(targets, list) or not all(isinstance(target, str) for target in targets):
            raise ValueError("Targets must be a JSON list of strings")
        collect(targets, args.artifacts, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Release collection failed: {error}\n")


if __name__ == "__main__":
    main()
