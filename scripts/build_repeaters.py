"""Build and package the SaveMeshcore repeater target set."""

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BUILD = ["bash", str(ROOT / "build.sh")]
CHECKSUMS = "SHA256SUMS.txt"


def repeater_targets():
    output = subprocess.check_output(
        [*BUILD, "get-repeater-firmwares-to-build"], cwd=ROOT, text=True
    )
    targets = sorted(output.splitlines())
    if not targets:
        raise ValueError("PlatformIO reported no repeater targets")
    return targets


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_checksums(directory, files):
    with (directory / CHECKSUMS).open("w", encoding="utf-8") as checksums:
        for path in sorted(files):
            checksums.write(f"{sha256(path)}  {path.name}\n")


def check_builds(targets, destination):
    destination.mkdir(parents=True)
    print(f"Build logs: {destination}", flush=True)

    passed = 0
    summary = destination / "summary.txt"
    with summary.open("w", encoding="utf-8") as report:
        for index, target in enumerate(targets, start=1):
            print(f"[{index}/{len(targets)}] Building {target}", flush=True)
            log_path = destination / f"{target}.log"
            with log_path.open("w", encoding="utf-8") as log:
                result = subprocess.run(
                    ["pio", "run", "-e", target], cwd=ROOT,
                    stdout=log, stderr=subprocess.STDOUT,
                )
            success = result.returncode == 0
            passed += success
            line = f'{"PASS" if success else "FAIL"} {target} ({log_path.name})'
            print(line, flush=True)
            print(line, file=report, flush=True)

        totals = f"{passed} passed, {len(targets) - passed} failed"
        print(totals, file=report)
    print(f"{totals}. Summary: {summary}")
    return 0 if passed == len(targets) else 1


def build_package(targets, version, destination):
    build_dir = ROOT / ".pio" / "repeater-release-build"
    build_dir.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with (build_dir.parent / "repeater-package.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"Output path already exists: {destination}")

        revision = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True
        ).strip()
        changes = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
        if changes:
            revision += "-dirty"

        with tempfile.TemporaryDirectory(prefix=".repeater-build-", dir=destination.parent) as temp:
            stage = Path(temp) / "firmware"
            env = dict(
                os.environ,
                FIRMWARE_OUTPUT_DIR=str(stage),
                FIRMWARE_VERSION=version,
                FIRMWARE_BUILD_REVISION=revision,
                FIRMWARE_BUILD_DATE=os.getenv(
                    "FIRMWARE_BUILD_DATE", datetime.now(timezone.utc).date().isoformat()
                ),
                PLATFORMIO_BUILD_DIR=str(build_dir),
            )
            print(f"Building {len(targets)} repeater targets for {version}-{revision}", flush=True)
            subprocess.run([*BUILD, "build-firmware", *targets], cwd=ROOT, env=env, check=True)

            files = sorted(stage.iterdir())
            missing = [
                target for target in targets
                if not any(path.name.startswith(f"{target}-{version}-{revision}.")
                           for path in files)
            ]
            if missing:
                raise ValueError("Missing firmware for " + ", ".join(missing))
            write_checksums(stage, files)
            stage.rename(destination)
    print(f"Packaged {len(files)} firmware files in {destination}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list target names and exit")
    parser.add_argument("--check", action="store_true",
                        help="compile each selected target and log pass/fail without packaging")
    parser.add_argument("--target", action="append", metavar="ENV",
                        help="build this target instead of the full list; repeat as needed")
    parser.add_argument("--version", default=os.getenv("FIRMWARE_VERSION"),
                        help="firmware version; defaults to FIRMWARE_VERSION")
    parser.add_argument("--output", type=Path,
                        help="new directory for firmware packages or build check logs")
    args = parser.parse_args()

    try:
        targets = repeater_targets()
        if args.list:
            print(*targets, sep="\n")
            return
        if args.target:
            unknown = sorted(set(args.target) - set(targets))
            if unknown:
                parser.error("unknown repeater targets: " + ", ".join(unknown))
            targets = sorted(set(args.target))

        if args.check:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            destination = args.output or ROOT / "out" / "repeater-check" / stamp
            return check_builds(targets, destination.absolute())

        if not args.version or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", args.version):
            parser.error("provide a version such as v1.18.0-hardened using --version or FIRMWARE_VERSION")
        destination = args.output or ROOT / "out" / "repeaters" / args.version
        build_package(targets, args.version, destination.absolute())
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Repeater build command failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
