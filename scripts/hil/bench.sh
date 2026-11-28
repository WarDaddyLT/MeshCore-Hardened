#!/usr/bin/env sh
set -eu

bench_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$bench_dir/../.." && pwd)
cd "$repo_dir"

action=${1:-help}
if [ "$#" -gt 0 ]; then shift; fi

case "$action" in
    help|-h|--help)
        cat <<'HELP'
Usage: scripts/hil/bench.sh <build|build-admin|prepare|setup|list|preflight|run> [runner options]
  build      Compile the RAK 1W and ThinkNode M5 repeater images.
  build-admin Compile the USB-capable Wio Tracker e-ink admin bench image.
  prepare    Install test dependencies, pin the four USB keys, and check preflight.
  setup      Provision the named, scoped USB fixture and private channel.
  list       List USB devices.
  preflight  Check the pinned USB identities and settings without transmitting.
  run        Run the actor scenario by default. Accepts --suite or --all.
HELP
        exit 0
        ;;
    build)
        if [ "$#" -ne 0 ]; then
            printf '%s\n' "The build action takes no arguments." >&2
            exit 2
        fi
        "${MESHCORE_HIL_PIO:-pio}" run -e RAK_3401_repeater -e ThinkNode_M5_Repeater
        printf '%s\n' \
            ".pio/build/RAK_3401_repeater/firmware.zip" \
            ".pio/build/ThinkNode_M5_Repeater/firmware.bin"
        exit 0
        ;;
    build-admin)
        if [ "$#" -ne 0 ]; then
            printf '%s\n' "The build-admin action takes no arguments." >&2
            exit 2
        fi
        "${MESHCORE_HIL_PIO:-pio}" run -e WioTrackerL1Eink_hil_admin_usb
        printf '%s\n' ".pio/build/WioTrackerL1Eink_hil_admin_usb/firmware.zip"
        exit 0
        ;;
    prepare|setup|list|preflight|run) ;;
    *) printf '%s\n' "Unknown bench action: $action" >&2; exit 2 ;;
esac

venv="${MESHCORE_HIL_VENV:-$repo_dir/.venv/hil}"
bench_python="$venv/bin/python"
if [ ! -x "$bench_python" ]; then
    "${MESHCORE_HIL_PYTHON:-python3}" -m venv "$venv"
fi
if ! "$bench_python" -c 'import serial; assert serial.VERSION == "3.5"' 2>/dev/null; then
    "$bench_python" -m pip install --disable-pip-version-check -r "$bench_dir/requirements.txt"
fi

case "$action" in
    prepare)
        if [ "$#" -eq 0 ] && [ ! -e "$bench_dir/hil_config.local.json" ]; then
            (umask 077; cp "$bench_dir/hil_config.example.json" "$bench_dir/hil_config.local.json")
            printf '%s\n' "Created scripts/hil/hil_config.local.json. Fill in the four USB selectors from the list action, then run prepare again."
            exit 2
        fi
        exec "$bench_python" "$bench_dir/run.py" --pin "$@"
        ;;
    setup) exec "$bench_python" "$bench_dir/setup_bench.py" "$@" ;;
    list) exec "$bench_python" "$bench_dir/run.py" --list "$@" ;;
    preflight) exec "$bench_python" "$bench_dir/run.py" --preflight "$@" ;;
    run)
        for option in "$@"; do
            case "$option" in --suite|--suite=*|--all)
                exec "$bench_python" "$bench_dir/run.py" "$@" ;;
            esac
        done
        exec "$bench_python" "$bench_dir/run.py" --suite actor "$@"
        ;;
esac
