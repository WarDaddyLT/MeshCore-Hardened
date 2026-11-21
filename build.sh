#!/usr/bin/env bash

# exit when any command fails
set -e
set -o pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

global_usage() {
  cat - <<EOF
Usage:
sh build.sh <command> [target]

Commands:
  help|usage|-h|--help: Shows this message.
  list|-l: List firmwares available to build.
  build-firmware <target>: Build the firmware for the given build target.
  build-firmwares: Build all firmwares for all targets.
  build-matching-firmwares <build-match-spec>: Build all firmwares for build targets containing the string given for <build-match-spec>.
  build-companion-firmwares: Build all companion firmwares for all build targets.
  build-repeater-firmwares --version <version> [--target <target>]: Package SaveMeshcore's repeater targets.
  check-repeater-firmwares [--target <target>]: Compile repeater targets and report every result.
  get-repeater-firmwares-to-build: List the repeater targets without building.
  build-room-server-firmwares: Build all chat room server firmwares for all build targets.

Examples:
Build firmware for the "RAK_4631_repeater" device target
$ sh build.sh build-firmware RAK_4631_repeater

Build all firmwares for device targets containing the string "RAK_4631"
$ sh build.sh build-matching-firmwares <build-match-spec>

Build all companion firmwares
$ sh build.sh build-companion-firmwares

Build all repeater firmwares
$ bash build.sh build-repeater-firmwares --version v1.18.0-hardened

Build all chat room server firmwares
$ sh build.sh build-room-server-firmwares

Build all kiss radio firmwares
$ sh build.sh build-kiss-radio-firmwares

Environment Variables:
  DISABLE_DEBUG=1: Disables all debug logging flags (MESH_DEBUG, MESH_PACKET_LOGGING, etc.)
                   If not set, debug flags from variant platformio.ini files are used.

Examples:
Build without debug logging:
$ export FIRMWARE_VERSION=v1.0.0
$ export DISABLE_DEBUG=1
$ sh build.sh build-firmware RAK_4631_repeater

Build with debug logging (default, uses flags from variant files):
$ export FIRMWARE_VERSION=v1.0.0
$ sh build.sh build-firmware RAK_4631_repeater
EOF
}

# get a list of pio env names that start with "env:"
get_pio_envs() {
  printf '%s' "$PIO_CONFIG_JSON" | python3 -c '
import json
import sys
for section, _ in json.load(sys.stdin):
    if section.startswith("env:"):
        print(section[4:])
'
}

# Catch cries for help before doing anything else.
case ${1:-} in
  help|usage|-h|--help)
    global_usage
    exit 0
    ;;
  build-repeater-firmwares)
    shift
    exec python3 "$SCRIPT_DIR/scripts/build_repeaters.py" "$@"
    ;;
  check-repeater-firmwares)
    shift
    exec python3 "$SCRIPT_DIR/scripts/build_repeaters.py" --check "$@"
    ;;
esac

# cache project config json for use in get_platform_for_env()
PIO_CONFIG_JSON=$(pio project config --json-output)
FIRMWARE_OUTPUT_DIR=${FIRMWARE_OUTPUT_DIR:-out}

# $1 should be the string to find (case insensitive)
get_pio_envs_containing_string() {
  shopt -s nocasematch
  envs=($(get_pio_envs))
  for env in "${envs[@]}"; do
      if [[ "$env" == *${1}* ]]; then
        echo $env
      fi
  done
}

# $1 should be the string to find (case insensitive)
get_pio_envs_ending_with_string() {
  shopt -s nocasematch
  envs=($(get_pio_envs))
  for env in "${envs[@]}"; do
    if [[ "$env" == *${1} ]]; then
      echo $env
    fi
  done
}

# get platform flag for a given environment
# $1 should be the environment name
get_platform_for_env() {
  printf '%s' "$PIO_CONFIG_JSON" | python3 -c '
import sys, json, re
data = json.load(sys.stdin)
for section, options in data:
    if section == "env:" + sys.argv[1]:
        options = dict(options)
        for flag in options.get("build_flags", []):
            match = re.search(r"(ESP32_PLATFORM|NRF52_PLATFORM|STM32_PLATFORM|RP2040_PLATFORM)", flag)
            if match:
                platform = match.group(1)
                if platform == "NRF52_PLATFORM" and options.get("upload_protocol") == "jlink":
                    platform = "NRF52_UF2_ONLY"
                print(platform)
                sys.exit(0)
sys.exit(f"Unsupported or unknown PlatformIO environment: {sys.argv[1]}")
' "$1"
}

# disable all debug logging flags if DISABLE_DEBUG=1 is set
disable_debug_flags() {
  if [ "$DISABLE_DEBUG" == "1" ]; then
    export PLATFORMIO_BUILD_FLAGS="${PLATFORMIO_BUILD_FLAGS} -UMESH_DEBUG -UBLE_DEBUG_LOGGING -UWIFI_DEBUG_LOGGING -UBRIDGE_DEBUG -UGPS_NMEA_DEBUG -UCORE_DEBUG_LEVEL -UESPNOW_DEBUG_LOGGING -UDEBUG_RP2040_WIRE -UDEBUG_RP2040_SPI -UDEBUG_RP2040_CORE -UDEBUG_RP2040_PORT -URADIOLIB_DEBUG_SPI -UCFG_DEBUG -URADIOLIB_DEBUG_BASIC -URADIOLIB_DEBUG_PROTOCOL"
  fi
}

# build firmware for the provided pio env in $1
build_firmware() (
  ENV_PLATFORM=$(get_platform_for_env "$1")
  build_dir="${PLATFORMIO_BUILD_DIR:-.pio/build}/$1"

  # get git commit sha
  COMMIT_HASH=${FIRMWARE_BUILD_REVISION:-$(git rev-parse --short HEAD)}

  # set firmware build date
  FIRMWARE_BUILD_DATE=${FIRMWARE_BUILD_DATE:-$(date '+%d-%b-%Y')}

  # get FIRMWARE_VERSION, which should be provided by the environment
  if [ -z "$FIRMWARE_VERSION" ]; then
    echo "FIRMWARE_VERSION must be set in environment"
    exit 1
  fi

  # set firmware version string
  # e.g: v1.0.0-abcdef
  FIRMWARE_VERSION_STRING="${FIRMWARE_VERSION}-${COMMIT_HASH}"

  # craft filename
  # e.g: RAK_4631_Repeater-v1.0.0-SHA
  FIRMWARE_FILENAME="$1-${FIRMWARE_VERSION_STRING}"

  # add firmware version info to end of existing platformio build flags in environment vars
  export PLATFORMIO_BUILD_FLAGS="${PLATFORMIO_BUILD_FLAGS} -DFIRMWARE_BUILD_DATE='\"${FIRMWARE_BUILD_DATE}\"' -DFIRMWARE_VERSION='\"${FIRMWARE_VERSION_STRING}\"'"

  # disable debug flags if requested
  disable_debug_flags

  # build firmware target
  pio run -e "$1"

  artifact() {
    if [[ ! -s "$build_dir/firmware$1" ]]; then
      printf 'Missing firmware artifact: %s\n' "$build_dir/firmware$1" >&2
      return 1
    fi
    cp "$build_dir/firmware$1" "$FIRMWARE_OUTPUT_DIR/$FIRMWARE_FILENAME$1"
  }

  # build merge-bin for esp32 fresh install, copy .bins to out folder (e.g: Heltec_v3_room_server-v1.0.0-SHA.bin)
  if [ "$ENV_PLATFORM" == "ESP32_PLATFORM" ]; then
    pio run -t mergebin -e "$1"
    artifact .bin
    artifact -merged.bin
  fi

  # build .uf2 for nrf52 boards, copy .uf2 and .zip to out folder (e.g: RAK_4631_Repeater-v1.0.0-SHA.uf2)
  if [[ "$ENV_PLATFORM" == "NRF52_PLATFORM" || "$ENV_PLATFORM" == "NRF52_UF2_ONLY" ]]; then
    python3 bin/uf2conv/uf2conv.py "$build_dir/firmware.hex" -c -o "$build_dir/firmware.uf2" -f 0xADA52840
    artifact .uf2
    if [[ "$ENV_PLATFORM" == "NRF52_PLATFORM" ]]; then
      artifact .zip
    fi
  fi

  # for stm32, copy .bin and .hex to out folder
  if [ "$ENV_PLATFORM" == "STM32_PLATFORM" ]; then
    artifact .bin
    artifact .hex
  fi

  # for rp2040, copy .bin and .uf2 to out folder
  if [ "$ENV_PLATFORM" == "RP2040_PLATFORM" ]; then
    artifact .bin
    artifact .uf2
  fi

)

# firmwares containing $1 will be built
build_all_firmwares_matching() {
  envs=($(get_pio_envs_containing_string "$1"))
  for env in "${envs[@]}"; do
      build_firmware $env
  done
}

# firmwares ending with $1 will be built
build_all_firmwares_by_suffix() {
  envs=($(get_pio_envs_ending_with_string "$1"))
  for env in "${envs[@]}"; do
    build_firmware $env
  done
}

build_repeater_firmwares() {

#  # build specific repeater firmwares
#  build_firmware "Heltec_v2_repeater"
#  build_firmware "Heltec_v3_repeater"
#  build_firmware "Xiao_C3_Repeater_sx1262"
#  build_firmware "Xiao_S3_WIO_Repeater"
#  build_firmware "LilyGo_T3S3_sx1262_Repeater"
#  build_firmware "RAK_4631_Repeater"

  # build all repeater firmwares
  build_all_firmwares_by_suffix "_repeater"

}

build_companion_firmwares() {

#  # build specific companion firmwares
#  build_firmware "Heltec_v2_companion_radio_usb"
#  build_firmware "Heltec_v2_companion_radio_ble"
#  build_firmware "Heltec_v3_companion_radio_usb"
#  build_firmware "Heltec_v3_companion_radio_ble"
#  build_firmware "Xiao_S3_WIO_companion_radio_ble"
#  build_firmware "LilyGo_T3S3_sx1262_companion_radio_usb"
#  build_firmware "LilyGo_T3S3_sx1262_companion_radio_ble"
#  build_firmware "RAK_4631_companion_radio_usb"
#  build_firmware "RAK_4631_companion_radio_ble"
#  build_firmware "t1000e_companion_radio_ble"

  # build all companion firmwares
  build_all_firmwares_by_suffix "_companion_radio_usb"
  build_all_firmwares_by_suffix "_companion_radio_ble"

}

build_room_server_firmwares() {

#  # build specific room server firmwares
#  build_firmware "Heltec_v3_room_server"
#  build_firmware "RAK_4631_room_server"

  # build all room server firmwares
  build_all_firmwares_by_suffix "_room_server"

}

build_kiss_modem_firmwares() {

#  # build specific kiss radio firmwares
#  build_firmware "Heltec_v3_kiss_modem"
#  build_firmware "RAK_4631_kiss_modem"

  # build all room server firmwares
  build_all_firmwares_by_suffix "_kiss_modem"

}

build_firmwares() {
  build_companion_firmwares
  build_repeater_firmwares
  build_room_server_firmwares
}

# Listing targets must not create or modify firmware artifacts.
case ${1:-} in
  list|-l)
    get_pio_envs
    exit 0
    ;;
  get-companion-firmwares-to-build)
    get_pio_envs_ending_with_string "_companion_radio_usb"
    get_pio_envs_ending_with_string "_companion_radio_ble"
    exit 0
    ;;
  get-repeater-firmwares-to-build)
    get_pio_envs_ending_with_string "_repeater"
    exit 0
    ;;
  get-room-server-firmwares-to-build)
    get_pio_envs_ending_with_string "_room_server"
    exit 0
    ;;
esac

mkdir -p "$FIRMWARE_OUTPUT_DIR"

# handle script args
if [[ $1 == "build-firmware" ]]; then
  shift
  if [ "$#" -gt 0 ]; then
    for env in "$@"; do
      build_firmware "$env"
    done
  else
    echo "usage: $0 build-firmware <target>"
    exit 1
  fi
elif [[ $1 == "build-matching-firmwares" ]]; then
  if [ "$2" ]; then
     build_all_firmwares_matching $2
  else
     echo "usage: $0 build-matching-firmwares <build-match-spec>"
    exit 1
  fi
elif [[ $1 == "build-firmwares" ]]; then
  build_firmwares
elif [[ $1 == "build-companion-firmwares" ]]; then
  build_companion_firmwares
elif [[ $1 == "build-room-server-firmwares" ]]; then
  build_room_server_firmwares
elif [[ $1 == "build-kiss-radio-firmwares" ]]; then
  build_kiss_modem_firmwares
fi
