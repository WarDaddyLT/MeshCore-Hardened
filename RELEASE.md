# Release repeater firmware

## First Alpha candidate

The [Alpha release issue](https://github.com/WarDaddyLT/MeshCore-Hardened/issues/29) records the required physical validation. Before creating a GitHub Alpha release, record the firmware Git commit and SHA-256 of both installed repeater images in the local bench configuration, complete the four-device validation, and link the passing evidence from the issue.

Prepare the local bundle from the saved RAK 1W application DFU ZIP and ThinkNode M5 application BIN for the verified candidate.

```sh
python3 scripts/package_alpha_candidate.py \
  --actor-report out/hil/actor.json --commit "$FIRMWARE_COMMIT" \
  --r1-zip /path/to/tested/RAK_3401_repeater.zip \
  --r2-bin /path/to/tested/ThinkNode_M5_Repeater.bin \
  --output out/repeaters/alpha-candidate
```

Use the standalone `--suite actor` report from the isolated bench. The output contains both images, `SHA256SUMS.txt`, and an evidence manifest linking the exact images to the test run. Keep the original report with the release evidence. The GitHub release gate also requires the remaining acceptance results in the release issue. The local command produces no GitHub draft or tag.

## GitHub release

Push a release tag such as `repeater-v1.18.0-hardened` or `repeater-v1.18.0-hardened.1` from a commit that contains the release workflow. For an existing tag, run **MeshCore Hardened repeater release** from the Actions tab and enter the tag.

GitHub Actions builds the repeater matrix from that tagged commit. After all jobs succeed, it verifies the artifacts and uploads them with `SHA256SUMS.txt` to a **draft GitHub release**. Review the draft and publish it from the Releases tab.

The full build uses the SaveMeshcore release selector. It selects PlatformIO environments whose names end in `_repeater`, ignoring case. The imported configuration matches all 97 targets published in [SaveMeshcore v1.18.0-savemesh.1](https://github.com/aigarslv/SaveMeshcore/releases/tag/repeater-v1.18.0-savemesh.1).

## Local tooling

To inspect the list locally, install PlatformIO and make `pio` available on PATH.

```sh
bash build.sh build-repeater-firmwares --list
```

To check all repeater builds locally, run the following command. It continues after a failed build, saves one log per target and a `summary.txt` under `out/repeater-check/`, and exits with status 1 if any target fails. Repeat `--target` to check a subset or use `--output` to choose a new log directory.

```sh
bash build.sh check-repeater-firmwares
```

The workflow uses `build-repeater-firmwares` with `--version` and `--target` to package each board. For an individual development package, use `--output` to choose a new output directory.

```sh
bash build.sh build-repeater-firmwares --version v1.18.0-hardened \
  --target RAK_3401_repeater --target Heltec_v3_repeater \
  --output out/repeaters/local-check
```

Local outputs default to `out/repeaters/<version>/`. The script finalizes the output directory after every selected target produces its expected files and refuses to overwrite an existing directory. Filenames include the short Git revision and a `-dirty` suffix when the checkout has local changes.

| Platform | Artifacts |
| --- | --- |
| ESP32 | Application BIN and merged BIN |
| nRF52 | UF2 and DFU ZIP |
| Wio WM1110 | UF2 |
| RP2040 and RP2350 | BIN and UF2 |
| STM32 | BIN and HEX |

The merged ESP32 BIN includes the bootloader and partition table for a fresh install. Use the application BIN for a matching existing partition layout.
