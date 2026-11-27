# Four-device actor bench

The actor scenario checks whether two Hardened repeaters drop a banned device's signed advert while continuing to forward an ordinary, non-banned companion's advert. ADMIN and ACTOR both use stock MeshCore Companion firmware. The run transmits five ordinary adverts and uses the repeaters' USB consoles to apply and remove two temporary local denies.

| Role | Device | Required firmware |
| --- | --- | --- |
| R1 | RAK 1W | MeshCore Hardened repeater with `rules device` |
| R2 | ThinkNode M5 | MeshCore Hardened repeater with `rules device` |
| ADMIN | Wio Tracker e-ink | Stock MeshCore Companion with working USB Companion protocol |
| ACTOR | T-Echo Lite Kit | Stock MeshCore USB Companion |

## Run from CLion

From the repository root in CLion's Terminal, with the four USB devices connected:

```sh
./scripts/hil/bench.sh list
./scripts/hil/bench.sh prepare
./scripts/hil/bench.sh run --isolated-rf
```

The first `prepare` installs the pinned dependency in `.venv/hil`, writes the four verified public-key pins to `hil_config.local.json`, and checks the bench. On another checkout, fill in the USB selectors in that local file first. Existing pins must match the attached devices. `run` repeats preflight before transmitting and writes its reports to `out/hil/actor.*`. Use `bench.sh preflight` for a read-only readiness check. Use `bench.sh build` to compile the installable RAK 1W and ThinkNode M5 images with PlatformIO. The build command only compiles, and firmware installation is a separate operation.

To run directly with a Python Run Configuration:

1. Install the requirements with `python -m pip install -r scripts/hil/requirements.txt`. Configure that Python interpreter in the CLion run configuration, or run the same commands in CLion's Terminal.
2. Use the repository root as the working directory and `scripts/hil/run.py` as the script. Run it with `--list` to see USB selectors.
3. Copy `hil_config.example.json` to `hil_config.local.json` in this directory. Fill in the stable selectors. On Linux, `"by_id": "/dev/serial/by-id/…"` can replace a serial number or location. You may record a known artifact's source commit as `firmware_git_sha` in each role. Run with `--identify` and pin the public keys in the local file after checking the devices.
4. Configure the same legal frequency, bandwidth, spreading factor and coding rate on all four devices. Keep both repeaters in Normal with an empty transmit queue and one free rule slot each. For this scenario, either use an accepted bench region on all devices or use an isolated setup that allows the unscoped adverts from both companions. Disable companion repeating and close serial monitors and apps that hold any bench port.
5. Run with `--preflight`. Match the report's settings with your isolated RF setup.
6. Run with `--suite actor --isolated-rf --report out/hil/actor`. Use an RF enclosure or controlled attenuation so the four radios can hear the intended test paths without sending adverts to a public mesh. The flag confirms isolation, legal settings and authorization to add and remove the temporary denies.

Equivalent commands for CLion's Terminal:

```sh
python scripts/hil/run.py --list
python scripts/hil/run.py --identify
python scripts/hil/run.py --preflight
python scripts/hil/run.py --suite actor --isolated-rf --report out/hil/actor
```

The runner writes JSON, JUnit XML and Markdown reports. The JSON includes both repeaters' forwarding counters and path evidence from the observing Companion. It fingerprints the enrolled bench identities and omits passwords, private keys and private channel secrets. If temporary rule cleanup fails, the report lists the exact rule IDs to inspect and remove. A successfully deleted rule can leave a tombstone in current firmware.

## What the scenario verifies

- Both repeaters forward ADMIN and ACTOR before the deny.
- During the deny, the observing companion still hears ACTOR's direct advert. Neither repeater transmits it, and both show an identity drop.
- Both repeaters continue to forward ADMIN while the deny is active.
- After cleanup, both repeaters forward ACTOR again.

Nearby receivers may hear a source directly. The runner requires a matching last-hop path prefix and transmit counter change to verify each repeater's forwarding. Poor RF visibility or unrelated traffic can make the result inconclusive. A BLE-only companion may expose a serial port while lacking the wired Companion protocol. A missing USB response leaves the run unverified.

`--smoke` is an alias for the actor scenario. This first scenario covers attributable blacklist forwarding in Normal. Full ACL, filtering, security, sync, identity, and Protected/Locked RF coverage are still pending. The runner sends no malformed or synthetic RF frames and never flashes a device.
