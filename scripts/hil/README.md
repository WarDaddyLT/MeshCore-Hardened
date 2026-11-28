# Four-device actor bench

The actor scenario checks whether two Hardened repeaters drop a banned device's signed advert while continuing to forward an ordinary, non-banned companion's advert. It uses the standard MeshCore Companion protocol on ADMIN and stock MeshCore USB Companion firmware on ACTOR. The run transmits five ordinary adverts and uses the repeaters' USB consoles to apply and remove two temporary local denies.

| Role | Device | Required firmware |
| --- | --- | --- |
| R1 | RAK 1W | MeshCore Hardened repeater with `rules device` |
| R2 | ThinkNode M5 | MeshCore Hardened repeater with `rules device` |
| ADMIN | Wio Tracker L1 Pro e-ink | USB-capable admin bench build of MeshCore Companion |
| ACTOR | Wio Tracker L1 OLED | Stock USB Companion protocol |

## Run from CLion

From the repository root in CLion's Terminal, with the four USB devices connected:

```sh
./scripts/hil/bench.sh list
./scripts/hil/bench.sh prepare
./scripts/hil/bench.sh run --isolated-rf
```

The first `prepare` installs the pinned dependency in `.venv/hil`, writes the four verified public-key pins to `hil_config.local.json`, and checks the bench. On another checkout, fill in the USB selectors in that local file first. Existing pins must match the attached devices. `run` repeats preflight before transmitting and writes its reports to `out/hil/actor.*`. Use `bench.sh preflight` for a read-only readiness check. Use `bench.sh build` to compile the installable RAK 1W and ThinkNode M5 images with PlatformIO. The build command only compiles, and firmware installation is a separate operation.

Use `./scripts/hil/bench.sh build-admin` to compile `.pio/build/WioTrackerL1Eink_hil_admin_usb/firmware.zip`. This test profile enables USB alongside BLE using the existing Companion code and board settings. Close any connected phone app before using the admin device on the USB bench. Record the image hash and source commit after authorized installation. Stock Android interoperability is verified separately with the stock app and firmware.

To run directly with a Python Run Configuration:

1. Install the requirements with `python -m pip install -r scripts/hil/requirements.txt`. Configure that Python interpreter in the CLion run configuration, or run the same commands in CLion's Terminal.
2. Use the repository root as the working directory and `scripts/hil/run.py` as the script. Run it with `--list` to see USB selectors.
3. Copy `hil_config.example.json` to `hil_config.local.json` in this directory. Fill in the stable selectors. On Linux, `"by_id": "/dev/serial/by-id/…"` can replace a serial number or location. Record the flashed artifact's source commit and SHA-256 as `firmware_git_sha` and `firmware_sha256` in each role. Run with `--identify` and pin the public keys in the local file after checking the devices.
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

## Repeatable USB setup

From CLion's Terminal, select the four connected ports in the local config and run:

```sh
./scripts/hil/bench.sh setup --observer /path/outside/the/repository/hardened-bench.txt
```

The command checks and pins the four USB identities, sets EU/UK (Narrow) and the `hardened` flood scope, enables repeater forwarding for that scope, disables periodic repeater adverts, and shares or reuses a private **Bench Private** channel on the companions. Set optional `display_name` in each role to choose its bench name. The observer file contains the private channel key and is restricted to its owner. Firmware installation is separate from setup.

Use `--anonymize` to renew the neutral display names on the four devices. Add `--private-only` to clear all other channels from the two bench companions. This choice is saved in the fixture. Suites that require Public traffic report SKIP with a private-only fixture.

The setup records the direct-adverts-only preference in the local fixture. Suites that require repeated signed adverts report SKIP under that preference. To send one ordinary scoped private ACTOR message for an observer, add `--check-channel --isolated-rf`. This checks the repeaters' TX counters and leaves the observer's inbox untouched.

To replace ACTOR, add `--actor-serial <USB-serial> --actor-name <existing-name>`. The runner checks that the replacement reports the selected name before it updates the fixture. After installing an exact image, add `--record-image ROLE COMMIT PATH` for each flashed role to record its source and SHA-256 in the local config.

## SaveMeshcore comparison setup

After installing the pinned SaveMeshcore builds on R1 and R2, keep the same four USB devices, known identity pins, and RF settings. Record the firmware provenance for the installed images in the local bench config. Run the baseline and Hardened checks with separate report paths so each report preserves the measured settings.

```sh
./scripts/hil/bench.sh preflight --baseline --report out/hil/savemeshcore-preflight
./scripts/hil/bench.sh preflight --report out/hil/hardened-preflight
```

Run the second command after restoring the Hardened bench images. Inspect both reports for matching radio and inherited filter settings before the RF comparison. Baseline preflight recognizes the control firmware's CLI profile. The report identifies the configured images by the hashes entered by the operator. Both commands require all four devices and perform no RF trials or flashing.

### Quiet delivery comparison

In the isolated setup, arrange the radios so the receiving companion hears the sender through R1 and R2 in sequence. The comparison uses the stock Public channel in slot 0 on both companions. Keep Public filtering off on both repeaters and use matching inherited filters and radio settings for both runs. Confirm the duty cycle for the configured radio settings and reserve the ACTOR inbox for the test before setting `test_only_inboxes` to true.

```sh
./scripts/hil/bench.sh run --suite quiet --baseline --isolated-rf --report out/hil/quiet-baseline
./scripts/hil/bench.sh run --suite quiet --baseline-report out/hil/quiet-baseline.json --isolated-rf --report out/hil/quiet-hardened
```

Install the baseline repeater images for the first run and the Hardened images for the second. Update each image's recorded hash and commit after installation. Each run sends 20 ordinary messages from ADMIN, at most one per minute. The runner counts a delivery when ACTOR reports the matching stock message with exactly two hops and both repeaters record a flood transmission. Latency covers send request to observed Companion inbox delivery, with a 15-second observation window. Direct reception counts as a missed routed delivery. The report applies the quiet acceptance thresholds from the implementation plan to the two matching profiles.

## What the scenario verifies

- Both repeaters forward ADMIN and ACTOR before the deny.
- During the deny, the observing companion still hears ACTOR's direct advert. Neither repeater transmits it, and both show an identity drop.
- Both repeaters continue to forward ADMIN while the deny is active.
- After cleanup, both repeaters forward ACTOR again.

Nearby receivers may hear a source directly. The runner requires a matching last-hop path prefix and transmit counter change to verify each repeater's forwarding. Poor RF visibility or unrelated traffic can make the result inconclusive. A BLE-only companion may expose a serial port while lacking the wired Companion protocol. A missing USB response leaves the run unverified.

`--smoke` is an alias for the actor scenario. Run `./scripts/hil/bench.sh run --suite filtering --isolated-rf` to check Public group-text forwarding, the Public filter drop counter, and unaffected signed ADMIN adverts. Both companions need their stock Public channel in slot 0 and both repeaters must start with Public filtering off. The scenario records RF routing evidence and leaves the companion app inbox alone.

Run `./scripts/hil/bench.sh run --suite security --isolated-rf` to check initial Protected probation, Locked admission, and ADMIN forwarding. ACTOR must start unenrolled and without an existing probation entry. Use a fresh bench configuration for this case and synchronize the radios' clocks. The test restores Normal and removes its temporary allow rules. Protected can retain ACTOR's probation record.

Run `./scripts/hil/bench.sh run --suite sync --isolated-rf` to verify signed subnet mode propagation and applied-policy confirmation. Both repeaters must already be onboarded into the same isolated test subnet, authenticated to each other, and on the same signed Normal revision. Both need R1's subnet publishing grant. The run publishes Protected on R1, checks the committed revision on R2, requests authenticated confirmation, and restores signed Normal on both.

Run `./scripts/hil/bench.sh run --suite acl --isolated-rf` to verify remote CLI access over stock MeshCore. Import both repeaters as contacts on both companions. Provision ADMIN as administrator and ACTOR as a read-only client on each repeater. Reserve both companion inboxes for test messages and set `"test_only_inboxes": true` in the local config because the runner consumes replies through the stock inbox protocol. The runner checks that ADMIN can set the already active Normal mode, ACTOR can read policy status but receives an explicit denial for the same command, and the policy revision stays fixed.

Run `./scripts/hil/bench.sh run --suite shared --isolated-rf` to verify a temporary shared deny, retained policy during an authenticated session outage, and deletion convergence after reconnect. Both repeaters need the same configured test policy domain and a live domain session. R2 needs R1's global publisher grant. Use an otherwise quiet bench with available rule slots. The suite disconnects policy sessions over USB and leaves physical RF partition testing to a separate case.

Run `./scripts/hil/bench.sh run --suite onboarding-manual --isolated-rf` to verify durable manual activation on R2. Use a dedicated bench with both repeaters in the same test subnet in Normal mode. Keep R1 active and put R2 into onboarding over USB with `rules onboarding start`. Review the intended R2 settings before running. The suite observes R1 forward a stock ADMIN advert while R2 receives it and holds transit. It then commits R2's reviewed policy and requires RF evidence that both repeaters forward a second advert. R2 remains active after the test. Run this suite separately because it needs R2 to start with transit held.

Run `./scripts/hil/bench.sh run --suite onboarding-peer --isolated-rf` with R1 as the snapshot provider and R2 pending. Follow the [peer onboarding provisioning steps](../../docs/hardened-repeater-cli.md#onboarding-from-a-peer), establish a fresh authenticated subnet session, and make sure R1 has published a signed Normal revision. Leave both repeaters' policies unchanged during the run. The runner requests a single snapshot, waits up to 51 minutes, compares R2's staged revision with R1's, and checks that R2 still holds transit until the reviewed policy is committed. It then verifies forwarding with an ordinary stock advert. R2 remains active after the test.

`./scripts/hil/bench.sh run --all --isolated-rf` runs the cases compatible with an already active bench and records outstanding release coverage as skipped. Run the onboarding suites separately. The remaining ACL and filter matrix, physical partition testing, Android and room identity, signed neighbour notices, and the baseline comparison remain release work.
