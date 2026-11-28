# Implementation plan

Build and flash development firmware as each feature lands. Formal native and four-device hardware testing follow feature implementation.

| Phase | Status | Scope |
| --- | --- | --- |
| Source baseline | VERIFIED | Pinned [SaveMeshcore snapshot](source-baseline.md) in the independent MeshCore Hardened repository. |
| RAK3401 development build | VERIFIED | `pio run -e RAK_3401_repeater` produced `.pio/build/RAK_3401_repeater/firmware.zip` with all firmware features below. Flash usage is 439,968 bytes (54.0%) and static RAM usage is 48,716 bytes (20.7%). |
| Rule store and CLI | VERIFIED (build) | Persistent allow, deny and filter rules, stable IDs, pagination, durable deletion records and existing repeater CLI role checks. |
| Packet policy | VERIFIED (build) | Verified-identity enforcement, existing packet filters, type and category forwarding limits, and aggregate drop counters. |
| Normal and legacy mode migration | IN PROGRESS (RF validation pending) | Normal preserves the stock forwarding and enrollment paths. Saved open settings read as Normal and saved restrictions remain active. |
| RF forwarding airtime and queue limits | IN PROGRESS (RF validation pending) | Separate RF airtime budgets and outstanding queue limits by category, reserved packet buffers for local service, and per-category admission counters. The controlled comparison against the pinned baseline is pending. |
| Bounded receive work | IN PROGRESS (RF validation pending) | Early frame and duplicate checks, bounded verification and delayed queues, and volatile diagnostics instead of a persistent packet log. CPU, queue and airtime measurements under controlled RF load are pending. |
| Device trust and activity | IN PROGRESS (RF validation pending) | Persistent full-key trust rules, denies across advertised roles, and bounded recent advert counts and quotas in RAM. Legacy traffic still uses category controls. |
| Protected mode | IN PROGRESS (RF validation pending) | Drops unattributable transit, keeps authenticated management available, and applies a bounded 72-hour probation to fresh verified RF keys. |
| Locked mode and enrollment freeze | IN PROGRESS (RF validation pending) | Fresh allowlisted transit, persistent independent freeze, conservative expiry, and local operator recovery. |
| Direct-neighbour notifications | VERIFIED (build) | Private-channel notices for verified zero-hop observations, with a bounded deduplication table and send interval. |
| Policy synchronization | VERIFIED (build) | Signed, encrypted global and regional updates between provisioned repeaters, including deletion records and explicit reconciliation. |
| Scoped publishing authority and subnet membership | IN PROGRESS (RF validation pending) | Independent named subnet settings and scoped publisher grants. Durable USB retirement removes accepted rules for a compromised origin in that scope. |
| Authenticated policy peers | IN PROGRESS (RF validation pending) | Fresh signed proofs establish directional session keys. Accepted policy requires both an authenticated peer and the original authorized publisher's signature. |
| Managed onboarding hold | IN PROGRESS (RF validation pending) | New subnet assignments durably hold radio and bridge transit. Local administration and authenticated setup remain available. A verified initial policy commit is required to release the hold. |
| Subnet mode propagation | IN PROGRESS (RF validation pending) | Signed mode changes fit one control payload and stay within the configured subnet. A member retains its committed revision across reboot and partitions. Local restrictions can keep its effective mode stricter. |
| Applied-policy confirmation | IN PROGRESS (RF validation pending) | On-demand authenticated subnet status distinguishes a recent matching reply from stale and unknown peers. Re-established sessions queue current policy and eligible deletion checkpoints. |
| Manual onboarding | IN PROGRESS (RF validation pending) | An authorized administrator can review and commit local starting policy while transit remains held. Activation requires a durable commit of the reviewed revision. |
| Peer onboarding | IN PROGRESS (RF validation pending) | An authenticated peer can supply a signed, scoped snapshot in bounded blocks. Verified staging preserves the forwarding hold. |
| Verified onboarding activation | IN PROGRESS (RF validation pending) | Both paths use revision-bound review and durable activation. Peer-supplied provenance survives reboot and its authority is checked again before forwarding opens. |
| Optional room identity | VERIFIED (build) | Separate persistent room identity, signed contact export, and a read-only room adapter. It defaults off pending stock Android validation. |
| RAK3401 development flash | VERIFIED | USB DFU completed. The repeater returned in application mode and responded to `rules status` with revision 0, open mode, and capacity for 24 records. |
| Formal validation and release | TODO | Validate native behavior, the four-device RF matrix, and stock Android interoperability in the formal validation phase. |

Run the host regression suite from the repository root.

```sh
pio test -e native -e native_kiss_modem -e native_savemesh -e native_savemesh_prefs -e native_hardened
```

The five native environments passed 83 tests on the alpha development branch. The hardened suite exercises the production rule store, peer session, receive checks, probation ledger, and airtime budgets with real Ed25519 and SHA-256 and a fault-injecting filesystem. Physical LoRa and Android behavior remain separate release checks.

The firmware CLI and the development limits are documented in the [repeater CLI guide](hardened-repeater-cli.md).

### Blacklist RF bench

The RAK3401 detected the enrolled ThinkNode M5 from a signed zero-hop advert. The M5 ran the official MeshCore USB companion v1.18.0 build. Captures matched the RAK3401's hop hash for the M5's signed flood advert before adding a deny rule and after deleting it. With the deny rule active, the RAK3401 recorded one identity drop and zero flood transmissions for the advert trial.

The RAK3401 forwarded private group text before, during, and after the deny. The captures matched the temporary channel and the RAK3401's hop hash. Legacy group text carries no cryptographically verifiable sender identity for a transit repeater.

The T-Echo Lite Kit accepted official firmware updates over DFU but did not answer companion queries over USB. The RAK3401's USB console applied and removed the test rules, so the T-Echo remote admin flow remains pending. Cleanup restored the repeater's previous forwarding and notification settings, cleared the temporary M5 channel, and left no active test rules. The two test deletion records remain in the rule store.

## First-alpha bench builds

The SaveMeshcore builds use the [pinned source snapshot](source-baseline.md) from import commit `0bf5d85388fb98bd0b392301776786b56c31079b`. The Hardened bench images use commit `dc484101231878845eed0806d668f47c96b8c703`. The source changes between that commit and the merged peer-onboarding test affect test tooling only.

Run `pio run -e RAK_3401_repeater -e ThinkNode_M5_Repeater` from each source tree. The RAK 1W artifact is the RAK3401 DFU application ZIP. The ThinkNode M5 artifact is the ESP32-S3 application binary.

| Bench role and PlatformIO target | Build | Static RAM used | Application flash used |
| --- | --- | ---: | ---: |
| R1 RAK 1W, `RAK_3401_repeater` | SaveMeshcore | 35,652 / 235,520 bytes | 413,232 / 815,104 bytes |
| R1 RAK 1W, `RAK_3401_repeater` | Hardened | 66,636 / 235,520 bytes | 493,312 / 815,104 bytes |
| R2 ThinkNode M5, `ThinkNode_M5_Repeater` | SaveMeshcore | 63,672 / 524,288 bytes | 1,132,821 / 1,310,720 bytes |
| R2 ThinkNode M5, `ThinkNode_M5_Repeater` | Hardened | 94,584 / 524,288 bytes | 1,190,277 / 1,310,720 bytes |

PlatformIO reports 80,080 additional flash bytes and 30,984 additional static RAM bytes on the RAK 1W, and 57,456 additional flash bytes and 30,912 additional static RAM bytes on the ThinkNode M5. The RAM figures are linker estimates. Runtime headroom, forwarding CPU cost and airtime, clean installs, upgrades, and rollback remain pending on the four-device bench.

| Build and artifact | SHA-256 for the bench copy |
| --- | --- |
| SaveMeshcore R1 `firmware.zip` | `fddb0069f3b76d391a923252d6072c3df803493ec835dd1769ab349fa5119a46` |
| SaveMeshcore R2 `firmware.bin` | `359bb8766f106ee8a37e9c9b46f12cbe778440bb04b6c3a142af0ca05c323b49` |
| Hardened R1 `firmware.zip` | `4730e2b642e49606aa9b33b0062b3331b86af23245d886b23dc20e2de78c595d` |
| Hardened R2 `firmware.bin` | `a2b1508b8c675256b137b13506e52a3ba969aef46bae993ef9f94582ab7fb0fc` |
| Wio Tracker L1 Pro e-ink USB ADMIN bench `firmware.zip` | `51d8fcd159b013d7ad1d7e6400e82b1c28dcc5170c8288bab1c4dbed8a0c74e3` |
| T-Echo Lite Kit stock USB ACTOR v1.17.1 DFU ZIP | `10a103acc7af77664473876e5a082390c5ff87af0e1066c7e55d727eed32d099` |

These checksums identify the local artifacts. Record the exact artifacts installed on each device in the [four-device bench configuration](../scripts/hil/README.md) and confirm the resulting identity and firmware over USB. The e-ink ADMIN image has built successfully and still needs installation and USB confirmation. Stock Android interoperability and the physical bad-actor scenarios are release gates.

## Forwarding and identity audit

| Current receive or transmit path | Identity evidence and alpha treatment |
| --- | --- |
| Direct RF transit, including TRACE and multipart ACKs | A path selects a next hop. It does not identify the source or relay. Direct packets reach the repeater policy hook before duplicate checks on several branches. In Normal, keep the stock routing behavior with packet and category controls. Protected and Locked require verified attribution for ordinary transit, including any control frame eligible for forwarding. |
| Flood and transport-scoped flood | Region, hop, loop, and duplicate checks constrain the route. Stock group text and group data carry channel data but no verifiable sender. A stock anonymous request carries a claimed key whose authentication is checkable at its destination. Normal uses packet, region, recognized-channel, and class controls for this transit traffic. Protected and Locked drop unattributable traffic. |
| Client and repeater advertisements | The flood handler verifies the signature before invoking the advert callback. The direct forwarding hook currently verifies only in cases where a key decision would otherwise block the advert. Protected and Locked must verify each admitted advert, with separate freshness evidence before crediting probation. An advert does not authenticate later group messages or establish the most recent RF hop. |
| Primary local service and optional admin room | Authenticated local management uses a full key selected through the MeshCore shared-secret exchange, with current ACL checks. The local room is read-only. Keep bounded USB recovery and authenticated management available independent of forwarding mode. Replies still use the radio budget. |
| Bridge input and output | Bridge input enters the delayed receive queue, and bridge output can be selected from RX or TX logging hooks. Treat both as policy boundaries. A bridge connection or injected packet provides no additional proof of the stock packet's original sender. |
| Locally created packets and policy control | Signed self-adverts, discovery, replies, notices, and sync can enter the dispatcher without going through the ordinary forwarding hook. Apply the budget for their own category and the same radio constraints. Verify authenticated control peers and the policy issuer separately. |

Audit references include [core routing](../src/Mesh.cpp), [radio dispatch](../src/Dispatcher.cpp), [repeater policy](../examples/simple_repeater/MyMesh.cpp), [RS232 bridging](../src/helpers/bridges/RS232Bridge.cpp), and [ESP-NOW bridging](../src/helpers/bridges/ESPNowBridge.cpp). The mode behavior above is the implementation target.

## Policy precedence and recovery

1. Parse the frame and apply the route's structure, path, scope, loop, and duplicate checks before expensive decisions where routing semantics permit. Keep inherited filters in force.
2. Attribute a source only when the frame or authenticated management exchange supports it. A matching deny takes precedence over an allowlist or probation. Apply the active mode to remaining traffic. Normal can admit stock legacy traffic. Protected requires attribution and can admit probationary keys. Locked needs a verified allowlisted key.
3. Charge approved traffic to a category budget and, where attributable, the corresponding per-key budget. The radio scheduler still applies the configured airtime and queue limits. Aggregate counters report the drop reason.
4. Keep local restrictions local. A subnet mode change requires an authorized issuer and authenticated policy propagation. Keep subnet and region scope independent. A local restriction can further limit the effective policy without weakening an active subnet restriction. A reboot or partition retains the last valid committed policy and marks unconfirmed peers stale or unknown. An interrupted first-time setup keeps managed forwarding disabled.
5. Use trustworthy elapsed time for probation and temporary restrictions. An unreliable clock cannot advance probation or silently relax a restriction. Resume time-based changes once the clock can support them. Keep authorized USB recovery available.

## RF acceptance thresholds

Use these initial thresholds for the controlled alpha bench. Confirm the packet size, transmission interval, legal airtime, and RF isolation in preflight for each board and preset. Record at least 20 intended stock-client deliveries per profile and run both an idle and a loaded scenario with the same radio configuration and inherited filters on SaveMeshcore and Hardened. Run a separate isolated category-limit scenario with the data filter off on both builds. Verify the forwarding route through path or repeater counter evidence.

| Profile | Pass threshold |
| --- | --- |
| Quiet Normal | At least 95% stock-client delivery. The 95th-percentile delivery time is at most the baseline value plus the greater of two seconds or 20%. |
| Normal under controlled load in a different category | At least 90% delivery for the legitimate messages, with 95th-percentile delivered-message latency at most 15 seconds. Record attacker-category forwarding airtime against the configured cap and confirm dispatcher limits. |
| Separate unaffected subnet | Meets the quiet Normal thresholds while the other subnet changes mode or experiences controlled abuse. |
| Protected and Locked | Zero forwarded frames from the disallowed test classes or attributable banned keys. Verify intended stock exclusions, allowed attributable traffic, and unchanged policy on the unaffected subnet. |
| Recovery and onboarding | Zero managed forwards before either onboarding path commits. Validate the applied revision and return to quiet Normal thresholds after restoring Normal and clearing the controlled load. |

Record every attempted legitimate send in the delivery-rate denominator. Report latency for delivered messages. A same-class legacy spam test measures total class containment and documents any stock-message loss separately because the repeater has no verifiable sender to prioritize within that class.
