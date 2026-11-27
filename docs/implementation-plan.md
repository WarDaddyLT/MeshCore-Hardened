# Implementation plan

Build and flash development firmware as each feature lands. Formal native and four-device hardware testing follow feature implementation.

| Phase | Status | Scope |
| --- | --- | --- |
| Source baseline | VERIFIED | Pinned [SaveMeshcore snapshot](source-baseline.md) in the independent MeshCore Hardened repository. |
| RAK3401 development build | VERIFIED | `pio run -e RAK_3401_repeater` produced `.pio/build/RAK_3401_repeater/firmware.zip` with all firmware features below. Flash usage is 439,968 bytes (54.0%) and static RAM usage is 48,716 bytes (20.7%). |
| Rule store and CLI | VERIFIED (build) | Persistent allow, deny and filter rules, stable IDs, pagination, durable deletion records and existing repeater CLI role checks. |
| Packet policy | VERIFIED (build) | Verified-identity enforcement, existing packet filters, open and restricted modes, a shared forwarding budget for unattributed group and anonymous traffic, and aggregate drop counters. |
| Direct-neighbour notifications | VERIFIED (build) | Private-channel notices for verified zero-hop observations, with a bounded deduplication table and send interval. |
| Policy synchronization | VERIFIED (build) | Signed, encrypted global and regional updates between provisioned repeaters, including deletion records and explicit reconciliation. |
| Optional room identity | VERIFIED (build) | Separate persistent room identity, signed contact export, and a read-only room adapter. It defaults off pending stock Android validation. |
| RAK3401 development flash | VERIFIED | USB DFU completed. The repeater returned in application mode and responded to `rules status` with revision 0, open mode, and capacity for 24 records. |
| Formal validation and release | TODO | Validate native behavior, the four-device RF matrix, and stock Android interoperability in the formal validation phase. |

The firmware CLI and the development limits are documented in the [repeater CLI guide](hardened-repeater-cli.md).

### Blacklist RF bench

The RAK3401 detected the enrolled ThinkNode M5 from a signed zero-hop advert. The M5 ran the official MeshCore USB companion v1.18.0 build. Captures matched the RAK3401's hop hash for the M5's signed flood advert before adding a deny rule and after deleting it. With the deny rule active, the RAK3401 recorded one identity drop and zero flood transmissions for the advert trial.

The RAK3401 forwarded private group text before, during, and after the deny. The captures matched the temporary channel and the RAK3401's hop hash. Legacy group text carries no cryptographically verifiable sender identity for a transit repeater.

The T-Echo Lite Kit accepted official firmware updates over DFU but did not answer companion queries over USB. The RAK3401's USB console applied and removed the test rules, so the T-Echo remote admin flow remains pending. Cleanup restored the repeater's previous forwarding and notification settings, cleared the temporary M5 channel, and left no active test rules. The two test deletion records remain in the rule store.

## First-alpha baseline build

The imported baseline commit `0bf5d85388fb98bd0b392301776786b56c31079b` contains the [pinned SaveMeshcore source](source-baseline.md). Building an isolated export of that commit with `pio run -e RAK_3401_repeater` produced a DFU ZIP with SHA-256 `d647d0be4b79c10b9dccd07f77ec0d40f88f7c6023cfb5fd93285b5063925178`. PlatformIO reported 413,232 bytes of flash and 35,652 bytes of static RAM. No MeshCore USB ports were present at inventory, so R2, the two stock companions, and RF evidence are pending.
