# Implementation plan

Build and flash development firmware as each feature lands. Formal native and four-device hardware testing follow feature implementation.

| Phase | Status | Scope |
| --- | --- | --- |
| Source baseline | VERIFIED | Pinned [SaveMeshcore snapshot](source-baseline.md) in the independent MeshCore Hardened repository. |
| First development build | VERIFIED | `pio run -e RAK_3401_repeater` produced `.pio/build/RAK_3401_repeater/firmware.zip` for the WisCore RAK3401. Flash usage was 413,232 bytes and static RAM usage was 35,652 bytes. |
| Rule store and CLI | TODO | Add persistent allow, deny and filter rules with stable IDs, pagination and exact-ID deletion through the existing repeater CLI. |
| Packet policy | TODO | Apply rules at forwarding gates using verified identities and preserve stock traffic policy for unattributable traffic. |
| Direct-neighbour notifications | TODO | Notify authorized operators about authenticated direct observations. |
| Policy synchronization | TODO | Distribute signed revisions and deletion records to authorized peers. |
| Optional room identity | TODO | Add the secondary identity and verify stock Android behavior before enabling room-based administration. |
| Formal validation and release | TODO | Run native and four-device hardware suites, measure resource use and prepare release artifacts. |
