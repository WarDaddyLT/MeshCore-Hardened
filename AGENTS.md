# AGENTS.md — MeshCore Hardened Firmware

> Instructions for Codex and other repository coding agents. This file is normative for this repository. Read it completely before changing code. Implement against the checked-out code and the current upstream protocol, not assumptions from earlier discussions.

## 0. Mission and operating constraints

Build **MeshCore Hardened**, a standalone public repository containing **repeater firmware** that retains normal MeshCore interoperability while adding controlled forwarding, persistent administrator-managed rules, an optional private virtual room-server identity, event-driven **direct-neighbour** discovery, and compact signed policy synchronization between managed repeaters.

**Hard requirements**

1. **The official MeshCore Android application and ordinary companion firmware must work unmodified** for repeater configuration, contact import, room interaction, private channels and existing messaging. Do not depend on a proprietary app, new mobile UI, online backend, cloud identity provider or continuously available controller.
2. One physical device, one LoRa radio, one primary public **repeater** identity, and optionally one secondary, separate **room-server** identity for authorized administration. The public identity remains a normal MeshCore repeater. The secondary identity is not a routing node.
3. The repeater stores **active settings/rules and minimal convergence metadata only**. Do not implement persistent chat logs, message history, per-packet archives, client movement histories, or daily event databases.
4. Every active administrative rule has a unique persistent ID; an authorized admin can list rules and **delete a particular rule by ID**. Deletion must survive reboot and must not be undone by delayed synchronization.
5. Direct-neighbour notifications are **event-driven**, only after an authenticated, direct/zero-hop observation. Do not mistake packets forwarded by another node for a new direct neighbour. No recurring network-wide presence broadcast.
6. Preserve existing SaveMeshcore-style repeater packet filters and safety bounds, as listed in Section 3, throughout feature development.
7. Access control, room commands, rule sync and administrative execution must be authenticated. An ordinary MeshCore private **channel key is not administrator authorization**. A sender name in a group message is not a cryptographic identity.
8. Flash footprint, RAM use, LoRa airtime, duty-cycle limitations and source compatibility must remain first-class requirements. Default to static/bounded allocation and no packet-path heap allocation.
9. Build, unit-test and flash targets must be explicitly identified from the real PlatformIO configuration and actual hardware; never guess board environments or erase a device without authorization.
10. Do not claim a security property or stock-app compatibility until an automated or documented manual test demonstrates it. Unsupported functionality is a documented limitation, not a simulated success.

## 1. Repository bootstrap and provenance

The project **starts from a source snapshot/check-out of `https://github.com/aigarslv/SaveMeshcore`**, but the resulting GitHub repository must be independently created and **must not be a GitHub fork**, must not inherit Git commit history, and must not retain the original repository as a Git remote, submodule, or automated merge dependency.

Bootstrap procedure when the new repository has not already been initialized:

1. Obtain the source tree at a pinned commit or release; record its content hash and source version in an **internal development note** (e.g. `docs/source-baseline.md`) so changes are reproducible. Do not present a modified snapshot as independently authored from scratch.
2. Copy the source tree **without `.git/`**, and initialize a new `git init` repository. Use a new initial commit authored in the new project. Create a new public GitHub repository normally, not via GitHub's Fork action.
3. Remove or replace inherited **project branding**, original repository badges, original repository-specific auto-merge jobs, remote URLs, CI publish destinations and release pipelines. Ensure all new branch protection, release and publishing paths belong to this repository.
4. **Preserve all legally required copyright notices, license texts and third-party attribution.** MeshCore upstream is MIT-licensed; inspect the actual SaveMeshcore snapshot and every bundled dependency for any additional obligations before publishing. Independence of Git history is **not** absence of software provenance and cannot justify stripping required notices.
5. Do not automatically merge from SaveMeshcore. If upstream tracking is desired, track **official stable MeshCore repeater releases** through a controlled, reviewed import process with preserved legal notices; do not silently track its development branch.
6. Clean inherited branding from the user-facing CLI banner and docs, without changing protocol-defined identifiers or mandatory notices. Document source imports in a reproducible manner.
7. Never rewrite an existing public repository history or push to a remote without explicit authorization from its owner.

**Do not assume the source website can be reached in an agent sandbox.** If network access is unavailable, work with the checked-out snapshot, identify its exact revision when possible, and report any unverified license/compatibility issues as release blockers.

## 2. Scope and non-goals

**In scope**: repeater firmware, repeater-only CLI, on-device policy store, virtual admin identity/room adapter, incoming packet policy hooks, signed rule distribution, direct-neighbour change detection, stock-client interoperability tests, host unit tests, hardware-in-loop tests, build/release scripts and docs.

**Out of scope**: new Android/iOS app, modifications required in standard companion firmware, dedicated desktop admin tool, internet server, arbitrary message storage, continuous fleet telemetry, real-time tracking, secret backdoors, stealth interception, decryption of unrelated users' private traffic, and blanket blocking claims for senders not cryptographically attributable from a packet.

**Important limitation**: Stock companions do **not** add a new authentication extension to all outgoing packet types. A repeater cannot reliably enforce a per-public-key allow/deny list against every legacy encrypted group message, anonymous request or malformed frame. Implement identity-based decisions **only when the packet source is cryptographically verifiable**; otherwise enforce type/channel/region/rate policies and report the limitation. Do not silently reinterpret an unauthenticated nickname, sender_id or channel MAC as proof of a client's key.

A managed repeater controls **its own forwarding and services**, not all RF transmissions and not unmanaged repeaters elsewhere in the mesh. It cannot prevent external radios from transmitting or jamming the channel.

## 3. Preserve the source filter baseline

Use the initial source snapshot as the reference for actual behavior. The expected SaveMeshcore-style baseline is:

- `filter 1byte on|off`: default **off**; when on, reject forwarding of already-traversed 1-byte path-hash floods; do not reject zero-hop floods, direct traffic or 2-/3-byte path-hash floods solely under this rule.
- `filter data on|off`: default **on** only when no saved setting exists; when on, reject forwarding payload types `0x06` (`GRP_DATA`), `0x0C`–`0x0E` (reserved unsigned types), `0x0F` (`RAW_CUSTOM`). Preserve a previously saved `off` after reboot/update.
- `filter public on|off`: default **off**; reject default Public-channel `GRP_TXT` and `GRP_DATA` when enabled. Match the known Public channel's 2-byte MAC after checking its hash byte (`0x11`) rather than dropping all channels with hash `0x11`. This is channel recognition, **not user authentication**.
- `filter` with no arguments returns compact status of all three filters; existing `filter <name>` readback works unchanged.
- `path.hash.mode`: only `1` or `2`; auto-correct saved `0` to `1` at boot; reject an invalid CLI value without modifying a valid saved value.
- `multi.acks`: always `1`.
- `loop.detect`: `minimal|moderate|strict`; saved `off` becomes `minimal`.
- `advert.interval`: always `0` for periodic zero-hop self-advertisement.
- `flood.advert.interval`: `0` or `47..168` hours; persisted enabled values below `47` become `47` before radio/advert timers start.
- Existing setting persistence, reboot repair and command handling must not regress.

Keep these filter rules separate from the new administrative allow/deny rules. Do not change these defaults without a versioned migration and explicit user approval. Review the actual code if the snapshot differs from this specification; document and resolve differences instead of assuming which version is correct.

## 4. Architecture

Prefer small modules with stable interfaces **inside the repeater build**. Adapt to the actual tree instead of introducing unnecessary abstraction:

```text
examples/simple_repeater/         # primary integration, command registration, packet hooks
src/managed/                      # use only if it truly reduces integration churn
  ManagedIdentity.*               # primary + optional secondary keypair
  ManagedAccess.*                 # authn/authz against verified identities
  RuleStore.*                     # persistent active rules + revision/tombstones
  PacketPolicy.*                  # filtering against observable/verified fields
  AdminRoom.*                     # standard room protocol adapter, not chat archive
  NeighbourTracker.*              # authenticated zero-hop discovery/dedup
  PolicySync.*                    # bounded signed rule propagation
  ManagedStorage.*                # atomic flash persistence and migration
  ManagedDiagnostics.*            # minimal counters, no raw payload logs

tests/managed/                    # deterministic host/unit tests
scripts/hil/                      # 4-USB-device radio hardware test harness
docs/                             # protocol, CLI, threat model, HIL guide
```

Don't change core routing, crypto, packet formats or non-repeater firmware when an isolated repeater adapter suffices. If a core patch is unavoidable, document its motivation, the minimal API, interoperability implications and tests. Follow upstream style: no unnecessary heap allocations in packet paths and no broad reformatting.

**Packet decision order**, applied to *all real forwarding paths*:

1. Frame structure and subtype validity.
2. Existing loop/duplicate/path/region checks.
3. SaveMeshcore packet filters.
4. Identity attribution, **only where verifiable**.
5. Explicit blacklist > whitelist > unknown-device policy (for attributable identities).
6. Bounded per-source/per-class rate limiting where possible; unknown traffic has shared limits, not a forged per-key bucket.
7. Hardware duty-cycle and forwarding constraints.
8. Forward or drop, with an aggregated reason counter.

Avoid bypasses through alternate flood/direct pathways, bridge interfaces, locally originated packets, admin-room handling or restart paths. Authorized admin/control traffic still obeys legal airtime limits.

## 5. Dual identity on one physical repeater

**Primary identity A**: ordinary MeshCore repeater, its current stable keypair, normal public advert `0x02`, normal routing, existing management CLI. Do not rotate or overwrite the existing repeater private key during firmware upgrade.

**Secondary identity B**: separately generated persistent keypair, room-server advert type `0x03`, default display name `<repeater name> Admin`, authorized administrative access only, no ordinary routing participation, no periodic advertising, no extra radio, no duplicate forwarding.

Both identities share one rule store, one radio, one administration policy and storage quota. Never export a private key. Do not assume existing MeshCore internally supports two simultaneous local identities: audit packet targeting, encryption/session dispatch, signatures, contact discovery, reply routing, message handlers and key persistence. Explicitly handle identity B only for room-server operations.

**Official Android app is a release gate.** A proof of concept must establish that an unmodified official MeshCore Android client can:

- add the secondary identity as a standard room contact;
- open/read its room and send standard room-compatible messages;
- receive messages from that identity over normal multi-hop routing;
- perform authorized operations, while unauthorized users cannot;
- continue using the primary identity as a normal repeater.

If the app or protocol prevents a critical behavior, **do not fake a room UI**. Record a compatibility blocker and keep the existing remote CLI as the fully functional management path. Guard the secondary identity behind an explicit feature flag until HIL/manual Android proof passes.

### Secondary advertisement retrieval

Add stable repeater CLI commands:

```text
get admin.enabled
set admin.enabled on|off
get admin.name
set admin.name <short-name>
get admin.pubkey
get admin.advert
get admin.advert <part-index>    # only if response exceeds transport limit
admin.advert once                # OPTIONAL, authenticated on-demand RF advert
```

`get admin.advert` must export the **actual native, signed MeshCore room-server contact advertisement**, ideally as a standard importable `meshcore://` URI **if that URI is supported by the target stock-app version**. Use the upstream encoder and exact key/flags/name bytes. CLI response size varies by transport: detect actual buffer limits, offer deterministic indexed chunks with `transfer_id`, `part_index`, `part_count`, integrity digest and expiry, and make reconstruction possible without a custom app. Prefer a native single-frame protocol method when available. No periodic secondary advert; optional on-demand RF advert only on an authenticated explicit command, respecting airtime.

Contact discovery is not an access credential. Even if identity B's public advert leaks, only authorized identities can read its state or change policy. If standard room-server transport does not securely authenticate the sender for administrative writes, prohibit writes through the room and use authenticated primary-repeater remote CLI instead.

## 6. Admin room is a current-state interface, not a message server

A room read/list operation returns **only currently active rules and essential status**. Admin commands are processed then discarded. The firmware retains no admin message history, no room chat log and no user message archive. The stock phone app may show historical messages cached locally; do not claim firmware can delete them.

Supported read/write concept, adapted to the real native room protocol:

```text
rules count
rules list [cursor]
rules show <full-id-or-unambiguous-prefix>
rules add allow client <full-public-key> [scope]
rules add deny client <full-public-key> [scope]
rules add allow repeater <full-public-key> [scope]
rules add deny repeater <full-public-key> [scope]
rules add filter public on|off [scope]
rules add filter 1byte on|off [scope]
rules add filter data on|off [scope]
rules delete <instruction-id>
rules status
```

**Do not break existing `filter ...`, `get ...`, `set ...`, `setperm ...` or other official CLI commands.** The above are proposed new commands, not claims that upstream already supports them. Ensure CLI responses are brief, predictable and paginated to fit remote transport limits. Never enumerate sensitive ACL details to guests.

Read-only admin roles may list; rule mutations require appropriate write/admin authority. Preserve established management credentials and supported public-key ACLs. Provide recovery from the physically connected USB serial console without introducing remote bypasses or a universal default password.

## 7. Rule model and persistence

Maintain a bounded, versioned, atomically persisted table:

```text
rule_id             128-bit random, generated once
revision            monotonic policy revision or comparable signed version
issuer_key          full verified admin public key
scope               LOCAL | REGION:<id> | GLOBAL:<domain>
kind                ALLOW | DENY | FILTER
subject_kind        CLIENT | REPEATER | PACKET_FILTER
subject_key         full 32-byte key, or known filter enum
value               boolean/enum where required
signature           issuer's verified signature or verifiable signed update reference
```

`rule_id` is the identity of **that instruction**, not a 4-byte sender fingerprint or a fixed incrementing counter. Display a short prefix only if unique among current and deletion entries; accept the full ID when ambiguous. Assign deterministic meaning to duplicate/incompatible rules: deny wins over allow for the same subject; more-specific local policies should not be silently overridden by ambiguous global policies; version the precedence algorithm. Never accept unverified signatures or out-of-scope administrator authority.

Deletion:

- `rules delete <id>` creates a signed, monotonic deletion/revocation event. The active entry disappears immediately after durable commit.
- Keep the **minimum bounded tombstone/version state** needed to prevent old peer copies from resurrecting the rule; this is not message history. A policy snapshot/epoch mechanism may replace long-lived tombstones if rigorously proven.
- Deletes are idempotent, reboot-safe, and synchronized according to the rule's scope. An unknown or ambiguous ID must not delete another entry.
- Handle power loss between record write and commit. Never report success before durable storage has been validated.
- Do not write flash for each RF packet, repeated neighbour reception or ordinary non-admin message. Debounce/aggregate noncritical state and wear-level the journal.

Implement storage capacity detection per target; measure real partitions and OTA slots. Offer a conservative minimal profile for boards with little free flash, and optional larger profiles where external flash exists. Fail safely on store full/corruption; preserve admin access and explicit recovery. Do not overwrite the existing MeshCore config filesystem or keys.

## 8. Authentication, trust and misbehaving devices

Reuse real MeshCore identities and existing verified administrative access wherever supported. Do **not** create a parallel client identity that the official app cannot use. Separate:

- **Identity**: a verified full MeshCore public key, never merely a displayed name/hash;
- **Authorization**: admin ACL or active allow/deny rule;
- **Packet filtering**: observable type, public-channel verification, region, path and limited traffic budget;
- **Misbehavior**: evidence-based rate control or deliberate administrator ban.

Explicit blacklist takes precedence over whitelist for verified identities. An unknown-device policy can be `open|restricted` for verifiable identity-bearing traffic; it must not pretend to enforce per-client allowlisting of legacy anonymous/group traffic. Device-to-repeater direct observation does not grant authorization.

**Never automatically permanently ban a key because an attacker supplied that key in an unsigned payload.** Forged sender labels, invalid signatures, replay attempts, random malformed frames and unauthenticated packet floods can produce local **anonymous-source/shared rate limiting** and counters, not a permanent ban of the claimed public key. Permanent ban requires an authenticated key and an administrator decision, or a separately reviewed evidence-based policy that does not permit spoof-induced victim bans. Tests must try to provoke false attribution.

For manageable authenticated admin operations and sync, prefer standard, well-reviewed Ed25519 signatures, complete canonical signing bytes, domain separation, bounded nonces and anti-replay. Do not invent short HMAC packet authentication until compatible clients can produce it and its threat model has been reviewed. Never claim that an 8-byte MAC exists on legacy packets.

## 9. Direct-neighbour discovery and private notifications

Report *only newly learned direct neighbours*:

- A **verified direct repeater**: signed identity-bearing observation (e.g., an advert) plus confirmed zero-hop/direct reception in the actual radio/path metadata.
- A **verified direct client**: a verified, identifiable direct observation, limited to clients enrolled in the managed domain. Ordinary legacy packet types may not expose enough information to make this determination.
- A routed advert, reconstructed multi-hop message, unverified nickname, string in a payload, or weak SNR alone is **not** proof of direct identity.

Maintain a small bounded deduplication table of full identities, type, last-seen/coarse freshness information, and whether the discovery notification has been sent. Emit at most one new-neighbour event per newly observed identity per local configured observation epoch. Support a deliberate reset/expiry policy; do not repeatedly announce devices merely because they move or send packets. Do not collect precise movement histories. No 'device left coverage' events in MVP.

Notifications use an ordinary **private MeshCore group channel** that stock Android can read, using a randomly provisioned secret key and preferably a narrow region scope. Use brief, human-readable messages so no app modification is needed. A shared channel secret provides confidentiality for group content, **not authenticated sender authority**; never execute instructions found in group chat. Device events should include a short key fingerprint and type, while full keys remain available via authenticated query if authorized.

Use an explicit bounded outbound queue, event coalescing, a strict message/airtime budget, and region/local preference. Global administrative channel is for sparse notifications, not a constantly updated live map. No telemetry broadcasts for each packet and no unauthenticated client-sighting announcements.

## 10. Signed managed-repeater synchronization

Two managed repeaters can synchronize **active rules, deletion markers and monotonic revisions** when they can communicate. No central server and no repeaters required to be simultaneously online. Transfers use the existing MeshCore transport when possible; every privileged policy operation is **signed by an authorized issuer** and independently verified by receiving peers.

- Scope limits must be applied; LOCAL never propagates by default.
- Synchronization is event-driven or explicit on admin command; add cautious periodic reconciliation only if measured necessary and within a defined airtime budget.
- Deduplicate by full rule ID and revision; reject replay, rollback, conflicting unauthorised rules, stale snapshots and malformed/cross-domain updates.
- Never trust a repeater merely because it relayed a policy update; validate the originating signature and administrator permissions.
- Reconnect after partitions without reviving deleted rules. Simulate reboots and power loss.
- A repeater with stale policies must expose its current revision; do not claim instant global revocation in a partitioned network.
- If policy sync would exceed airtime budget, prefer resumable bounded chunks and reconciliation over flood retries.

## 11. Four-device USB/RF test bench for release validation

Provide **automated hardware-in-loop (HIL) testing using exactly four real MeshCore devices**, each separately connected to a **USB serial port** on one test computer. USB is for control/logging; **real LoRa radio links** are used for traffic and routing tests. Do not substitute four virtual serial ports or mock packets and report the outcome as hardware validation.

| Role | Label | Firmware | Purpose |
|---|---|---|---|
| 1 | `R1` | MeshCore Hardened repeater | Primary policy target, primary+secondary identities |
| 2 | `R2` | MeshCore Hardened repeater | Forwarding peer, neighbour and policy-sync target |
| 3 | `ADMIN` | Stock MeshCore companion | Authorized administrator, whitelisted client, private-channel receiver |
| 4 | `ACTOR` | Stock MeshCore companion initially | Unknown/blacklisted client and controlled bad-actor traffic source |

For negative malformed packet and cryptographic spoofing tests, ACTOR may be temporarily flashed with **separate lab-only traffic-generator firmware**. Always restore the stock companion baseline afterwards and record the flashed image hashes. Do not modify the production companion firmware as a product requirement.

The script must enumerate `/dev/serial/by-id/*` first (or corresponding stable ports on other OS), identify each actual board/firmware/version/public key, and map them through a user-owned `hil_config.local.json` excluded from Git. Never assume `/dev/ttyACM0` is consistently the same physical device. Protect against swapping R1/R2/ADMIN/ACTOR. Never print private keys, administrator passwords or private channel secrets into reports or CI logs.

### Test runner and artifacts

Create `scripts/hil/run.py` with `--list`, `--preflight`, `--smoke`, `--suite filtering`, `--suite acl`, `--suite security`, `--suite sync`, `--suite identity`, `--all`, and `--report <path>`. `--flash` must be separate and explicitly approved, never implied by `--all`. Actual argument names can vary slightly if documented, but coverage must match.

Preflight must confirm: four ports present; expected device roles; per-device identity; compatible firmware; same configured RF parameters; synchronized clocks if necessary; test keys provisioned; administrative authorization; legal test frequency/power/duty cycle; safe isolated test setup. Prefer attenuators/shielded enclosures or other controlled RF setup to prevent accidental interaction with the public mesh. Never run uncontrolled transmissions or malicious load against non-test devices. Hardware tests must be reproducible and rate-limited.

Reports: machine-readable JUnit/JSON + human-readable Markdown with run ID, timestamp, firmware git SHA, board IDs, radio parameters (no secrets), test-case name, observed TX/RX/drop evidence, policy version before/after, PASS/FAIL/SKIP, clear reason for SKIP. **If four devices are unavailable, hardware tests must report SKIP/NOT RUN, never PASS.** Run host unit tests during the formal validation phase.

RF topology caution: with four nearby devices, `ADMIN` or `ACTOR` may hear both R1 and R2 directly. Use attenuation/shielding or independently observed repeater TX counters/instrumentation to prove forwarding; a mere received packet at a nearby radio does not prove R2 repeated it. Record path and/or TX evidence. Keep actual RF airtime low and avoid creating new flooding loops.

### Required test matrix

**A — Baseline / stock interoperability**

- A01: All four USB devices identified, expected unique keys, stable serial mapping.
- A02: R1 and R2 normal repeater advertisements remain visible to stock clients; ordinary direct/private routed messaging works.
- A03: Existing official remote CLI and `filter` commands work from ADMIN without changing the Android app or companion firmware.
- A04: Persist all original SaveMeshcore filters and corrected safety settings across reboot; invalid ranges rejected.
- A05: USB CLI, remote CLI, unknown command and oversized-response handling do not crash.

**B — Whitelist / blacklist / authorization**

- B01: ADMIN authenticated as administrator on R1 and R2; unauthorized ACTOR denied management writes.
- B02: Add `allow client ADMIN`; verify persistent unique instruction ID, list and correct access decision for *verifiably identified* packets.
- B03: Add `deny client ACTOR`; verify rejection of ACTOR's attributable traffic/services and no effect on ADMIN's allowed traffic.
- B04: `deny` overrides `allow` for same full public key; no 32-bit fingerprint collision authority.
- B05: Add `allow repeater R2`; verify relevant authenticated peer interactions.
- B06: Add `deny repeater R2` in an isolated test; verify defined peer/forwarding policy and no arbitrary radio outage; restore after test.
- B07: Rules remain after reboot; delete by *exact* instruction ID and verify only that rule disappears.
- B08: Reissue delete: idempotent; invalid/ambiguous ID fails safely; malformed rules fail atomically.
- B09: Deny by purported nick, spoofed key label or unauthenticated packet does **not** ban innocent ADMIN.
- B10: Legacy group/anonymous traffic whose sender cannot be established follows documented packet-class policy; no false 'identity block success'.

**C — Packet filters and bad actor**

- C01: `filter 1byte on` drops already-hopped 1-byte path-hash floods; preserves direct/zero-hop and appropriate 2-/3-byte hash traffic.
- C02: `filter data on` blocks forwarding `GRP_DATA`, reserved unsigned `0x0C..0x0E`, and `RAW_CUSTOM` as specified; `off` restores normal handling subject to other rules.
- C03: `filter public on` blocks verified default Public-channel group traffic, not every different channel sharing hash byte `0x11`.
- C04: All `filter ...` status/get replies correct and settings persist; defaults correct on clean storage.
- C05: ACTOR generates **bounded, legal-rate** repeated packets; rate-limit without long-term per-key ban if identity unverified; ADMIN remains usable.
- C06: Malformed packets, fake names, invalid signatures, replayed commands, contradictory rules and unauthorized deletions fail safely without crashes.
- C07: Logging/drop counters classify causes without storing raw private messages.

**D — Dual identity / admin room**

- D01: R1 primary public key and repeater advert unchanged after upgrade and restart.
- D02: R1 secondary room public key distinct, persistent, emits room-server advert type, and never periodically advertises.
- D03: Authenticated `get admin.advert` returns native signed importable representation; long responses are complete, paginated and integrity-checked if necessary.
- D04: Stock Android app **manual** contact import/open/read/send with room identity works; if not, report explicit blocker and disable room release flag.
- D05: ADMIN can list active rules through room; ACTOR cannot read or modify protected state.
- D06: Admin `add`/`delete` via room changes only current rule state; old admin messages are **not stored on repeater**.
- D07: No duplicate normal repeater adverts, no routing via B identity, no extra autonomous chatter.
- D08: Existing primary remote CLI remains full fallback if stock room-server UI cannot deliver a feature.

**E — Direct neighbour notification**

- E01: On first valid, direct, identity-bearing R2 advert, R1 emits at most one new-direct-repeater notice.
- E02: Repeated direct adverts do not produce duplicate notices.
- E03: R1 hearing a **routed** R2 advert via another hop does not report R2 as direct.
- E04: An enrolled directly observed client can trigger one notice only when verified; unverified ordinary clients must not trigger identifiable global sightings.
- E05: Notifications are readable on the stock private-channel UI; channel messages cannot execute admin commands.
- E06: No public key or sender name from a malicious payload is accepted as a verified neighbour.

**F — Policy synchronization / storage**

- F01: Authorized GLOBAL policy created on R1 reaches R2 and is independently signature-validated.
- F02: LOCAL policy does not silently propagate; REGION policy obeys configured scope.
- F03: A deletion on R1 removes the corresponding active R2 rule after sync.
- F04: Deliberately partition R2, delete a rule on R1, reconnect; stale R2 state must **not resurrect** it.
- F05: Repeated/replayed/forged/cross-domain sync traffic is rejected and not re-flooded.
- F06: Reboot and simulated interrupted storage write do not corrupt keys or elevate ACL.
- F07: Stress bounded rule count/storage full; reject new changes cleanly and preserve last valid policy.
- F08: Measure RAM/flash, CPU impact, serialized bytes, airtime and power where instrumentation permits; report against baseline.

**G — Safety / regression**

- G01: An unrestricted official companion can still communicate through managed repeaters in OPEN/FILTERED mode, subject to documented filters.
- G02: In RESTRICTED mode, attributable unauthorized traffic is dropped without false claims about unattributable encrypted group traffic.
- G03: Packet loops and ACK/path handling do not regress.
- G04: Radio airtime caps remain effective under high-priority/admin messages.
- G05: Repeated reboot, OTA upgrade and rule migration retain original identity and active policy; confirm safe recovery on failure.

For each case, document the actual steps, input frames or commands, expected outcomes, proof source (serial trace or stats), and **cleanup** to restore default test state. Unit tests should mirror every practical HIL case with deterministic synthetic frames, including collision/replay/power-loss edge conditions. Do not write test cases that can only pass by asserting mocked values.

## 12. Implementation sequence and stop gates

Implement the firmware features first and produce flashable development builds early. Compile the selected repeater target as features land. Defer writing and running formal tests, including native and four-device HIL suites, to the validation phase. Keep a living task plan in `docs/implementation-plan.md`, marking each item `TODO / IN PROGRESS / VERIFIED / BLOCKED` and linking to available build or validation evidence.

1. **Audit and baseline**: inspect actual code, licenses, PlatformIO targets, storage layout, crypto and existing CLI; capture a baseline repeater build and document the existing filters, preserve identity; initialize clean independent Git repository if needed.
2. **RuleStore + CLI**: active allow/deny/filter table, durable IDs, exact-ID deletion, revision/tombstone behavior and pagination; use primary repeater remote CLI first.
3. **Packet policy**: integrate existing filters and verifiable-identity ACL at all forwarding gates; clear fallback for unattributable legacy traffic and add drop counters.
4. **Direct neighbour tracker**: authenticated zero-hop events and deduplicated minimal private channel notices.
5. **Policy synchronization**: verify signed global/regional updates, replay protection and delete convergence, with bounded airtime.
6. **Secondary room identity spike**: distinct persistent keypair, true native signed room contact export via `get admin.advert`; verify stock Android import and room protocol before exposing administrative mutation via the room.
7. **Room management adapter**: display only active instructions, execute only authorized commands, no stored history.
8. **Regression and release**: four-device hardware test, unit tests, static analysis, flash/RAM measurement, docs, fresh build artifacts, end-user upgrade/rollback instructions and signed/checksummed releases where supported.

Do not make feature 6 block early delivery of features 1–5. Do not enable a misleading or insecure room-interface fallback merely to claim completion.

## 13. Build, quality and release requirements

- Examine actual PlatformIO configuration before selecting `pio run -e <actual_repeater_environment>`; never invent an environment name. Build at least the actual nRF52840 test-board target and any other repeater boards included in the initial release.
- During formal validation, run the existing native suites, add independent native coverage for the new modules, and make results reproducible.
- Keep companion, room-server-only and sensor firmware targets untouched unless required for **compilation compatibility**, and never require users to flash custom companion firmware for production.
- Include defensive parsing and cover CLI and over-the-air admin protocol fuzz cases during formal validation. No unchecked lengths, unauthenticated execution, secret leakage or unbounded queues.
- Document per-target firmware size, free RAM, free nonvolatile storage and battery/airtime impacts. If external flash is available, use it only through a verified driver and explicit capacity detection.
- CI must build without physical radios. During formal validation, run native tests in CI and invoke HIL separately with the four real devices. An absent bench leaves hardware validation pending.
- Never commit private signing keys, live client keys, fleet admin secrets, private channel keys, exact sensitive node positions or `hil_config.local.json`. Supply templates and test-only generated identities.
- Never run an aggressive RF test on public network settings, modify live deployed devices, factory-reset hardware or deploy OTA without the user's explicit authorization.
- Keep a release changelog identifying wire-protocol changes, config migrations, non-interoperability and known limitations. Ensure inherited license notices are included in distribution.

## 14. Codex execution/reporting contract

On every task:

1. Inspect the relevant code, determine what the checked-out revision really supports, and briefly state the files and dependencies to change.
2. Implement the smallest complete end-to-end capability and document how to use it. Avoid speculative framework rewrites and placeholder/mock implementations represented as finished functionality.
3. Compile the affected repeater firmware and report the artifact path. During formal validation, run native tests and run HIL only if the real four-device rig is connected and approved. Capture the available evidence.
4. Summarize changed files, supported capabilities, exact CLI usage, unit/HIL pass/fail/skip, memory/flash footprint changes, limitations, and next smallest task.
5. Keep the normal repeater operational and the primary key intact. Prefer safe rollback to the last known-good firmware over feature completeness.

### Definition of done

A development build can be flashed on an authorized test device once the correct target builds successfully. A feature is **production-ready** only when (a) it is implemented in actual production firmware, (b) host tests pass, (c) affected repeater build(s) compile, (d) the relevant HIL tests pass on the four-device rig or are explicitly marked *pending hardware validation*, (e) stock-app interoperability is demonstrated for any user-visible room or channel feature, and (f) the applicable security and airtime limitations are documented. Pending HIL or stock-app proof prevents labeling that feature **production-ready**.

**Design maxim**: *A normal MeshCore repeater to everyone; an authenticated, minimal, remotely administrable and optionally room-enabled node to authorized administrators. No dedicated app. No chat archive. No unnecessary RF traffic.*
