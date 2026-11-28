# MeshCore Hardened repeater CLI

The existing MeshCore repeater CLI and SaveMeshcore filter commands are available alongside the commands below. The new features use the repeater's existing public identity for management. Configure the optional features from the USB serial console. The isolated secondary room identity starts disabled.

## Administrator enrollment

The MeshCore USB web configurator's **Access control** panel uses the same `get acl` and `setperm` commands as the serial console. Use that panel or `setperm <64-hex-public-key> 3` over USB to approve a key directly. An enrolled key can use stock repeater login with an empty password where the client permits it.

Normal mode allows the stock remote login to enroll or promote a key through a configured admin password. Use `password <new-password>` to set it or `password` with no argument to clear it. Fresh installs have no admin password configured. Legacy Restricted mode disables password-based enrollment. Guest login follows its separate permissions.

Use `get acl` on USB to review installed roles and `setperm <64-hex-public-key> 0` to revoke an entry. An unambiguous byte-aligned prefix also works for revocation. In Normal, rotate or clear the enrollment password if a revoked operator knows it.

The first ACL change copies the existing roles into the repeater's versioned ACL store. A successful command commits the new roles before returning. Routes are rebuilt through normal MeshCore exchanges. If a committed ACL cannot be read, use physical USB to enroll a trusted administrator again. The repeater keeps the legacy contacts file for rollback. An older firmware uses the legacy permissions, so review the ACL after a rollback. Stock-client interoperability and power-loss behavior on hardware remain pending.

The unauthenticated Ethernet console exposes only `eth.status`, `ver`, and `board`. Manage the repeater through USB or the authenticated mesh CLI.

## Persistent rules

```text
rules status
rules count
rules list [cursor]
rules show <rule-id-or-prefix>
rules add allow client <64-hex-public-key> [scope]
rules add deny client <64-hex-public-key> [scope]
rules add allow repeater <64-hex-public-key> [scope]
rules add deny repeater <64-hex-public-key> [scope]
rules device <client|repeater> <64-hex-public-key>
rules add filter 1byte|data|public on|off [scope]
rules delete <rule-id-or-prefix>
rules mode [normal|protected|locked|restricted]
rules freeze [start [minutes]|extend <minutes>|end]
rules rate <packets-per-minute>
rules airtime [percent]
rules drops [category]
```

Scope defaults to `local`. Use `global:<domain>` or `region:<name>` after provisioning sync. Rule changes and explicit sync requests require physical USB or the mesh admin role. Read-only and read-write ACL users can inspect rules and status. Use full 32-hex-character rule IDs when deleting. Prefixes of at least eight hex characters work when unique across active rules and retained deletion records. A shared rule is deleted on its originating repeater. `rules list` returns one active rule per response. Pass the returned `next` value as the next cursor until the response is `End`.

Normal is the default mode. It forwards stock traffic subject to the configured filters, attributable bans, and forwarding limits. An existing `open` setting reads as `normal` after upgrade, and `rules mode open` remains an alias. An existing `restricted` setting remains active and keeps its prior allowlist and enrollment behavior. Upgrade leaves the saved rule and filter settings in place.

### Protected mode

Use `rules mode protected` to stop unattributable transit, including stock group messages and ordinary direct packets whose source the repeater cannot verify. The repeater continues to accept locally authenticated management for approved keys. Password-based enrollment and unauthenticated discovery replies are disabled. A policy update can relay after the existing peer, signature, and scope checks succeed.

Signed client and repeater adverts from approved keys can still pass subject to the ordinary forwarding limits. A fresh, verified RF advert from an unknown key starts probation at zero. The fraction of eligible adverts that may be forwarded grows linearly with elapsed uptime, reaching one-third at 24 hours, two-thirds at 48 hours, and the full probation allowance at 72 hours. An unattributable message never inherits the advert's identity. Each probation key gets at most six eligible candidates per signed minute. While the key is still on probation, admitted adverts also share six forwarding opportunities per minute. The ordinary airtime, queue and packet policies apply throughout.

The repeater tracks up to 12 probation keys and reuses entries resolved by an administrator allow or deny. Freshness requires a synchronized repeater clock. Forwarding credit comes from monotonic uptime, so time offline or an adjustment to the wall clock does not fast-forward probation. New entries are saved in batches with at least a minute between writes and can forward only after their first successful save. Progress checkpoints are 15 minutes apart. A reboot can discard unsaved progress. A new key starts over. Use `rules device <role> <key>` to read whole hours remaining and `rules drops` to inspect probation drops.

When an admin enters Protected, the repeater discards packets still queued for transmit. Bridge transit in Protected requires an explicitly allowed signed advert. Use `rules mode normal` to restore normal forwarding.

### Locked mode and the enrollment freeze

Use `rules mode locked` to require a fresh, signed client or repeater advert from an explicitly allowed key. A deny still takes precedence. Probation completion alone gives no Locked forwarding access. Legacy group messages and other unattributable transit are dropped even when a channel is private. Bridge transit follows the same approved-advert policy. Locked relay of existing policy sync requires a separately trusted and allowlisted repeater, plus the existing scope and signature checks. Entering Locked clears queued transmissions. Local authenticated administration remains available over USB and for enrolled administrators. Use `rules drops` to read Locked drops.

`rules freeze start` begins a local 60-minute enrollment freeze. Supply minutes to choose another duration from 1 to 10080. `rules freeze extend <minutes>` adds time up to seven days remaining. `rules freeze end` ends the freeze. USB operators and authenticated mesh administrators can change it. An active freeze blocks new password-based enrollment and promotion, new guest registration, and new automatic Protected probation entries. Approved keys and existing probation keep their forwarding policy. Explicit authorized ACL and rule edits remain available for recovery and deliberate onboarding.

The freeze is independent of mode and stays active across reboot. It counts powered-on time, checkpoints remaining time every 15 minutes, and ends after a successful expiry write. Reboot can restore up to the last checkpoint's remaining time. Wall-clock changes leave the timer alone. If storage cannot record expiry, the freeze stays active and can be ended by an authorized operator when storage recovers.

The store supports 24 total entries. The `free` count in `rules status` includes unused slots and deleted local rules. A deleted local rule remains identifiable until its slot is reused. Shared deletion records stay in the store to prevent stale peers from restoring deleted rules. New entries are rejected when no slots can be reused. Rule updates are read back from the alternate snapshot before the active state changes.

Deny takes precedence over allow for a verified identity. A deny covers the full key across device roles, including a changed advertised role. An allow applies to its specified role. Traffic addressed to this device can also use the identity matched by its existing MeshCore management authentication. Forwarded legacy traffic without a verifiable sender follows packet-class policy. Restricted mode admits attributable traffic from allowed identities and preserves access for existing management ACL entries unless an explicit deny applies. `rules rate` applies the same per-minute packet count separately to anonymous requests, group text, and group data. A value of `0` disables that cap.

## Device trust and activity

`rules device client <key>` and `rules device repeater <key>` show the effective trust decision and recent signed advert counts for the full key. Add or remove trust through the persistent `rules add allow`, `rules add deny`, and `rules delete` commands. For a deliberate key change, deny the old key and then explicitly allow the replacement. Device trust is independent of the management ACL and policy publication authority.

Activity uses bounded RAM with reserved entries for approved keys. The repeater counts verified client and repeater advertisements received on RF when the signed timestamp is at most 60 seconds behind or 15 seconds ahead of the repeater clock. Within that window, repeated or older timestamps for a tracked key are dropped without increasing its count. Each tracked key can use six increasing timestamps per signed minute. Outside the freshness window or when an unknown key cannot be tracked, normal category controls still apply. Bridge exports use their own category controls.

The counts are advisory. Received activity cannot grant trust or create a ban. Counters reset at reboot, and a valid advert replayed within the freshness window may be observed after that reset. Legacy transit messages have no verifiable sender key for a per-device count. Keep the repeater clock synchronized when inspecting recent activity.

Managed filter rules can add restrictions to the existing filters. The most specific active managed filter wins, in the order local, region, then global. Within a scope, revisions are ordered numerically with the originating key breaking ties. A managed `off` removes the restriction contributed by managed rules. Use the existing `filter` command for the independently persisted base filter.

## Forwarding controls by packet type and category

These controls are local to the repeater. They apply to RF forwarding and bridge exports. Local management requests still use the existing ACL.

```text
rules traffic
rules traffic type 0x06
rules traffic type 6 drop
rules traffic type 0x06 allow
rules traffic category group-text
rules traffic category group-text limit 30
```

Use decimal packet types `0` to `15` or hex `0x00` to `0x0f`. Omit the action to read the current setting. Actions are `allow`, `drop`, or `limit <1..600>` forwarding candidates per minute. USB and mesh admins can make changes. Inspect-only ACL roles can read settings. All new settings initially allow traffic through this policy.

| Category | Packet types |
| --- | --- |
| `group-text` | Group text |
| `group-data` | Group data |
| `direct-text` | Direct text, including transit CLI text |
| `discovery` | Advertisements and route traces |
| `anonymous` | Anonymous requests |
| `routing` | ACK, returned paths, and multipart |
| `management` | Request, response, and control |
| `other` | Reserved and custom types |

A type drop or category drop blocks that traffic. An allow leaves the other configured controls in force, including the inherited SaveMeshcore filters and `rules rate`. A frame must fit every applicable type and category cap. RF and bridge exports use separate packet-count budgets.

Each RF forwarding category gets its own estimated airtime budget. `rules airtime` reads the current share, and `rules airtime <1..100>` sets it as a percentage of the configured dispatcher duty cycle. The default is 25%. At a configured 10% duty cycle, the default gives each category 2.5% of wall-clock time over sustained traffic. Each budget can accumulate credit for two maximum-size frames and charges the outgoing frame size at the current radio settings. `rules airtime 0` disables category airtime budgets. The dispatcher still enforces the shared radio limit for all transmissions, including local replies.

Forwarding admission limits each category to four outstanding packets in the outbound queue and leaves three free packet buffers for other operations, including local management replies. Stock queue priority still applies. Legacy senders within one category share its budget. Local forwarding controls cannot prevent nearby radios from occupying the RF channel.

`rules drops` shows totals by reason. `rules drops <category>` reports airtime drops, queue drops, and the estimated airtime admitted for RF forwarding. Admission totals include frames that may later fail to transmit. Use radio counters and path evidence to validate actual RF delivery.

Valid v5 and v6 rule snapshots load with the default airtime share. A v5 snapshot also defaults its type and category packet policies to allow. Snapshots from v5 through v7 load with an empty probation ledger. Snapshots from v5 through v8 load with the enrollment freeze off. The next policy write uses v9. Back up policy before installing an older build that lacks this snapshot format.

## Receive work and diagnostics

The repeater checks the packet envelope and supported payload lengths before processing RF packets. Direct transit duplicates are checked before forwarding policy. Signature verification for signed adverts has a bounded cache of recent results and its own work limit. Failed signature checks never create identity bans. Anonymous requests addressed to the primary identity, policy sync, and the optional room each have independent limits for expensive receive work. Delayed RF packets and bridge input leave three buffers free for other operations.

Use `rules work` to read aggregate volatile counters for malformed frames, RF delay-queue drops, invalid advert signatures, and advert verification cache hits. Use `rules work advert`, `rules work anonymous`, `rules work sync`, or `rules work room` to read admitted verification attempts and work-limit drops. These counters reset at reboot. Compare them with `rules drops` and `stats-radio` when measuring responsiveness.

Bridge exports observe forwarding enablement, flood scope and hop limits, and the existing packet policies. An exported advertisement must have a valid signature. Policy-sync packets stay on the RF sync path. Optional room and neighbour notices still require separate stock-client and airtime validation.

The repeater stores no packet journal. `log stop` reports that logging is disabled. A file left by older firmware can be removed explicitly with `log erase` over USB.

## Policy storage recovery

The repeater checks each committed policy snapshot and its revision record at boot. If the expected policy is missing or corrupt, RF forwarding and bridge exports stop. The USB CLI and enrolled local management remain available.

1. Run `rules recovery` over USB to see the storage status and last readable revision.
2. Use `rules recover <last-revision>` to restore the last readable policy explicitly. If no snapshot can be used, `rules recover empty` initializes an empty managed policy. Either recovery command clears the sync key. The empty recovery also clears managed rules and secondary room settings. The primary identity, administrator ACL, and base filters are stored separately.
3. Review or reprovision the policy, then run `rules resume` over USB. The hold survives reboot and stays in effect until resume succeeds.

Valid snapshots from older builds are recorded on upgrade. Interrupted writes preserve the previous sealed snapshot. If the boot checks cannot establish which policy is safe to use, forwarding stays held and the repeater reports recovery is required.

## Private direct-neighbour notices

```text
neighbours channel <32-hex-private-channel-key>
neighbours channel off
neighbours status
neighbours show <index>
neighbours reset
```

Use the same 16-byte secret in the stock app's private channel. The repeater rejects the built-in Public key during setup. A previously saved Public key is reported as `channel=blocked` and cannot send notices. Configure and reset from USB. A verified zero-hop radio advertisement can queue a notice for a repeater or for a client enrolled with an allow rule. The table holds up to 32 identities per boot or deliberate reset. It sends at most one notice every five minutes. With a default transport region, notices use that region. Otherwise they are zero-hop. A signed advert authenticates its contents. MeshCore hop metadata describes the received route and cannot prove physical proximity against an RF replay.

## Shared policy

```text
rules domain <domain>
rules region <meshcore-region-name>
rules sync.key <32-hex-private-sync-key>
rules sync.key off
rules trust <64-hex-repeater-public-key>
rules untrust <64-hex-repeater-public-key>
rules subnet [name]
rules subnet mode [normal|protected|locked]
rules subnet sync
rules onboarding
rules onboarding start
rules authority <64-hex-public-key>
rules publisher grant|retire global|region|subnet <64-hex-public-key>
rules relay allow|remove <64-hex-repeater-public-key>
rules peer connect|disconnect|status domain|subnet <64-hex-repeater-public-key>
rules sync status
rules sync
rules checkpoint
rules checkpoint global|region
```

Configure the domain, sync key, and authorized origins over USB on each participating repeater. Use a dedicated randomly generated 16-byte sync key. For regional policy, configure the same region name in the MeshCore region map on participating repeaters. Domain, region, and subnet names accept up to 15 lowercase letters, digits, underscores, or hyphens. A scope name is fixed while it has signed records, a committed checkpoint, or scoped authority entries. [MeshCore region management](cli_commands.md#region-management-v110)

Shared updates are signed with the originating repeater key after it authorizes the change. Each receiving repeater checks the scope grant and verifies the origin signature independently. Sync messages are encrypted with AES-128-GCM and carry one update per packet. Local rules stay on their repeater. A write queues shared updates, and `rules sync` resends active rules and deletion records after a partition. Senders queue at most one update per minute. For a multi-hop reconciliation, run sync on intermediate repeaters that already hold the current state.

`rules subnet <name>` assigns this repeater to one named managed subnet, independently of its MeshCore region. `rules authority <key>` reports peer, relay, and publisher settings. For shared global and regional rules, use a `domain` session. Use a `subnet` session to share the mode within the configured subnet.

Assigning a new subnet name holds RF and bridge forwarding in the same durable write. Upgrading a repeater with an existing subnet also requires onboarding. `rules onboarding` reports the selected subnet, onboarding state, and transit availability. `rules onboarding start` is a USB-only command that puts a configured repeater back into onboarding. USB management and authenticated policy exchange stay available during onboarding. `rules resume` controls the separate storage recovery hold. Managed transit stays held until a verified policy commit. [Onboarding commit](https://github.com/WarDaddyLT/MeshCore-Hardened/issues/24)

On both repeaters, set the same dedicated random sync key and trust the other's full public key. In Locked, a domain-session peer also needs a repeater allow rule. Trusted subnet control peers can still share signed mode changes in Locked. A repeater deny rule blocks both session types. Use `rules peer connect` on one end and wait for `rules peer status` to show `peer=authenticated` at both ends. The handshake uses three signed proofs, reserves a durable freshness epoch on first use after boot, and expires pending state after four minutes. Active sessions expire after one hour. If the last proof is lost, disconnect on both ends before reconnecting. A repeater holds up to eight sessions. After restoring a policy snapshot with USB recovery, provision a fresh dedicated sync key on participating nodes before reconnecting.

Session frames go directly between authenticated peers. For a peer to carry another publisher's signed rules or checkpoints, grant that peer `rules relay allow <key>` on the receiver. The receiver still verifies the original publisher and scope. Peer handshakes, rule updates, and checkpoint frames use the same one-frame-per-minute transmit budget. A session and its sequence counters are volatile. Reconnect and run `rules sync` after a reboot or an expired session.

`rules subnet mode` shows the committed signed mode, hexadecimal revision, local setting, and effective mode. A local administrator can publish a new mode only when the repeater's own key has a subnet publisher grant. Members retain their last verified revision during a partition. Each signed mode fits in one 130-byte control payload. Newer revisions win, with a tie between distinct publishers resolved by the lexicographically greater full public key. A trusted session that reconnects queues the last committed mode. Third-party mode records require the same explicit relay grant as other policy. The more restrictive local mode stays in force. Retirement blocks new updates from the retired key and keeps the last committed mode until an authorized publisher replaces it.

Grant a full origin key separately for each scope where a receiving repeater should accept its signatures. A repeater's own key can issue global and regional rules after configuring the corresponding scope. Subnet publishing requires its own grant. On upgrade, any previously trusted keys retain their existing global or regional publishing permissions. New `rules trust` entries grant peer permission only.

To retire an unavailable or compromised publisher, run `rules publisher retire <scope> <key>` on each affected repeater over USB. This atomically removes that key's rules for the scope and blocks its later updates and checkpoints, including delayed copies. The retired key cannot be granted the same scope again. Grant a fresh key and reissue the intended rules to rotate it. Peer trust and other scope grants remain independent. The authority table holds 12 keys including retired entries. Retirements are local durable operations and require provisioning on each affected repeater.

Run `rules checkpoint global` or `rules checkpoint region` on the originating repeater to reclaim its shared deletion slots for that scope. It commits a signed checkpoint and queues its active rules. A peer applies the checkpoint atomically after it receives and verifies every record. It preserves newer updates and ignores older updates covered by the committed checkpoint, including after reboot. A peer that installs a checkpoint queues it for relay. Its revision floor survives removing and re-adding the origin key. Checkpoint floor storage holds up to nine full origin keys including the local repeater.

`rules checkpoint` reports the transfer state. Each repeater stages one transfer at a time for up to 30 minutes. The checkpoint header and its records share the one-frame-per-minute policy send budget. After missed frames, reboot, or a partition, issue a fresh checkpoint on the originating repeater and verify the receiving rule list. Use checkpoint-capable firmware on each managed peer that needs to apply or relay checkpoints.

## Optional administration room

```text
get admin.enabled
set admin.enabled on|off
get admin.name
set admin.name <short-name>
get admin.pubkey
get admin.advert
get admin.advert <zero-based-part-index>
admin.advert once
```

Enable the room from USB. The repeater keeps a separate room-server keypair across reboots, and its public repeater key remains the routing identity. The room sends no periodic advertisements. `get admin.advert` returns the transfer ID, part count, byte count, and SHA-256 of the native signed advert. Retrieve each part within five minutes, match the transfer ID, then concatenate the hex in index order. This is the native advert payload used in the upstream `meshcore://<hex>` card format. `admin.advert once` exposes the contact directly over radio for manual validation.

The room uses the repeater's existing ACL and native room login with an empty password. Send `rules count`, `rules list`, `rules show`, or `rules status` in the room. Only the current state is returned. Rule changes go through the repeater CLI because native room messages lack a signed write command. No room messages or responses are saved by the firmware. Android import, login, and reply display remain pending on-device validation.
