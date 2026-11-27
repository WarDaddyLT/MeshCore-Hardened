# MeshCore Hardened repeater CLI

The existing MeshCore repeater CLI and SaveMeshcore filter commands are available alongside the commands below. The new features use the repeater's existing public identity for management. Configure the optional features from the USB serial console. The isolated secondary room identity starts disabled.

## Administrator enrollment

The MeshCore USB web configurator's **Access control** panel uses the same `get acl` and `setperm` commands as the serial console. Use that panel or `setperm <64-hex-public-key> 3` over USB to approve a key directly. An enrolled key can use stock repeater login with an empty password where the client permits it.

Normal operation (currently `open`) also allows the stock remote login to enroll or promote a key through a configured admin password. Use `password <new-password>` to set it or `password` with no argument to clear it. Fresh installs have no admin password configured. The current `restricted` mode disables password-based enrollment. Protected and Locked will have the same behavior when implemented. Guest login follows its separate permissions.

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
rules add filter 1byte|data|public on|off [scope]
rules delete <rule-id-or-prefix>
rules mode open|restricted
rules rate <packets-per-minute>
rules airtime [percent]
rules drops [category]
```

Scope defaults to `local`. Use `global:<domain>` or `region:<name>` after provisioning sync. Rule changes and explicit sync requests require physical USB or the mesh admin role. Read-only and read-write ACL users can inspect rules and status. Use full 32-hex-character rule IDs when deleting. Prefixes of at least eight hex characters work when unique across active rules and retained deletion records. A shared rule is deleted on its originating repeater. `rules list` returns one active rule per response. Pass the returned `next` value as the next cursor until the response is `End`.

The store supports 24 total entries, including deletion records. An update is written to the alternate snapshot and read back before the active state changes. It verifies snapshot integrity and rule signatures at boot. Retaining deletion records prevents old copies from restoring deleted rules, so new entries are rejected when the table fills. The last valid snapshot stays available when a write fails.

Deny takes precedence over allow for a verified identity. Forwarding decisions use signed client and repeater advertisements. Traffic addressed to this device can also use the identity matched by its existing MeshCore management authentication. Forwarded legacy traffic without a verifiable sender follows packet-class policy. Restricted mode admits attributable traffic from allowed identities and preserves access for existing management ACL entries unless an explicit deny applies. `rules rate` applies the same per-minute packet count separately to anonymous requests, group text, and group data. A value of `0` disables that cap.

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

Valid v5 and v6 rule snapshots load with the default airtime share. A v5 snapshot also defaults its type and category packet policies to allow. The next policy write uses v7. Back up policy before installing an older build that lacks this snapshot format.

## Policy storage recovery

The repeater checks each committed policy snapshot and its revision record at boot. If the expected policy is missing or corrupt, RF forwarding and bridge exports stop. The USB CLI and enrolled local management remain available.

1. Run `rules recovery` over USB to see the storage status and last readable revision.
2. Use `rules recover <last-revision>` to restore the last readable policy explicitly. If no snapshot can be used, `rules recover empty` initializes an empty managed policy. This clears managed rules, policy sync settings, and secondary room settings. The primary identity, administrator ACL, and base filters are stored separately.
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
rules sync status
rules sync
```

Configure the domain, sync key, and trusted origin keys over USB on each participating repeater. Use a dedicated randomly generated 16-byte sync key. For regional policy, configure the same region name in the [MeshCore region map](cli_commands.md#region-management-v110) on participating repeaters. Domain and region names accept up to 15 lowercase letters, digits, underscores, or hyphens. The domain and region cannot be renamed while their signed rules or deletion records exist.

Shared updates are signed with the originating repeater key after it authorizes the change. Peers verify that trusted origin signature independently. Sync messages are encrypted with AES-128-GCM and carry one update per packet. Local rules stay on their repeater. A write queues shared updates, and `rules sync` resends active rules and deletion records after a partition. Senders queue at most one update per minute. For a multi-hop reconciliation, run sync on intermediate trusted repeaters that already hold the current state. Untrusting a key stops future updates from that signer. Previously accepted records retain their last state.

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
