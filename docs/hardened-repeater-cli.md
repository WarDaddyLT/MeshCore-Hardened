# MeshCore Hardened repeater CLI

The existing MeshCore repeater CLI and SaveMeshcore filter commands are available alongside the commands below. The new features use the repeater's existing public identity for management. Configure the optional features from the USB serial console. The isolated secondary room identity starts disabled.

## Administrator enrollment

From the physical USB console, use `setperm <64-hex-public-key> 3` to approve the first administrator key. An enrolled client uses the stock repeater login with an empty password where the client permits it. Login cannot grant a role. A configured guest password permits guest access only.

Use `get acl` on USB to review the installed roles. Firmware upgrades retain the existing ACL, so review and revoke any unknown entries from earlier password-based deployments. Revoke a role with `setperm <64-hex-public-key> 0`. An unambiguous byte-aligned prefix also works for revocation.

The first ACL change copies the existing roles into the repeater's versioned ACL store. A successful command commits the new roles before returning. Routes are rebuilt through normal MeshCore exchanges. If a committed ACL cannot be read, use physical USB to enroll a trusted administrator again. The repeater keeps the legacy contacts file for rollback. An older firmware uses the legacy permissions, so review the ACL after a rollback. Stock-client interoperability and power-loss behavior on hardware remain pending.

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
rules drops
```

Scope defaults to `local`. Use `global:<domain>` or `region:<name>` after provisioning sync. The USB console and MeshCore ACL users with write access can edit local rules. Publishing shared rules over MeshCore requires the admin role. Use full 32-hex-character rule IDs when deleting. Prefixes of at least eight hex characters work when unique across active rules and retained deletion records. A shared rule is deleted on its originating repeater. `rules list` returns one active rule per response. Pass the returned `next` value as the next cursor until the response is `End`.

The store supports 24 total entries, including deletion records. An update is written to the alternate snapshot and read back before the active state changes. It verifies snapshot integrity and rule signatures at boot. Retaining deletion records prevents old copies from restoring deleted rules, so new entries are rejected when the table fills. The last valid snapshot stays available when a write fails.

Deny takes precedence over allow for a verified identity. Forwarding decisions use signed client and repeater advertisements. Traffic addressed to this device can also use the identity matched by its existing MeshCore management authentication. Forwarded legacy traffic without a verifiable sender follows packet-class policy. Restricted mode admits attributable traffic from allowed identities and preserves access for existing management ACL entries unless an explicit deny applies. `rules rate` adds a shared per-minute forwarding budget for anonymous requests and group packets. A value of `0` disables that added limit.

Managed filter rules can add restrictions to the existing filters. The most specific active managed filter wins, in the order local, region, then global. Within a scope, revisions are ordered numerically with the originating key breaking ties. A managed `off` removes the restriction contributed by managed rules. Use the existing `filter` command for the independently persisted base filter.

## Private direct-neighbour notices

```text
neighbours channel <32-hex-private-channel-key>
neighbours channel off
neighbours status
neighbours show <index>
neighbours reset
```

Use the same 16-byte secret in the stock app's private channel. Configure and reset from USB. A verified zero-hop radio advertisement can queue a notice for a repeater or for a client enrolled with an allow rule. The table holds up to 32 identities per boot or deliberate reset. It sends at most one notice every five minutes. With a default transport region, notices use that region. Otherwise they are zero-hop. A signed advert authenticates its contents. MeshCore hop metadata describes the received route and cannot prove physical proximity against an RF replay.

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
