#pragma once

#include <Arduino.h>
#include <helpers/IdentityStore.h>
#include "ForwardTraffic.h"
#include "Probation.h"

class RuleStore {
public:
  static constexpr size_t IdSize = 16;
  static constexpr size_t ChannelKeySize = 16;
  static constexpr size_t Capacity = 24;
  static constexpr size_t ScopeNameSize = 16;

  enum Kind : uint8_t { Allow = 1, Deny, Filter };
  enum Subject : uint8_t { AnyDevice, Client, Repeater, OneByte, Data, Public };
  enum Decision : uint8_t { Unknown, Allowed, Denied };
  enum Scope : uint8_t { Local, Region, Global, Subnet };
  // Keep the on-disk values used by open and restricted in v5–v7 snapshots.
  enum Mode : uint8_t { Normal = 0, LegacyRestricted = 1, Protected = 2, Locked = 3 };

  struct Rule {
    uint8_t id[IdSize];
    uint8_t issuer[PUB_KEY_SIZE];
    uint8_t subject_key[PUB_KEY_SIZE];
    uint8_t revision[4];
    uint8_t kind;
    uint8_t subject;
    uint8_t value;
    uint8_t deleted;
    uint8_t scope;
    uint8_t signature[SIGNATURE_SIZE];
    uint8_t origin[PUB_KEY_SIZE];
  };
  static constexpr size_t WireSize = offsetof(Rule, origin);
  struct Checkpoint {
    uint8_t origin[PUB_KEY_SIZE];
    uint8_t floor[4];
    uint8_t scope;
    uint8_t count;
    uint8_t digest[32];
    uint8_t signature[SIGNATURE_SIZE];
  };
  enum MergeResult : uint8_t { Rejected, Current, Changed };
  struct SubnetModeRecord {
    uint8_t origin[PUB_KEY_SIZE];
    uint8_t revision[8];
    uint8_t mode;
    uint8_t signature[SIGNATURE_SIZE];
  };

  void begin(FILESYSTEM* fs, const mesh::LocalIdentity& node);
  Decision decide(Subject subject, const uint8_t* key) const;
  bool filterEnabled(Subject subject) const;
  bool forwardingAllowed() const { return _ready && !_forwarding_hold; }
  bool onboarding() const { return _state.onboarding != 0; }
  bool transitAllowed() const { return forwardingAllowed() && !onboarding(); }
  bool startOnboarding();
  void handleRecoveryCommand(const char* command, char* reply);
  Mode mode() const;
  const SubnetModeRecord& subnetModeRecord() const { return _state.subnet_mode; }
  uint64_t subnetModeRevision() const;
  MergeResult mergeSubnetMode(const SubnetModeRecord& record, const mesh::Identity& node);
  bool strictTransit() const { return mode() == Protected || mode() == Locked; }
  const char* modeName() const;
  const probation::Snapshot& probationState() const { return _state.probation; }
  bool saveProbation(const probation::Snapshot& state);
  bool enrollmentFrozen() const { return _state.freeze_seconds.get() != 0; }
  void advanceFreeze(uint64_t uptimeMs);
  void restartFreezeTimer(uint64_t uptimeMs) { _freezeAnchor = uptimeMs; _nextFreezeWrite = 0; }
  uint16_t unknownRate() const;
  uint8_t airtimeShare() const { return _state.airtime_share; }
  const forward_traffic::Policy& trafficPolicy() const { return _state.traffic; }
  const uint8_t* neighbourChannel() const { return _state.neighbour_channel; }
  bool setNeighbourChannel(const uint8_t* key);
  const uint8_t* syncKey() const { return _state.sync_key; }
  bool setSyncKey(const uint8_t* key);
  uint32_t reservePeerEpoch();
  bool loadRoomIdentity(mesh::LocalIdentity& identity) const;
  bool saveRoomIdentity(mesh::LocalIdentity& identity);
  bool roomEnabled() const { return _state.room_enabled; }
  const char* roomName() const { return _state.room_name; }
  bool setRoomEnabled(bool enabled);
  bool setRoomName(const char* name);
  bool setScope(Scope scope, const char* name);
  bool setTrustedPeer(const uint8_t* key, bool trust, const mesh::Identity& node);
  const char* scopeName(Scope scope) const;
  bool trustedPeer(const uint8_t* key) const;
  bool publisherAllowed(Scope scope, const uint8_t* key, const mesh::Identity& node) const;
  bool setPublisher(Scope scope, const uint8_t* key, bool grant);
  bool relayAllowed(const uint8_t* key) const;
  bool setRelay(const uint8_t* key, bool allow);
  void describeAuthority(const uint8_t* key, const mesh::Identity& node, char* reply) const;
  const Rule* exportRule(size_t index) const;
  MergeResult mergeRule(Rule& rule, const uint8_t* fingerprint, const mesh::Identity& node,
                        const uint8_t* requiredOrigin = nullptr);
  bool makeCheckpoint(Scope scope, const mesh::LocalIdentity& node, Checkpoint& checkpoint,
                      Rule (&records)[Capacity]) const;
  bool hasCheckpointFloor(Scope scope, const mesh::Identity& node) const;
  MergeResult checkCheckpoint(const Checkpoint& checkpoint, const mesh::Identity& node,
                              bool local = false) const;
  MergeResult installCheckpoint(const Checkpoint& checkpoint, const Rule* records, size_t count,
                                const mesh::Identity& node, bool local = false);
  static constexpr size_t FingerprintSize = 6;
  void handleCommand(const char* command, char* reply, const mesh::LocalIdentity& node,
                     const mesh::Identity* issuer, uint32_t timestamp, mesh::RNG& rng, bool can_write,
                     bool can_publish, bool& sync_requested, uint64_t uptimeMs = 0);

private:
  static constexpr uint8_t RelayPermission = 1;
  struct Authority {
    uint8_t key[PUB_KEY_SIZE];
    uint8_t permissions;
    uint8_t retired;
  };
  static constexpr uint8_t scopePermission(Scope scope) { return uint8_t(1) << scope; }

  struct OriginFloor {
    uint8_t key[PUB_KEY_SIZE];
    uint8_t global[4];
    uint8_t region[4];

    const uint8_t* forScope(Scope scope) const { return scope == Global ? global : region; }
    uint8_t* forScope(Scope scope) { return scope == Global ? global : region; }
  };

  struct Snapshot {
    uint8_t magic[4];
    uint8_t revision[4];
    uint8_t mode;
    uint8_t count;
    uint8_t unknown_rate[2];
    uint8_t neighbour_channel[ChannelKeySize];
    uint8_t sync_key[CIPHER_KEY_SIZE];
    uint8_t room_identity[PRV_KEY_SIZE + PUB_KEY_SIZE];
    char room_name[MAX_ADVERT_DATA_SIZE];
    uint8_t room_enabled;
    char domain[ScopeNameSize];
    char region[ScopeNameSize];
    uint8_t trusted_peers[8][PUB_KEY_SIZE];
    struct {
      uint8_t key[PUB_KEY_SIZE];
      uint8_t timestamp[4];
    } remote_writers[8];
    Rule rules[Capacity];
    forward_traffic::Policy traffic;
    uint8_t airtime_share = forward_traffic::DefaultAirtimeShare;
    probation::Snapshot probation;
    probation::Seconds freeze_seconds;
    OriginFloor floors[9];
    char subnet[ScopeNameSize];
    Authority authorities[12];
    uint8_t onboarding;
    SubnetModeRecord subnet_mode;
    uint8_t digest[32];
  };

  FILESYSTEM* _fs = nullptr;
  Snapshot _state{};
  Snapshot _candidate{};
  int8_t _active_slot = -1;
  bool _ready = false;
  bool _forwarding_hold = false;
  uint8_t _invalid_slots = 0;
  uint64_t _freezeAnchor = 0;
  uint64_t _nextFreezeWrite = 0;

  bool load(const char* path, Snapshot& snapshot);
  bool verifyCandidate(const char* path, const uint8_t* digest);
  bool commit();
  static bool validate(const Snapshot& snapshot, const mesh::Identity& node);
  static bool validRule(const Rule& rule);
  static size_t reserveRuleSlot(Snapshot& snapshot);
  static void signableBytes(const Snapshot& snapshot, const Rule& rule, uint8_t* bytes);
  static uint32_t checkpointFloor(const Snapshot& snapshot, const uint8_t* origin, Scope scope);
  static Authority* authorityFor(Snapshot& snapshot, const uint8_t* key);
  const Authority* authorityFor(const uint8_t* key) const;
  const char* parseScope(const char* input, uint8_t& scope) const;
  int find(const char* id) const;
  void describe(size_t index, char* reply) const;
  uint32_t freezeRemaining(uint64_t uptimeMs) const;
};
