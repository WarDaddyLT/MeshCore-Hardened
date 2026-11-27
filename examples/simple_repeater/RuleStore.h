#pragma once

#include <Arduino.h>
#include <helpers/IdentityStore.h>
#include "ForwardTraffic.h"

class RuleStore {
public:
  static constexpr size_t IdSize = 16;
  static constexpr size_t ChannelKeySize = 16;
  static constexpr size_t Capacity = 24;
  static constexpr size_t ScopeNameSize = 16;

  enum Kind : uint8_t { Allow = 1, Deny, Filter };
  enum Subject : uint8_t { AnyDevice, Client, Repeater, OneByte, Data, Public };
  enum Decision : uint8_t { Unknown, Allowed, Denied };
  enum Scope : uint8_t { Local, Region, Global };

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
  enum MergeResult : uint8_t { Rejected, Current, Changed };

  void begin(FILESYSTEM* fs, const mesh::LocalIdentity& node);
  Decision decide(Subject subject, const uint8_t* key) const;
  bool filterEnabled(Subject subject) const;
  bool forwardingAllowed() const { return _ready && !_forwarding_hold; }
  void handleRecoveryCommand(const char* command, char* reply);
  bool restricted() const { return _state.restricted; }
  uint16_t unknownRate() const;
  uint8_t airtimeShare() const { return _state.airtime_share; }
  const forward_traffic::Policy& trafficPolicy() const { return _state.traffic; }
  const uint8_t* neighbourChannel() const { return _state.neighbour_channel; }
  bool setNeighbourChannel(const uint8_t* key);
  const uint8_t* syncKey() const { return _state.sync_key; }
  bool setSyncKey(const uint8_t* key);
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
  const Rule* exportRule(size_t index) const;
  MergeResult mergeRule(Rule& rule, const uint8_t* fingerprint, const mesh::Identity& node);
  static constexpr size_t FingerprintSize = 6;
  void handleCommand(const char* command, char* reply, const mesh::LocalIdentity& node,
                     const mesh::Identity* issuer, uint32_t timestamp, mesh::RNG& rng, bool can_write,
                     bool can_publish, bool& sync_requested);

private:
  struct Snapshot {
    uint8_t magic[4];
    uint8_t revision[4];
    uint8_t restricted;
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
    uint8_t digest[32];
  };

  FILESYSTEM* _fs = nullptr;
  Snapshot _state{};
  Snapshot _candidate{};
  int8_t _active_slot = -1;
  bool _ready = false;
  bool _forwarding_hold = false;
  uint8_t _invalid_slots = 0;

  bool load(const char* path, Snapshot& snapshot);
  bool verifyCandidate(const char* path, const uint8_t* digest);
  bool commit();
  static bool validate(const Snapshot& snapshot, const mesh::Identity& node);
  static bool validRule(const Rule& rule);
  static void signableBytes(const Snapshot& snapshot, const Rule& rule, uint8_t* bytes);
  const char* parseScope(const char* input, uint8_t& scope) const;
  int find(const char* id) const;
  void describe(size_t index, char* reply) const;
};
