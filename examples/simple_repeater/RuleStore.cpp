#include "RuleStore.h"
#include "CliParse.h"
#include <stddef.h>

namespace {
const char* const Files[] = {"/hardened_rules_a", "/hardened_rules_b"};
const char* const Seals[] = {"/hardened_rules_a_rev", "/hardened_rules_b_rev"};
constexpr const char* Pending = "/hardened_rules_tmp";
constexpr const char* PendingSeal = "/hardened_rules_rev_tmp";
constexpr const char* Provisioned = "/hardened_rules_provisioned";
constexpr const char* ForwardingHold = "/hardened_rules_hold";
constexpr uint8_t Magic[] = {'M', 'C', 'H', 7};
constexpr uint8_t LegacyTrafficMagic[] = {'M', 'C', 'H', 6};
constexpr uint8_t LegacyRulesMagic[] = {'M', 'C', 'H', 5};
constexpr char SigningDomain[] = "MeshCore Hardened policy v1";
constexpr size_t SignedSize = sizeof(SigningDomain) + RuleStore::ScopeNameSize * 2
                            + offsetof(RuleStore::Rule, signature) + PUB_KEY_SIZE;

uint32_t decodeRevision(const uint8_t* bytes) {
  return static_cast<uint32_t>(bytes[0])
       | static_cast<uint32_t>(bytes[1]) << 8
       | static_cast<uint32_t>(bytes[2]) << 16
       | static_cast<uint32_t>(bytes[3]) << 24;
}

void encodeRevision(uint8_t* bytes, uint32_t value) {
  for (size_t i = 0; i < 4; i++) {
    bytes[i] = static_cast<uint8_t>(value >> (i * 8));
  }
}

File openRead(FILESYSTEM* fs, const char* path) {
#if defined(RP2040_PLATFORM)
  return fs->open(path, "r");
#else
  return fs->open(path);
#endif
}

File openWrite(FILESYSTEM* fs, const char* path) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return fs->open(path, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(path, "w");
#else
  return fs->open(path, "w", true);
#endif
}

bool ensureMarker(FILESYSTEM* fs, const char* path) {
  if (fs->exists(path)) return true;
  auto file = openWrite(fs, path);
  if (!file) return false;
  const uint8_t marker = 1;
  bool written = file.write(&marker, sizeof(marker)) == sizeof(marker);
  file.close();
  return written && fs->exists(path);
}

bool removeIfPresent(FILESYSTEM* fs, const char* path) {
  return !fs->exists(path) || fs->remove(path);
}

bool verifySeal(FILESYSTEM* fs, const char* path, uint32_t revision) {
  auto file = openRead(fs, path);
  if (!file) return false;
  uint8_t stored[4];
  bool valid = file.size() == sizeof(stored)
      && file.read(stored, sizeof(stored)) == sizeof(stored)
      && decodeRevision(stored) == revision;
  file.close();
  return valid;
}

bool commitSeal(FILESYSTEM* fs, const char* path, uint32_t revision) {
  if (!removeIfPresent(fs, PendingSeal)) return false;
  auto file = openWrite(fs, PendingSeal);
  if (!file) return false;
  uint8_t encoded[4];
  encodeRevision(encoded, revision);
  bool written = file.write(encoded, sizeof(encoded)) == sizeof(encoded);
  file.close();
  return written && verifySeal(fs, PendingSeal, revision) && fs->rename(PendingSeal, path);
}

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  c = savemesh::lowerAscii(c);
  return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

bool decodeKey(const char* arg, uint8_t* key) {
  for (size_t i = 0; i < PUB_KEY_SIZE; i++) {
    int hi = hexValue(*arg);
    if (hi < 0) return false;
    int lo = hexValue(*++arg);
    if (lo < 0) return false;
    key[i] = static_cast<uint8_t>((hi << 4) | lo);
    ++arg;
  }
  return *arg == 0 || *arg == ' ';
}

struct TrafficTarget {
  unsigned index;
  bool category;

  const forward_traffic::Limit& select(const forward_traffic::Policy& policy) const {
    return category ? policy.categories[index] : policy.types[index];
  }

  void set(forward_traffic::Policy& policy, uint16_t value) const {
    (category ? policy.categories[index] : policy.types[index]).set(value);
  }
};

bool parseTrafficTarget(const char* input, TrafficTarget& target, const char** action) {
  const char* name;
  if (savemesh::matchCommand(input, "category", &name)) {
    for (unsigned i = 0; i < forward_traffic::CategoryCount; ++i) {
      if (savemesh::matchCommand(name, forward_traffic::CategoryNames[i], action)) {
        target = {i, true};
        return true;
      }
    }
  } else if (savemesh::matchCommand(input, "type", &name)) {
    const char* end = name + strcspn(name, " ");
    size_t length = end - name;
    int value = -1;
    if (length == 4 && name[0] == '0' && savemesh::lowerAscii(name[1]) == 'x' && name[2] == '0') {
      value = hexValue(name[3]);
    } else if (length == 1 || length == 2) {
      char number[3]{};
      memcpy(number, name, length);
      uint16_t parsed;
      if (savemesh::parseUnsigned(number, &parsed)) value = parsed;
    }
    if (value >= 0 && value < static_cast<int>(forward_traffic::TypeCount)) {
      target = {static_cast<unsigned>(value), false};
      while (*end == ' ') ++end;
      *action = end;
      return true;
    }
  }
  return false;
}

void describeTraffic(const TrafficTarget& target, uint16_t limit, char* reply) {
  char number[5];
  snprintf(number, sizeof(number), "0x%02x", target.index);
  const char* name = target.category ? forward_traffic::CategoryNames[target.index] : number;
  if (limit == 0 || limit == forward_traffic::Drop) {
    snprintf(reply, 150, "%s %s %s", target.category ? "category" : "type", name, limit ? "drop" : "allow");
  } else {
    snprintf(reply, 150, "%s %s limit %u", target.category ? "category" : "type", name, static_cast<unsigned>(limit));
  }
}

const char* kindName(uint8_t kind) {
  switch (kind) {
    case RuleStore::Allow: return "allow";
    case RuleStore::Deny: return "deny";
    default: return "filter";
  }
}

const char* subjectName(uint8_t subject) {
  switch (subject) {
    case RuleStore::Client: return "client";
    case RuleStore::Repeater: return "repeater";
    case RuleStore::OneByte: return "1byte";
    case RuleStore::Data: return "data";
    default: return "public";
  }
}

}

void RuleStore::signableBytes(const Snapshot& snapshot, const Rule& rule, uint8_t* bytes) {
  memcpy(bytes, SigningDomain, sizeof(SigningDomain));
  bytes += sizeof(SigningDomain);
  memset(bytes, 0, ScopeNameSize * 2);
  if (rule.scope != Local) memcpy(bytes, snapshot.domain, ScopeNameSize);
  if (rule.scope == Region) memcpy(bytes + ScopeNameSize, snapshot.region, ScopeNameSize);
  bytes += ScopeNameSize * 2;
  memcpy(bytes, &rule, offsetof(Rule, signature));
  memcpy(bytes + offsetof(Rule, signature), rule.origin, PUB_KEY_SIZE);
}

bool RuleStore::validRule(const Rule& rule) {
  return decodeRevision(rule.revision) != 0 && rule.deleted <= 1 && rule.scope <= Global
      && rule.kind >= Allow && rule.kind <= Filter && rule.value <= 1
      && (rule.kind == Filter ? rule.subject >= OneByte && rule.subject <= Public
                              : rule.subject == Client || rule.subject == Repeater);
}

bool RuleStore::load(const char* path, Snapshot& snapshot) {
  auto file = openRead(_fs, path);
  if (!file) return false;
  auto* bytes = reinterpret_cast<uint8_t*>(&snapshot);
  const size_t size = file.size();
  if (size == sizeof(snapshot)) {
    bool complete = file.read(bytes, sizeof(snapshot)) == sizeof(snapshot);
    file.close();
    return complete;
  }

  uint8_t legacyDigest[sizeof(snapshot.digest)];
  constexpr size_t rulesPrefix = offsetof(Snapshot, traffic);
  constexpr size_t trafficPrefix = offsetof(Snapshot, airtime_share);
  const bool hasTraffic = size == trafficPrefix + sizeof(legacyDigest);
  const size_t legacyPrefix = hasTraffic ? trafficPrefix : rulesPrefix;
  const auto* legacyMagic = hasTraffic ? LegacyTrafficMagic : LegacyRulesMagic;
  bool complete = size == legacyPrefix + sizeof(legacyDigest) && file.read(bytes, legacyPrefix) == legacyPrefix
      && file.read(legacyDigest, sizeof(legacyDigest)) == sizeof(legacyDigest);
  file.close();
  if (!complete || memcmp(snapshot.magic, legacyMagic, sizeof(Magic)) != 0) return false;

  mesh::Utils::sha256(snapshot.digest, sizeof(snapshot.digest), bytes, legacyPrefix);
  if (memcmp(legacyDigest, snapshot.digest, sizeof(legacyDigest)) != 0) return false;
  memcpy(snapshot.magic, Magic, sizeof(Magic));
  if (!hasTraffic) snapshot.traffic = {};
  snapshot.airtime_share = forward_traffic::DefaultAirtimeShare;
  mesh::Utils::sha256(snapshot.digest, sizeof(snapshot.digest), bytes, offsetof(Snapshot, digest));
  return true;
}

bool RuleStore::validate(const Snapshot& snapshot, const mesh::Identity& node) {
  if (memcmp(snapshot.magic, Magic, sizeof(Magic)) != 0
      || snapshot.restricted > 1 || snapshot.count > Capacity || snapshot.room_enabled > 1 || !snapshot.traffic.valid()
      || snapshot.airtime_share > 100
      || snapshot.room_name[sizeof(snapshot.room_name) - 1]
      || snapshot.domain[ScopeNameSize - 1] || snapshot.region[ScopeNameSize - 1]) return false;

  uint8_t digest[sizeof(snapshot.digest)];
  mesh::Utils::sha256(digest, sizeof(digest), reinterpret_cast<const uint8_t*>(&snapshot),
                     offsetof(Snapshot, digest));
  if (memcmp(digest, snapshot.digest, sizeof(digest)) != 0) return false;

  for (size_t i = 0; i < snapshot.count; i++) {
    const auto& rule = snapshot.rules[i];
    if (!validRule(rule) || (rule.scope == Local && !node.matches(rule.origin))
        || (rule.scope != Local && !snapshot.domain[0])
        || (rule.scope == Region && !snapshot.region[0])) return false;
    for (size_t j = 0; j < i; j++) {
      if (memcmp(snapshot.rules[j].id, rule.id, IdSize) == 0) return false;
    }
    uint8_t signed_bytes[SignedSize];
    signableBytes(snapshot, rule, signed_bytes);
    if (!mesh::Identity(rule.origin).verify(rule.signature, signed_bytes, sizeof(signed_bytes))) return false;
  }
  return true;
}

void RuleStore::begin(FILESYSTEM* fs, const mesh::LocalIdentity& node) {
  _fs = fs;
  _forwarding_hold = fs->exists(ForwardingHold);
  bool managed = fs->exists(Provisioned) || fs->exists(Seals[0]) || fs->exists(Seals[1]);
  uint32_t legacy_revisions[2]{};
  for (int slot = 0; slot < 2; slot++) {
    if (!fs->exists(Files[slot]) && !fs->exists(Seals[slot])) continue;
    if (!load(Files[slot], _candidate) || !validate(_candidate, node)) {
      _invalid_slots |= 1 << slot;
      continue;
    }
    uint32_t revision = decodeRevision(_candidate.revision);
    if (!revision || (managed && !verifySeal(fs, Seals[slot], revision))) {
      _invalid_slots |= 1 << slot;
      continue;
    }
    legacy_revisions[slot] = revision;
    if (_active_slot < 0 || revision > decodeRevision(_state.revision)) {
      _state = _candidate;
      _active_slot = slot;
    }
  }
  if (!_invalid_slots && _active_slot >= 0) {
    _ready = managed || ensureMarker(fs, Provisioned);
    if (!managed) {
      for (int slot = 0; slot < 2 && _ready; ++slot) {
        if (legacy_revisions[slot] && !commitSeal(fs, Seals[slot], legacy_revisions[slot])) {
          _invalid_slots |= 1 << slot;
          _ready = false;
        }
      }
    }
  } else {
    _ready = !_invalid_slots && !managed && !_forwarding_hold;
  }
  memcpy(_state.magic, Magic, sizeof(Magic));
}

bool RuleStore::verifyCandidate(const char* path, const uint8_t* digest) {
  if (!load(path, _candidate) || memcmp(_candidate.digest, digest, sizeof(_candidate.digest)) != 0) return false;
  uint8_t read_digest[sizeof(_candidate.digest)];
  mesh::Utils::sha256(read_digest, sizeof(read_digest), reinterpret_cast<const uint8_t*>(&_candidate),
                      offsetof(Snapshot, digest));
  return memcmp(read_digest, digest, sizeof(read_digest)) == 0;
}

bool RuleStore::commit() {
  int slot = _active_slot == 0 ? 1 : 0;
  mesh::Utils::sha256(_candidate.digest, sizeof(_candidate.digest),
                      reinterpret_cast<const uint8_t*>(&_candidate), offsetof(Snapshot, digest));
  uint8_t digest[sizeof(_candidate.digest)];
  memcpy(digest, _candidate.digest, sizeof(digest));
  if (!removeIfPresent(_fs, Pending)) return false;
  auto file = openWrite(_fs, Pending);
  if (!file) return false;
  bool written = file.write(reinterpret_cast<const uint8_t*>(&_candidate), sizeof(_candidate))
              == sizeof(_candidate);
  file.close();
  if (!written || !verifyCandidate(Pending, digest) || !ensureMarker(_fs, Provisioned)) return false;
  if (!removeIfPresent(_fs, Seals[slot]) || !removeIfPresent(_fs, Files[slot])
      || !_fs->rename(Pending, Files[slot]) || !verifyCandidate(Files[slot], digest)
      || !commitSeal(_fs, Seals[slot], decodeRevision(_candidate.revision))) return false;

  _state = _candidate;
  _active_slot = slot;
  _invalid_slots &= ~(1 << slot);
  return true;
}

void RuleStore::handleRecoveryCommand(const char* command, char* reply) {
  const char* arg;
  if (savemesh::matchesValue(command, "recovery")) {
    snprintf(reply, 150, "storage=%s forwarding=%s last=%lu", _ready ? "ready" : "recovery",
             forwardingAllowed() ? "available" : "held",
             static_cast<unsigned long>(decodeRevision(_state.revision)));
  } else if (savemesh::matchesValue(command, "resume")) {
    if (!_ready || !_forwarding_hold || !_fs->remove(ForwardingHold)) {
      strcpy(reply, "Err - no recoverable forwarding hold");
      return;
    }
    _forwarding_hold = false;
    strcpy(reply, "OK");
  } else if (savemesh::matchCommand(command, "recover", &arg)) {
    if (_ready) {
      strcpy(reply, "Err - policy storage is ready");
      return;
    }
    bool empty = savemesh::matchesValue(arg, "empty");
    uint32_t revision = decodeRevision(_state.revision);
    char expected[11];
    snprintf(expected, sizeof(expected), "%lu", static_cast<unsigned long>(revision));
    if (!empty && (_active_slot < 0 || !savemesh::matchesValue(arg, expected))) {
      strcpy(reply, "Err - confirm with rules recover <last-revision> or rules recover empty");
      return;
    }
    if (revision == UINT32_MAX || !ensureMarker(_fs, ForwardingHold)) {
      strcpy(reply, "Err - unable to hold forwarding");
      return;
    }
    _forwarding_hold = true;

    _candidate = empty ? Snapshot{} : _state;
    memcpy(_candidate.magic, Magic, sizeof(Magic));
    encodeRevision(_candidate.revision, revision + 1);
    if (!commit()) {
      strcpy(reply, "Err - policy recovery write failed");
      return;
    }
    int other_slot = 1 - _active_slot;
    if ((_invalid_slots & (1 << other_slot))
        && (!removeIfPresent(_fs, Seals[other_slot]) || !removeIfPresent(_fs, Files[other_slot]))) {
      strcpy(reply, "Err - corrupt policy slot could not be cleared");
      return;
    }
    _invalid_slots = 0;
    _ready = true;
    strcpy(reply, "OK - review policy before rules resume");
  }
}

bool RuleStore::setNeighbourChannel(const uint8_t* key) {
  if (!_ready || decodeRevision(_state.revision) == UINT32_MAX) return false;
  if (memcmp(_state.neighbour_channel, key, ChannelKeySize) == 0) return true;
  _candidate = _state;
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  memcpy(_candidate.neighbour_channel, key, ChannelKeySize);
  return commit();
}

bool RuleStore::setSyncKey(const uint8_t* key) {
  if (!_ready || decodeRevision(_state.revision) == UINT32_MAX) return false;
  if (memcmp(_state.sync_key, key, CIPHER_KEY_SIZE) == 0) return true;
  _candidate = _state;
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  memcpy(_candidate.sync_key, key, CIPHER_KEY_SIZE);
  return commit();
}

bool RuleStore::loadRoomIdentity(mesh::LocalIdentity& identity) const {
  if (!_ready) return false;
  const uint8_t empty[sizeof(_state.room_identity)]{};
  if (memcmp(_state.room_identity, empty, sizeof(empty)) == 0) return false;
  identity.readFrom(_state.room_identity, sizeof(_state.room_identity));
  uint8_t signature[SIGNATURE_SIZE];
  identity.sign(signature, Magic, sizeof(Magic));
  return identity.verify(signature, Magic, sizeof(Magic));
}

bool RuleStore::saveRoomIdentity(mesh::LocalIdentity& identity) {
  if (!_ready || decodeRevision(_state.revision) == UINT32_MAX) return false;
  const uint8_t empty[sizeof(_state.room_identity)]{};
  if (memcmp(_state.room_identity, empty, sizeof(empty)) != 0) return false;
  _candidate = _state;
  identity.writeTo(_candidate.room_identity, sizeof(_candidate.room_identity));
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  return commit();
}

bool RuleStore::setRoomEnabled(bool enabled) {
  if (!_ready || decodeRevision(_state.revision) == UINT32_MAX) return false;
  if (_state.room_enabled == enabled) return true;
  _candidate = _state;
  _candidate.room_enabled = enabled;
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  return commit();
}

bool RuleStore::setRoomName(const char* name) {
  if (!_ready || strlen(name) >= sizeof(_state.room_name)
      || decodeRevision(_state.revision) == UINT32_MAX) return false;
  if (strcmp(_state.room_name, name) == 0) return true;
  _candidate = _state;
  memset(_candidate.room_name, 0, sizeof(_candidate.room_name));
  strcpy(_candidate.room_name, name);
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  return commit();
}

const char* RuleStore::scopeName(Scope scope) const {
  return scope == Global ? _state.domain : _state.region;
}

bool RuleStore::setScope(Scope scope, const char* name) {
  if (!_ready || decodeRevision(_state.revision) == UINT32_MAX) return false;
  size_t length = strlen(name);
  if (!length || length >= ScopeNameSize) return false;
  for (size_t i = 0; i < length; i++) {
    char c = name[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  }
  if (strcmp(scopeName(scope), name) == 0) return true;
  for (size_t i = 0; i < _state.count; i++) {
    uint8_t rule_scope = _state.rules[i].scope;
    if (rule_scope == scope || (scope == Global && rule_scope == Region)) return false;
  }
  _candidate = _state;
  char* field = scope == Global ? _candidate.domain : _candidate.region;
  memset(field, 0, ScopeNameSize);
  memcpy(field, name, length);
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  return commit();
}

bool RuleStore::trustedPeer(const uint8_t* key) const {
  const uint8_t empty[PUB_KEY_SIZE]{};
  if (memcmp(key, empty, sizeof(empty)) == 0) return false;
  for (const auto& peer : _state.trusted_peers) {
    if (memcmp(peer, key, PUB_KEY_SIZE) == 0) return true;
  }
  return false;
}

bool RuleStore::setTrustedPeer(const uint8_t* key, bool trust, const mesh::Identity& node) {
  const uint8_t empty[PUB_KEY_SIZE]{};
  if (!_ready || decodeRevision(_state.revision) == UINT32_MAX
      || node.matches(key) || memcmp(key, empty, sizeof(empty)) == 0) return false;
  if (trustedPeer(key) == trust) return true;
  _candidate = _state;
  for (auto& peer : _candidate.trusted_peers) {
    if (memcmp(peer, trust ? empty : key, PUB_KEY_SIZE) != 0) continue;
    memcpy(peer, trust ? empty : key, PUB_KEY_SIZE);
    encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
    return commit();
  }
  return false;
}

const RuleStore::Rule* RuleStore::exportRule(size_t index) const {
  if (!_ready || index >= _state.count) return nullptr;
  const auto& rule = _state.rules[index];
  if (rule.scope == Local) return nullptr;
  return &rule;
}

RuleStore::MergeResult RuleStore::mergeRule(Rule& rule, const uint8_t* fingerprint,
                                          const mesh::Identity& node) {
  if (!_ready || !_state.domain[0] || rule.scope == Local || !validRule(rule)
      || (rule.scope == Region && !_state.region[0])) return Rejected;
  bool verified = false;
  uint8_t signed_bytes[SignedSize];
  const uint8_t empty[PUB_KEY_SIZE]{};
  for (const auto& peer : _state.trusted_peers) {
    if (memcmp(peer, empty, sizeof(empty)) == 0 || node.matches(peer)
        || memcmp(peer, fingerprint, FingerprintSize) != 0
        || decide(Repeater, peer) == Denied) continue;
    memcpy(rule.origin, peer, PUB_KEY_SIZE);
    signableBytes(_state, rule, signed_bytes);
    if (mesh::Identity(peer).verify(rule.signature, signed_bytes, sizeof(signed_bytes))) {
      verified = true;
      break;
    }
  }
  if (!verified) return Rejected;

  size_t index = 0;
  for (; index < _state.count; index++) {
    const auto& active = _state.rules[index];
    if (memcmp(active.id, rule.id, IdSize) != 0) continue;
    if (active.scope != rule.scope || memcmp(active.origin, rule.origin, PUB_KEY_SIZE) != 0) return Rejected;
    if (active.deleted || decodeRevision(rule.revision) <= decodeRevision(active.revision)) return Current;
    if (!rule.deleted || active.kind != rule.kind || active.subject != rule.subject
        || active.value != rule.value || memcmp(active.subject_key, rule.subject_key, PUB_KEY_SIZE) != 0) {
      return Rejected;
    }
    break;
  }
  if (index == Capacity || decodeRevision(_state.revision) == UINT32_MAX) return Rejected;
  _candidate = _state;
  if (index == _candidate.count) ++_candidate.count;
  _candidate.rules[index] = rule;
  encodeRevision(_candidate.revision, decodeRevision(_state.revision) + 1);
  return commit() ? Changed : Rejected;
}

RuleStore::Decision RuleStore::decide(Subject subject, const uint8_t* key) const {
  Decision decision = Unknown;
  for (size_t i = 0; i < _state.count; i++) {
    const auto& rule = _state.rules[i];
    if (rule.deleted || rule.kind == Filter || memcmp(rule.subject_key, key, PUB_KEY_SIZE) != 0) continue;
    // A signer can supply a different advertised role with the same key.
    if (rule.kind == Deny) return Denied;
    if (rule.subject == subject || subject == AnyDevice) decision = Allowed;
  }
  return decision;
}

bool RuleStore::filterEnabled(Subject subject) const {
  const Rule* latest = nullptr;
  for (size_t i = 0; i < _state.count; i++) {
    const auto& rule = _state.rules[i];
    if (rule.deleted || rule.kind != Filter || rule.subject != subject) continue;
    if (!latest || rule.scope < latest->scope
        || (rule.scope == latest->scope
            && (decodeRevision(rule.revision) > decodeRevision(latest->revision)
                || (decodeRevision(rule.revision) == decodeRevision(latest->revision)
                    && memcmp(rule.origin, latest->origin, PUB_KEY_SIZE) > 0)))) latest = &rule;
  }
  return latest && latest->value;
}

uint16_t RuleStore::unknownRate() const {
  return static_cast<uint16_t>(_state.unknown_rate[0]) | static_cast<uint16_t>(_state.unknown_rate[1]) << 8;
}

int RuleStore::find(const char* id) const {
  size_t length = strcspn(id, " ");
  if (length < 8 || length > IdSize * 2 || !savemesh::isSpacesOnly(id + length)) return -1;
  int index = -1;
  for (size_t i = 0; i < _state.count; i++) {
    char hex[IdSize * 2 + 1];
    mesh::Utils::toHex(hex, _state.rules[i].id, IdSize);
    size_t j = 0;
    while (j < length && savemesh::lowerAscii(hex[j]) == savemesh::lowerAscii(id[j])) j++;
    if (j != length) continue;
    if (index >= 0) return -2;
    index = static_cast<int>(i);
  }
  return index;
}

void RuleStore::describe(size_t index, char* reply) const {
  const auto& rule = _state.rules[index];
  char id[IdSize * 2 + 1], value[PUB_KEY_SIZE * 2 + 1];
  mesh::Utils::toHex(id, rule.id, IdSize);
  if (rule.kind == Filter) {
    strcpy(value, rule.value ? "on" : "off");
  } else {
    mesh::Utils::toHex(value, rule.subject_key, PUB_KEY_SIZE);
  }
  const char* scope = rule.scope == Local ? "local" : rule.scope == Global ? "global:" : "region:";
  const char* name = rule.scope == Local ? "" : scopeName(static_cast<Scope>(rule.scope));
  snprintf(reply, 150, "next=%u %s %s %s %s %s%s", static_cast<unsigned>(index + 1), id,
           kindName(rule.kind), subjectName(rule.subject), value, scope, name);
}

const char* RuleStore::parseScope(const char* input, uint8_t& scope) const {
  while (*input == ' ') ++input;
  if (!*input || savemesh::matchesValue(input, "local")) {
    scope = Local;
  } else if (strncmp(input, "global:", 7) == 0 && _state.domain[0]
             && savemesh::matchesValue(input + 7, _state.domain)) {
    scope = Global;
  } else if (strncmp(input, "region:", 7) == 0 && _state.domain[0] && _state.region[0]
             && savemesh::matchesValue(input + 7, _state.region)) {
    scope = Region;
  } else {
    return "Err - use local or the configured global/region scope";
  }
  return nullptr;
}

void RuleStore::handleCommand(const char* command, char* reply, const mesh::LocalIdentity& node,
                              const mesh::Identity* issuer, uint32_t timestamp, mesh::RNG& rng,
                              bool can_write, bool can_publish, bool& sync_requested) {
  if (!_ready) {
    strcpy(reply, "Err - rule storage unavailable; use rules recovery over USB");
    return;
  }
  unsigned active = 0;
  for (size_t i = 0; i < _state.count; i++) active += !_state.rules[i].deleted;

  const char* arg;
  if (savemesh::matchesValue(command, "count")) {
    snprintf(reply, 150, "%u", active);
    return;
  }
  if (savemesh::matchesValue(command, "status")) {
    snprintf(reply, 150, "rev=%lu active=%u deleted=%u capacity=%u mode=%s rate=%u airtime=%u",
             static_cast<unsigned long>(decodeRevision(_state.revision)), active, _state.count - active,
             static_cast<unsigned>(Capacity), restricted() ? "restricted" : "open", unknownRate(),
             airtimeShare());
    return;
  }
  if (savemesh::matchCommand(command, "list", &arg)) {
    uint16_t cursor = 0;
    if (*arg && !savemesh::parseUnsigned(arg, &cursor)) {
      strcpy(reply, "Err - invalid cursor");
      return;
    }
    while (cursor < _state.count && _state.rules[cursor].deleted) cursor++;
    if (cursor < _state.count) describe(cursor, reply);
    else strcpy(reply, "End");
    return;
  }
  if (savemesh::matchCommand(command, "show", &arg)) {
    int index = find(arg);
    if (index >= 0 && !_state.rules[index].deleted) describe(index, reply);
    else strcpy(reply, index == -2 ? "Err - ID ambiguous" : "Err - no active rule");
    return;
  }
  TrafficTarget traffic{};
  uint16_t trafficLimit = 0;
  bool setTraffic = savemesh::matchCommand(command, "traffic", &arg);
  if (setTraffic) {
    if (!*arg) {
      strcpy(reply, "type 0..15; categories: group-text group-data direct-text discovery anonymous routing management other");
      return;
    }
    const char* action;
    if (!parseTrafficTarget(arg, traffic, &action)) {
      strcpy(reply, "Err - expected traffic type <0..15> or category <name>");
      return;
    }
    if (!*action) {
      describeTraffic(traffic, traffic.select(_state.traffic).get(), reply);
      return;
    }
    const char* rate;
    if (savemesh::matchesValue(action, "drop")) trafficLimit = forward_traffic::Drop;
    else if (!savemesh::matchesValue(action, "allow")
             && (!savemesh::matchCommand(action, "limit", &rate)
                 || !savemesh::parseUnsigned(rate, &trafficLimit) || !trafficLimit || trafficLimit > forward_traffic::MaxRate)) {
      strcpy(reply, "Err - use allow, drop or limit <1..600>");
      return;
    }
  }
  uint16_t airtimeShareValue = 0;
  const bool setAirtimeShare = savemesh::matchCommand(command, "airtime", &arg);
  if (setAirtimeShare) {
    if (!*arg) {
      snprintf(reply, 150, "airtime=%u", airtimeShare());
      return;
    }
    if (!savemesh::parseUnsigned(arg, &airtimeShareValue) || airtimeShareValue > 100) {
      strcpy(reply, "Err - use airtime <0..100>");
      return;
    }
  }
  if (!can_write) {
    strcpy(reply, "Err - write permission required");
    return;
  }

  uint32_t revision = decodeRevision(_state.revision);
  if (revision == UINT32_MAX) {
    strcpy(reply, "Err - revision exhausted");
    return;
  }
  _candidate = _state;
  if (issuer) {
    bool recorded = false;
    for (auto& writer : _candidate.remote_writers) {
      uint32_t last = decodeRevision(writer.timestamp);
      if (last != 0 && !issuer->matches(writer.key)) continue;
      if (timestamp <= last) {
        strcpy(reply, "Err - stale rule command");
        return;
      }
      memcpy(writer.key, issuer->pub_key, PUB_KEY_SIZE);
      encodeRevision(writer.timestamp, timestamp);
      recorded = true;
      break;
    }
    if (!recorded) {
      strcpy(reply, "Err - remote writer storage full");
      return;
    }
  }
  encodeRevision(_candidate.revision, revision + 1);
  Rule* changed = nullptr;
  if (setTraffic) {
    if (traffic.select(_state.traffic).get() == trafficLimit) {
      strcpy(reply, "OK");
      return;
    }
    traffic.set(_candidate.traffic, trafficLimit);
  } else if (setAirtimeShare) {
    if (airtimeShare() == airtimeShareValue) {
      strcpy(reply, "OK");
      return;
    }
    _candidate.airtime_share = static_cast<uint8_t>(airtimeShareValue);
  } else if (savemesh::matchCommand(command, "delete", &arg)) {
    int index = find(arg);
    if (index < 0) {
      strcpy(reply, index == -2 ? "Err - ID ambiguous" : "Err - unknown ID");
      return;
    }
    changed = &_candidate.rules[index];
    if (changed->deleted) {
      strcpy(reply, "OK - already deleted");
      return;
    }
    if (!node.matches(changed->origin)) {
      strcpy(reply, "Err - delete on the originating repeater");
      return;
    }
    changed->deleted = 1;
  } else if (savemesh::matchCommand(command, "mode", &arg)) {
    if (savemesh::matchesValue(arg, "restricted")) _candidate.restricted = 1;
    else if (savemesh::matchesValue(arg, "open")) _candidate.restricted = 0;
    else {
      strcpy(reply, "Err - use open or restricted");
      return;
    }
    if (_candidate.restricted == _state.restricted) {
      strcpy(reply, "OK");
      return;
    }
  } else if (savemesh::matchCommand(command, "rate", &arg)) {
    uint16_t limit;
    if (!savemesh::parseUnsigned(arg, &limit) || limit > 600) {
      strcpy(reply, "Err - expected 0..600 packets per minute");
      return;
    }
    if (limit == unknownRate()) {
      strcpy(reply, "OK");
      return;
    }
    _candidate.unknown_rate[0] = limit & 0xFF;
    _candidate.unknown_rate[1] = limit >> 8;
  } else if (savemesh::matchCommand(command, "add", &arg)) {
    if (_candidate.count == Capacity) {
      strcpy(reply, "Err - rule storage full");
      return;
    }
    const char* subject;
    const char* value;
    changed = &_candidate.rules[_candidate.count++];
    *changed = Rule{};
    if (savemesh::matchCommand(arg, "filter", &subject)) {
      changed->kind = Filter;
      if (savemesh::matchCommand(subject, "1byte", &value)) changed->subject = OneByte;
      else if (savemesh::matchCommand(subject, "data", &value)) changed->subject = Data;
      else if (savemesh::matchCommand(subject, "public", &value)) changed->subject = Public;
      else {
        strcpy(reply, "Err - invalid filter");
        return;
      }
      const char* scope;
      if (savemesh::matchCommand(value, "on", &scope)) changed->value = 1;
      else if (!savemesh::matchCommand(value, "off", &scope)) {
        strcpy(reply, "Err - use on or off");
        return;
      }
      if (const char* error = parseScope(scope, changed->scope)) {
        strcpy(reply, error);
        return;
      }
    } else {
      if (savemesh::matchCommand(arg, "allow", &subject)) changed->kind = Allow;
      else if (savemesh::matchCommand(arg, "deny", &subject)) changed->kind = Deny;
      else {
        strcpy(reply, "Err - invalid rule kind");
        return;
      }
      if (savemesh::matchCommand(subject, "client", &value)) changed->subject = Client;
      else if (savemesh::matchCommand(subject, "repeater", &value)) changed->subject = Repeater;
      else {
        strcpy(reply, "Err - invalid subject");
        return;
      }
      if (!decodeKey(value, changed->subject_key)) {
        strcpy(reply, "Err - expected full public key");
        return;
      }
      if (const char* error = parseScope(value + PUB_KEY_SIZE * 2, changed->scope)) {
        strcpy(reply, error);
        return;
      }
    }
    rng.random(changed->id, IdSize);
    for (size_t i = 0; i < _state.count; i++) {
      if (memcmp(changed->id, _state.rules[i].id, IdSize) == 0) {
        strcpy(reply, "Err - ID collision, retry");
        return;
      }
    }
  } else {
    strcpy(reply, "Err - use rules count/list/show/add/delete/status/mode/rate/traffic/airtime");
    return;
  }

  if (changed) {
    if (changed->scope != Local && !can_publish) {
      strcpy(reply, "Err - admin permission required for shared rules");
      return;
    }
    memcpy(changed->issuer, issuer ? issuer->pub_key : node.pub_key, PUB_KEY_SIZE);
    memcpy(changed->origin, node.pub_key, PUB_KEY_SIZE);
    encodeRevision(changed->revision, revision + 1);
    uint8_t signed_bytes[SignedSize];
    signableBytes(_candidate, *changed, signed_bytes);
    node.sign(changed->signature, signed_bytes, sizeof(signed_bytes));
  }
  if (!commit()) {
    strcpy(reply, "Err - rule storage write failed");
    return;
  }
  sync_requested = changed && changed->scope != Local;
  if (changed && !changed->deleted) {
    strcpy(reply, "OK ");
    mesh::Utils::toHex(reply + 3, changed->id, IdSize);
  } else {
    strcpy(reply, "OK");
  }
}
