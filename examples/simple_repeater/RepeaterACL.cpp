#include "RepeaterACL.h"
#include <Utils.h>
#include <stddef.h>

namespace {
constexpr const char* Slots[] = {"/hacl_a", "/hacl_b"};
constexpr const char* PendingFile = "/hacl_tmp";
constexpr uint8_t Magic[] = {'H', 'A', 'C', '1'};
static_assert(MAX_CLIENTS <= UINT8_MAX, "ACL count must fit in a byte");
}

uint32_t RepeaterACL::candidateRevision() const {
  uint32_t revision = 0;
  for (unsigned i = 0; i < sizeof(_candidate.revision); ++i) {
    revision |= uint32_t(_candidate.revision[i]) << (8 * i);
  }
  return revision;
}

bool RepeaterACL::readCandidate(const char* path) {
#if defined(RP2040_PLATFORM)
  File file = _fs->open(path, "r");
#else
  File file = _fs->open(path);
#endif
  if (!file) return false;
  bool complete = file.size() == sizeof(_candidate)
      && file.read(reinterpret_cast<uint8_t*>(&_candidate), sizeof(_candidate)) == sizeof(_candidate);
  file.close();
  if (!complete || memcmp(_candidate.magic, Magic, sizeof(Magic)) != 0
      || !candidateRevision() || _candidate.count > MAX_CLIENTS) return false;

  uint8_t digest[sizeof(_candidate.digest)];
  mesh::Utils::sha256(digest, sizeof(digest), reinterpret_cast<const uint8_t*>(&_candidate),
                      offsetof(Snapshot, digest));
  return memcmp(digest, _candidate.digest, sizeof(digest)) == 0;
}

void RepeaterACL::begin(FILESYSTEM* fs, const mesh::LocalIdentity& self_id) {
  _fs = fs;
  for (int slot = 0; slot < 2; ++slot) {
    if (!_fs->exists(Slots[slot])) continue;
    if (!readCandidate(Slots[slot])) {
      _invalid_slots |= 1 << slot;
    } else if (candidateRevision() > _revision) {
      _revision = candidateRevision();
      _active_slot = slot;
    }
  }

  // Never fall back to older grants when a committed ACL cannot be read.
  if (needsRecovery()) return;
  if (_active_slot < 0) {
    ClientACL::load(_fs, self_id);
    return;
  }
  if (!readCandidate(Slots[_active_slot])) {
    _invalid_slots |= 1 << _active_slot;
    return;
  }
  for (unsigned i = 0; i < _candidate.count; ++i) {
    const Entry& entry = _candidate.entries[i];
    ClientACL::applyPermissions(self_id, entry.key, PUB_KEY_SIZE, entry.permissions);
  }
}

bool RepeaterACL::commitCandidate() {
  mesh::Utils::sha256(_candidate.digest, sizeof(_candidate.digest),
                      reinterpret_cast<const uint8_t*>(&_candidate), offsetof(Snapshot, digest));
  uint8_t digest[sizeof(_candidate.digest)];
  memcpy(digest, _candidate.digest, sizeof(digest));
  if (_fs->exists(PendingFile) && !_fs->remove(PendingFile)) return false;
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  File file = _fs->open(PendingFile, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  File file = _fs->open(PendingFile, "w");
#else
  File file = _fs->open(PendingFile, "w", true);
#endif
  if (!file) return false;
  bool complete = file.write(reinterpret_cast<const uint8_t*>(&_candidate), sizeof(_candidate)) == sizeof(_candidate);
  file.close();
  if (!complete || !readCandidate(PendingFile) || memcmp(digest, _candidate.digest, sizeof(digest)) != 0) {
    return false;
  }

  int slot = _active_slot == 0 ? 1 : 0;
  if (_fs->exists(Slots[slot]) && !_fs->remove(Slots[slot])) return false;
  if (!_fs->rename(PendingFile, Slots[slot]) || !readCandidate(Slots[slot])
      || memcmp(digest, _candidate.digest, sizeof(digest)) != 0) return false;
  int other_slot = 1 - slot;
  if ((_invalid_slots & (1 << other_slot)) && !_fs->remove(Slots[other_slot])) return false;
  _invalid_slots = 0;
  _active_slot = slot;
  _revision = candidateRevision();
  return true;
}

bool RepeaterACL::updatePermissions(const mesh::LocalIdentity& self_id, const uint8_t* pubkey, int key_len,
                                    uint8_t permissions) {
  if (key_len <= 0 || key_len > PUB_KEY_SIZE) return false;
  bool removing = (permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST;
  const ClientInfo* target = getClient(pubkey, key_len);
  if ((removing && !target) || (!removing && key_len != PUB_KEY_SIZE) || _revision == UINT32_MAX) return false;
  if (target && ((removing && (target->permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST)
                 || target->permissions == permissions)) {
    return removing ? ClientACL::applyPermissions(self_id, pubkey, key_len, permissions) : true;
  }

  _candidate = {};
  memcpy(_candidate.magic, Magic, sizeof(Magic));
  uint32_t revision = _revision + 1;
  for (unsigned i = 0; i < sizeof(_candidate.revision); ++i) {
    _candidate.revision[i] = uint8_t(revision >> (8 * i));
  }

  for (int i = 0; i < getNumClients(); ++i) {
    const ClientInfo* client = getClientByIdx(i);
    if (client == target || (client->permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST) continue;
    Entry& entry = _candidate.entries[_candidate.count++];
    memcpy(entry.key, client->id.pub_key, PUB_KEY_SIZE);
    entry.permissions = client->permissions;
  }
  if (!removing) {
    if (_candidate.count == MAX_CLIENTS) return false;
    Entry& entry = _candidate.entries[_candidate.count++];
    memcpy(entry.key, pubkey, PUB_KEY_SIZE);
    entry.permissions = permissions;
  }

  if (!commitCandidate()) return false;
  return ClientACL::applyPermissions(self_id, pubkey, key_len, permissions, true);
}
