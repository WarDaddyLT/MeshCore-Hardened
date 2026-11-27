#pragma once

#include <helpers/ClientACL.h>

class RepeaterACL : public ClientACL {
  struct Entry {
    uint8_t key[PUB_KEY_SIZE];
    uint8_t permissions;
  };

  struct Snapshot {
    uint8_t magic[4];
    uint8_t revision[4];
    uint8_t count;
    Entry entries[MAX_CLIENTS];
    uint8_t digest[32];
  };

  FILESYSTEM* _fs = nullptr;
  Snapshot _candidate{};
  uint32_t _revision = 0;
  int _active_slot = -1;
  uint8_t _invalid_slots = 0;

  uint32_t candidateRevision() const;
  bool readCandidate(const char* path);
  bool commitCandidate();

public:
  void begin(FILESYSTEM* fs, const mesh::LocalIdentity& self_id);
  bool needsRecovery() const { return _invalid_slots != 0; }
  bool updatePermissions(const mesh::LocalIdentity& self_id, const uint8_t* pubkey, int key_len,
                         uint8_t permissions);
};
