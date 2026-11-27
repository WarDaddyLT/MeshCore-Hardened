#pragma once

#include "ForwardTraffic.h"
#include <string.h>

namespace probation {

constexpr uint32_t DurationSeconds = 72 * 60 * 60;
constexpr size_t Capacity = 12;
constexpr uint8_t PerKeyPerMinute = 6;
constexpr uint8_t SharedPerMinute = 6;
constexpr uint32_t NewEntryCheckpoint = 60;
constexpr uint32_t ProgressCheckpoint = 15 * 60;

inline bool freshStamp(uint32_t stamp, uint32_t wallSeconds, uint64_t uptimeMs) {
  constexpr uint32_t UnsynchronizedEpoch = 1715770351;
  constexpr uint32_t EarliestValidWallTime = 1735689600;  // 2025-01-01 UTC
  return wallSeconds >= EarliestValidWallTime && wallSeconds > UnsynchronizedEpoch + uptimeMs / 1000
      && forward_traffic::recentSignedStamp(stamp, wallSeconds);
}

struct Seconds {
  uint8_t bytes[4];

  uint32_t get() const {
    return uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8
        | uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
  }

  void set(uint32_t value) {
    for (unsigned i = 0; i < sizeof(bytes); ++i) bytes[i] = uint8_t(value >> (i * 8));
  }
};

struct Entry {
  uint8_t key[PUB_KEY_SIZE];
  Seconds started;
  uint8_t subject;
};

struct Snapshot {
  Seconds elapsed;
  Entry entries[Capacity];

  bool valid() const {
    for (size_t i = 0; i < Capacity; ++i) {
      const auto& entry = entries[i];
      if (entry.subject > 2 || (entry.subject && entry.started.get() > elapsed.get())) return false;
      if (!entry.subject) continue;
      for (size_t j = 0; j < i; ++j) {
        if (entries[j].subject && memcmp(entries[j].key, entry.key, PUB_KEY_SIZE) == 0) return false;
      }
    }
    return true;
  }
};

class Ledger {
  struct Activity {
    uint32_t lastStamp = 0;
    uint32_t credit = 0;
    uint8_t candidates = 0;
    bool committed = false;
  };

  Snapshot _snapshot{};
  Activity _activity[Capacity];
  uint64_t _bootStart = 0;
  uint32_t _originSeconds = 0;
  uint32_t _nextSave = 0;
  uint32_t _sharedMinute = 0;
  uint8_t _sharedUsed = 0;
  bool _newEntry = false;

  uint32_t elapsed(uint64_t uptimeMs) const {
    const uint64_t seconds = _originSeconds + (uptimeMs - _bootStart) / 1000;
    return seconds < UINT32_MAX ? static_cast<uint32_t>(seconds) : UINT32_MAX;
  }

  size_t find(const uint8_t* key) const {
    for (size_t i = 0; i < Capacity; ++i) {
      if (_snapshot.entries[i].subject && memcmp(key, _snapshot.entries[i].key, PUB_KEY_SIZE) == 0) return i;
    }
    return Capacity;
  }

public:
  void begin(const Snapshot& stored, uint64_t uptimeMs = 0) {
    _snapshot = stored;
    _originSeconds = stored.elapsed.get();
    _bootStart = uptimeMs;
    _nextSave = 0;
    _sharedMinute = 0;
    _sharedUsed = 0;
    _newEntry = false;
    for (size_t i = 0; i < Capacity; ++i) {
      _activity[i] = {};
      _activity[i].committed = stored.entries[i].subject != 0;
    }
  }

  template<typename HasDecision>
  bool admit(const uint8_t* key, uint8_t subject, uint32_t stamp, uint32_t wallSeconds, uint64_t uptimeMs, bool transit,
             HasDecision hasDecision, bool canStart = true) {
    if (!freshStamp(stamp, wallSeconds, uptimeMs)) return false;

    const uint32_t now = elapsed(uptimeMs);
    size_t index = find(key);
    if (index == Capacity) {
      if (!canStart) return false;
      for (size_t i = 0; i < Capacity; ++i) {
        auto& entry = _snapshot.entries[i];
        if (entry.subject && !hasDecision(entry.key, entry.subject)) continue;
        index = i;
        memcpy(entry.key, key, PUB_KEY_SIZE);
        entry.started.set(now);
        entry.subject = subject;
        _activity[i] = {};
        _newEntry = true;
        break;
      }
      if (index == Capacity) return false;
    }

    auto& activity = _activity[index];
    if (stamp <= activity.lastStamp) return false;
    if (stamp / 60 != activity.lastStamp / 60) activity.candidates = 0;
    activity.lastStamp = stamp;
    if (!transit || !activity.committed || activity.candidates >= PerKeyPerMinute) return false;
    ++activity.candidates;

    const uint32_t age = now - _snapshot.entries[index].started.get();
    if (age >= DurationSeconds) return true;
    activity.credit += age;
    if (activity.credit < DurationSeconds) return false;
    // Consume the credit even when the shared quota is full.
    activity.credit -= DurationSeconds;
    if (now / 60 != _sharedMinute) {
      _sharedMinute = now / 60;
      _sharedUsed = 0;
    }
    if (_sharedUsed >= SharedPerMinute) return false;
    ++_sharedUsed;
    return true;
  }

  template<typename Save>
  void checkpoint(uint64_t uptimeMs, Save save) {
    const uint32_t now = elapsed(uptimeMs);
    const uint32_t savedAt = _snapshot.elapsed.get();
    if (now < _nextSave || now - savedAt < (_newEntry ? NewEntryCheckpoint : ProgressCheckpoint)) return;
    if (!_newEntry) {
      bool pending = false;
      for (const auto& entry : _snapshot.entries) {
        if (entry.subject && savedAt - entry.started.get() < DurationSeconds) pending = true;
      }
      if (!pending) return;
    }
    _nextSave = now + NewEntryCheckpoint;
    _snapshot.elapsed.set(now);
    if (save(_snapshot)) {
      for (size_t i = 0; i < Capacity; ++i) _activity[i].committed = _snapshot.entries[i].subject != 0;
      _newEntry = false;
    } else {
      _snapshot.elapsed.set(savedAt);
    }
  }

  int hoursRemaining(const uint8_t* key, uint64_t uptimeMs) const {
    const size_t index = find(key);
    if (index == Capacity) return -1;
    const uint32_t age = elapsed(uptimeMs) - _snapshot.entries[index].started.get();
    return age < DurationSeconds ? int((DurationSeconds - age + 3599) / 3600) : 0;
  }
};

}
