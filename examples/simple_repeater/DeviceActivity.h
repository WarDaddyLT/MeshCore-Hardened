#pragma once

#include "RuleStore.h"

class DeviceActivity {
public:
  static constexpr uint8_t AdvertsPerMinute = 6;

  struct Stats {
    uint8_t observations;
    uint8_t limited;
  };

  // A timestamp is signed by the device. It can identify repeats in the
  // current cache, but never confers an allowance or an administrator role.
  template<typename IsEnrolled>
  bool admit(const uint8_t* key, bool enrolled, uint32_t stamp, uint32_t now, IsEnrolled isEnrolled) {
    if (!forward_traffic::recentSignedStamp(stamp, now)) return true;
    auto* entries = enrolled ? _enrolled : _other;
    const size_t capacity = enrolled ? RuleStore::Capacity : OtherCapacity;
    Entry* entry = find(entries, capacity, key);
    if (!entry) {
      for (size_t i = 0; i < capacity; ++i) {
        auto& candidate = entries[i];
        if (!candidate.stamp || (enrolled ? !isEnrolled(candidate.key)
                                         : !forward_traffic::recentSignedStamp(candidate.stamp, now))) {
          entry = &candidate;
          break;
        }
      }
      // Under cache pressure the ordinary category allowance still applies.
      if (!entry) return true;
      *entry = {};
      memcpy(entry->key, key, PUB_KEY_SIZE);
    }
    if (entry->stamp >= stamp) return false;
    if (entry->stamp / 60 != stamp / 60) entry->stats = {};
    entry->stamp = stamp;
    if (entry->stats.observations < UINT8_MAX) ++entry->stats.observations;
    if (entry->stats.observations <= AdvertsPerMinute) return true;
    if (entry->stats.limited < UINT8_MAX) ++entry->stats.limited;
    return false;
  }

  Stats stats(const uint8_t* key, bool enrolled, uint32_t now) const {
    const auto* entries = enrolled ? _enrolled : _other;
    auto* entry = find(entries, enrolled ? RuleStore::Capacity : OtherCapacity, key);
    return entry && forward_traffic::recentSignedStamp(entry->stamp, now) ? entry->stats : Stats{};
  }

private:
  struct Entry {
    uint8_t key[PUB_KEY_SIZE];
    uint32_t stamp;
    Stats stats;
  };

  static constexpr size_t OtherCapacity = 8;
  Entry _enrolled[RuleStore::Capacity]{};
  Entry _other[OtherCapacity]{};

  template<typename Row>
  static Row* find(Row* entries, size_t capacity, const uint8_t* key) {
    for (size_t i = 0; i < capacity; ++i) {
      if (entries[i].stamp && memcmp(entries[i].key, key, PUB_KEY_SIZE) == 0) return &entries[i];
    }
    return nullptr;
  }
};
