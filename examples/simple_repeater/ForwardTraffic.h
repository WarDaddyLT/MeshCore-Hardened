#pragma once

#include <Packet.h>

namespace forward_traffic {

constexpr unsigned TypeCount = 16;
constexpr uint16_t Drop = UINT16_MAX;
constexpr uint16_t MaxRate = 600;
constexpr uint8_t DefaultAirtimeShare = 25;
constexpr unsigned MaxQueuedPerCategory = 4;
constexpr int ReservedFreePackets = 3;

inline bool recentSignedStamp(uint32_t stamp, uint32_t now) {
  return stamp && (stamp <= now ? now - stamp <= 60 : stamp - now <= 15);
}

enum Category : uint8_t { GroupText, GroupData, DirectText, Discovery, Anonymous, Routing, Management, Other, CategoryCount };

constexpr const char* CategoryNames[] = {
  "group-text", "group-data", "direct-text", "discovery", "anonymous", "routing", "management", "other"
};
static_assert(sizeof(CategoryNames) / sizeof(CategoryNames[0]) == CategoryCount, "Name each forwarding category");

inline Category categoryFor(uint8_t type) {
  switch (type) {
    case PAYLOAD_TYPE_GRP_TXT: return GroupText;
    case PAYLOAD_TYPE_GRP_DATA: return GroupData;
    case PAYLOAD_TYPE_TXT_MSG: return DirectText;
    case PAYLOAD_TYPE_ADVERT:
    case PAYLOAD_TYPE_TRACE: return Discovery;
    case PAYLOAD_TYPE_ANON_REQ: return Anonymous;
    case PAYLOAD_TYPE_ACK:
    case PAYLOAD_TYPE_PATH:
    case PAYLOAD_TYPE_MULTIPART: return Routing;
    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_CONTROL: return Management;
    default: return Other;
  }
}

struct Limit {
  uint8_t bytes[2];

  uint16_t get() const { return uint16_t(bytes[0]) | uint16_t(bytes[1]) << 8; }
  void set(uint16_t value) {
    bytes[0] = uint8_t(value);
    bytes[1] = uint8_t(value >> 8);
  }
  bool valid() const { return get() <= MaxRate || get() == Drop; }
};

struct Policy {
  Limit types[TypeCount];
  Limit categories[CategoryCount];

  bool valid() const {
    for (const auto& type : types) if (!type.valid()) return false;
    for (const auto& category : categories) if (!category.valid()) return false;
    return true;
  }

  bool drops(uint8_t type) const {
    return types[type].get() == Drop || categories[categoryFor(type)].get() == Drop;
  }
};

struct Budget {
  uint32_t windowStart = 0;
  uint16_t types[TypeCount]{};
  uint16_t categories[CategoryCount]{};

  bool admit(uint8_t type, const Policy& policy, uint16_t legacyRate, uint32_t now) {
    const auto category = categoryFor(type);
    const uint16_t typeRate = policy.types[type].get();
    const uint16_t categoryRate = policy.categories[category].get();
    if (category != GroupText && category != GroupData && category != Anonymous) legacyRate = 0;
    if (!typeRate && !categoryRate && !legacyRate) return true;

    if (now - windowStart >= 60000) {
      *this = {};
      windowStart = now;
    }
    if ((typeRate && types[type] >= typeRate) || (categoryRate && categories[category] >= categoryRate)
        || (legacyRate && categories[category] >= legacyRate)) return false;

    if (typeRate) ++types[type];
    if (categoryRate || legacyRate) ++categories[category];
    return true;
  }
};

// Credit is measured in thousandths of a millisecond of estimated airtime.
struct AirtimeBudget {
  uint32_t lastUpdate = 0;
  uint32_t credit = 0;
  bool started = false;

  bool admit(uint32_t now, uint32_t airtime, uint32_t maxFrameAirtime, unsigned refillPerMs) {
    constexpr uint32_t Scale = 1000;
    const uint32_t capacity = 2 * Scale * maxFrameAirtime;
    const uint64_t available = started
        ? credit + uint64_t(now - lastUpdate) * refillPerMs
        : capacity;
    started = true;
    lastUpdate = now;
    credit = available < capacity ? static_cast<uint32_t>(available) : capacity;
    const uint32_t cost = airtime * Scale;
    if (cost > credit) return false;
    credit -= cost;
    return true;
  }
};

}
