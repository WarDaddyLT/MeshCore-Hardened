#pragma once

#include <Packet.h>

namespace receive_work {

inline bool hasCiphertext(size_t length, size_t prefix) {
  return length > prefix + CIPHER_MAC_SIZE
      && (length - prefix - CIPHER_MAC_SIZE) % CIPHER_BLOCK_SIZE == 0;
}

inline bool validFrame(const mesh::Packet& packet) {
  const size_t length = packet.payload_len;
  switch (packet.getPayloadType()) {
    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_TXT_MSG:
    case PAYLOAD_TYPE_PATH:
      return hasCiphertext(length, 2);
    case PAYLOAD_TYPE_ANON_REQ:
      return hasCiphertext(length, 1 + PUB_KEY_SIZE);
    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA:
      return hasCiphertext(length, 1);
    case PAYLOAD_TYPE_ACK:
      return length >= sizeof(uint32_t);
    case PAYLOAD_TYPE_ADVERT:
      return length >= PUB_KEY_SIZE + sizeof(uint32_t) + SIGNATURE_SIZE
          && length <= PUB_KEY_SIZE + sizeof(uint32_t) + SIGNATURE_SIZE + MAX_ADVERT_DATA_SIZE;
    case PAYLOAD_TYPE_TRACE:
      return packet.isRouteDirect() && packet.path_len < MAX_PATH_SIZE && length >= 9
          && (length - 9) % (1U << (packet.payload[8] & 3)) == 0;
    case PAYLOAD_TYPE_MULTIPART:
      return length >= 5 && (packet.payload[0] & 0x0f) == PAYLOAD_TYPE_ACK;
    case PAYLOAD_TYPE_CONTROL:
      return length > 0;
    default:
      return true;
  }
}

class Budget {
  const uint32_t _interval;
  const uint32_t _capacity;
  uint32_t _credit;
  uint32_t _last = 0;

public:
  uint32_t attempts = 0;
  uint32_t drops = 0;

  Budget(uint32_t interval, unsigned burst)
    : _interval(interval), _capacity(interval * burst), _credit(_capacity) {}

  bool admit(uint32_t now) {
    const uint32_t elapsed = now - _last;
    const uint32_t available = _capacity - _credit;
    _credit += elapsed < available ? elapsed : available;
    _last = now;
    if (_credit < _interval) {
      ++drops;
      return false;
    }
    _credit -= _interval;
    ++attempts;
    return true;
  }
};

}
