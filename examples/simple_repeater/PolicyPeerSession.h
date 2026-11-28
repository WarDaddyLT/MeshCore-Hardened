#pragma once

#include <Identity.h>

class PolicyPeerSession {
public:
  enum class Context : uint8_t { Domain, Subnet };
  enum class Type : uint8_t { Challenge = 0xA4, Response, Confirm };
  static constexpr size_t NonceSize = 16;
  static constexpr size_t ContextNameSize = 16;

  struct Frame {
    Type type;
    Context context;
    uint8_t source[PUB_KEY_SIZE];
    uint8_t target[PUB_KEY_SIZE];
    uint8_t challenge[NonceSize];
    uint8_t response[NonceSize];
    uint8_t signature[SIGNATURE_SIZE];
  };
  static_assert(sizeof(Frame) == 2 + 2 * PUB_KEY_SIZE + 2 * NonceSize + SIGNATURE_SIZE,
                "Peer frame layout has unexpected padding");

  static bool isHandshake(uint8_t type);
  bool free() const { return _state == Idle; }
  bool active() const { return _state == Active; }
  Context context() const { return _context; }
  const uint8_t* peer() const { return _peer; }
  const uint8_t* transmitKey() const { return _transmit_key; }
  const uint8_t* receiveKey() const { return _receive_key; }
  uint32_t nextTransmitSequence() const { return _transmit_sequence + 1; }
  bool canReceiveSequence(uint32_t sequence) const { return sequence > _receive_sequence; }
  void markTransmitted(uint32_t sequence) { _transmit_sequence = sequence; }
  void markReceived(uint32_t sequence) { _receive_sequence = sequence; }

  void reset();
  void expire(uint32_t now);
  bool start(const uint8_t* peer, Context context, const uint8_t* nonce, uint32_t now);
  bool accept(const Frame& frame, const char* context_name, const uint8_t* sync_key, const mesh::LocalIdentity& local,
              uint32_t now);
  void setResponseNonce(const uint8_t* nonce);
  bool prepare(Frame& frame, const char* context_name, const uint8_t* sync_key, const mesh::LocalIdentity& local) const;
  void markHandshakeSent(uint32_t now);

private:
  enum State : uint8_t { Idle, SendChallenge, AwaitResponse, NeedResponseNonce, SendResponse, AwaitConfirm, SendConfirm, Active };
  State _state = Idle;
  Context _context = Context::Domain;
  uint8_t _peer[PUB_KEY_SIZE]{};
  uint8_t _challenge[NonceSize]{};
  uint8_t _response[NonceSize]{};
  uint8_t _transmit_key[CIPHER_KEY_SIZE]{};
  uint8_t _receive_key[CIPHER_KEY_SIZE]{};
  uint32_t _deadline = 0;
  uint32_t _transmit_sequence = 0;
  uint32_t _receive_sequence = 0;

  bool deriveKeys(const mesh::LocalIdentity& local, const char* context_name, const uint8_t* sync_key);
};
