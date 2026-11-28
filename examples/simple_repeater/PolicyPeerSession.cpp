#include "PolicyPeerSession.h"
#include <SHA256.h>

namespace {
constexpr uint32_t HandshakeMillis = 4 * 60 * 1000;
constexpr uint32_t SessionMillis = 60 * 60 * 1000;
constexpr char SigningDomain[] = "MeshCore Hardened peer proof v1";
constexpr char KeyDomain[] = "MeshCore Hardened peer traffic v1";
constexpr size_t ProofSize = offsetof(PolicyPeerSession::Frame, signature);
constexpr size_t SignedSize = sizeof(SigningDomain) + PolicyPeerSession::ContextNameSize + ProofSize + CIPHER_KEY_SIZE;

void proofBytes(const PolicyPeerSession::Frame& frame, const char* name, const uint8_t* sync_key,
                uint8_t (&out)[SignedSize]) {
  memcpy(out, SigningDomain, sizeof(SigningDomain));
  auto* context = out + sizeof(SigningDomain);
  memset(context, 0, PolicyPeerSession::ContextNameSize);
  memcpy(context, name, strnlen(name, PolicyPeerSession::ContextNameSize));
  memcpy(out + sizeof(SigningDomain) + PolicyPeerSession::ContextNameSize, &frame, ProofSize);
  memcpy(out + SignedSize - CIPHER_KEY_SIZE, sync_key, CIPHER_KEY_SIZE);
}

void wipe(uint8_t* value, size_t size) {
  volatile uint8_t* bytes = value;
  while (size--) *bytes++ = 0;
}
}

bool PolicyPeerSession::isHandshake(uint8_t type) {
  return type >= static_cast<uint8_t>(Type::Challenge) && type <= static_cast<uint8_t>(Type::Confirm);
}

void PolicyPeerSession::reset() {
  wipe(_transmit_key, sizeof(_transmit_key));
  wipe(_receive_key, sizeof(_receive_key));
  _state = Idle;
}

void PolicyPeerSession::expire(uint32_t now) {
  if (!free() && static_cast<int32_t>(now - _deadline) >= 0) reset();
}

bool PolicyPeerSession::start(const uint8_t* peer, Context context, const uint8_t* nonce, uint32_t now) {
  if (!free() || !nonce) return false;
  memcpy(_peer, peer, PUB_KEY_SIZE);
  _context = context;
  memcpy(_challenge, nonce, sizeof(_challenge));
  memset(_response, 0, sizeof(_response));
  _deadline = now + HandshakeMillis;
  _state = SendChallenge;
  return true;
}

bool PolicyPeerSession::prepare(Frame& frame, const char* name, const uint8_t* sync_key,
                                const mesh::LocalIdentity& local) const {
  switch (_state) {
    case SendChallenge: frame.type = Type::Challenge; break;
    case SendResponse: frame.type = Type::Response; break;
    case SendConfirm: frame.type = Type::Confirm; break;
    default: return false;
  }
  frame.context = _context;
  memcpy(frame.source, local.pub_key, PUB_KEY_SIZE);
  memcpy(frame.target, _peer, PUB_KEY_SIZE);
  memcpy(frame.challenge, _challenge, sizeof(_challenge));
  memcpy(frame.response, _response, sizeof(_response));
  uint8_t bytes[SignedSize];
  proofBytes(frame, name, sync_key, bytes);
  local.sign(frame.signature, bytes, sizeof(bytes));
  wipe(bytes, sizeof(bytes));
  return true;
}

void PolicyPeerSession::markHandshakeSent(uint32_t now) {
  if (_state == SendChallenge) _state = AwaitResponse;
  else if (_state == SendResponse) _state = AwaitConfirm;
  else if (_state == SendConfirm) {
    _deadline = now + SessionMillis;
    _state = Active;
  }
}

bool PolicyPeerSession::accept(const Frame& frame, const char* name, const uint8_t* sync_key,
                               const mesh::LocalIdentity& local, uint32_t now) {
  expire(now);
  if (!isHandshake(static_cast<uint8_t>(frame.type))
      || (frame.context != Context::Domain && frame.context != Context::Subnet)
      || !local.matches(frame.target) || local.matches(frame.source) || active()) return false;
  if (!free() && (_context != frame.context || memcmp(_peer, frame.source, PUB_KEY_SIZE) != 0)) return false;
  if (frame.type == Type::Challenge) {
    const bool competing = _state == SendChallenge || _state == AwaitResponse;
    if ((!free() && (!competing || memcmp(local.pub_key, frame.source, PUB_KEY_SIZE) < 0))
        || !mesh::Utils::isZeroes(frame.response, NonceSize)) return false;
  } else {
    if (memcmp(frame.challenge, _challenge, NonceSize) != 0) return false;
    if (frame.type == Type::Response && _state != AwaitResponse) return false;
    if (frame.type == Type::Confirm && (_state != AwaitConfirm
        || memcmp(frame.response, _response, NonceSize) != 0)) return false;
  }

  uint8_t bytes[SignedSize];
  proofBytes(frame, name, sync_key, bytes);
  const bool verified = mesh::Identity(frame.source).verify(frame.signature, bytes, sizeof(bytes));
  wipe(bytes, sizeof(bytes));
  if (!verified) return false;

  if (frame.type == Type::Challenge) {
    memcpy(_peer, frame.source, PUB_KEY_SIZE);
    _context = frame.context;
    memcpy(_challenge, frame.challenge, sizeof(_challenge));
    _deadline = now + HandshakeMillis;
    _state = NeedResponseNonce;
    return true;
  }
  if (frame.type == Type::Response) memcpy(_response, frame.response, sizeof(_response));
  if (!deriveKeys(local, name, sync_key)) { reset(); return false; }
  if (frame.type == Type::Confirm) {
    _deadline = now + SessionMillis;
    _state = Active;
  } else {
    _state = SendConfirm;
  }
  return true;
}

void PolicyPeerSession::setResponseNonce(const uint8_t* nonce) {
  if (_state != NeedResponseNonce) return;
  memcpy(_response, nonce, sizeof(_response));
  _state = SendResponse;
}

bool PolicyPeerSession::deriveKeys(const mesh::LocalIdentity& local, const char* name, const uint8_t* sync_key) {
  uint8_t secret[PUB_KEY_SIZE];
  local.calcSharedSecret(secret, _peer);
  if (mesh::Utils::isZeroes(secret, sizeof(secret))) return false;
  const auto* initiator = _state == AwaitResponse ? local.pub_key : _peer;
  const auto* responder = _state == AwaitResponse ? _peer : local.pub_key;
  const auto context_byte = static_cast<uint8_t>(_context);
  uint8_t context[ContextNameSize]{};
  memcpy(context, name, strnlen(name, sizeof(context)));
  const auto derive = [&](const uint8_t* sender, uint8_t* key) {
    SHA256 sha;
    sha.resetHMAC(secret, sizeof(secret));
    sha.update(KeyDomain, sizeof(KeyDomain));
    sha.update(&context_byte, 1);
    sha.update(context, sizeof(context));
    sha.update(initiator, PUB_KEY_SIZE);
    sha.update(responder, PUB_KEY_SIZE);
    sha.update(_challenge, NonceSize);
    sha.update(_response, NonceSize);
    sha.update(sender, PUB_KEY_SIZE);
    sha.update(sync_key, CIPHER_KEY_SIZE);
    sha.finalizeHMAC(secret, sizeof(secret), key, CIPHER_KEY_SIZE);
  };
  derive(local.pub_key, _transmit_key);
  derive(_peer, _receive_key);
  wipe(secret, sizeof(secret));
  _transmit_sequence = 0;
  _receive_sequence = 0;
  return true;
}
