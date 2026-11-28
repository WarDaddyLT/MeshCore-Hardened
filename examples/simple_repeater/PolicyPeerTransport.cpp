#include "MyMesh.h"
#include <AES.h>
#include <GCM.h>

namespace {
using Context = PolicyPeerSession::Context;
using savemesh::matchCommand;
constexpr uint32_t PolicyIntervalMs = 60 * 1000;
static_assert(sizeof(PolicyPeerSession::Frame) <= MAX_PACKET_PAYLOAD, "Peer proof exceeds packet capacity");
constexpr char NonceDomain[] = "MeshCore Hardened peer nonce v1";
}

bool MyMesh::isPeerHandshake(const mesh::Packet& packet) {
  return packet.getPayloadType() == PAYLOAD_TYPE_CONTROL && packet.payload_len
      && PolicyPeerSession::isHandshake(packet.payload[0]);
}

const char* MyMesh::peerContextName(Context context) const {
  if (context == Context::Domain) return _rules.scopeName(RuleStore::Global);
  if (context == Context::Subnet) return _rules.scopeName(RuleStore::Subnet);
  return "";
}

bool MyMesh::peerPermitted(Context context, const uint8_t* key) const {
  if (!_rules.trustedPeer(key)) return false;
  const auto decision = _rules.decide(RuleStore::Repeater, key);
  return decision != RuleStore::Denied && (context == Context::Subnet
      || _rules.mode() != RuleStore::Locked || decision == RuleStore::Allowed);
}

bool MyMesh::nextPolicyPeerNonce(uint8_t* nonce) {
  if (!_peer_epoch) {
    if (_next_peer_epoch_attempt && !millisHasNowPassed(_next_peer_epoch_attempt)) return false;
    _next_peer_epoch_attempt = futureMillis(PolicyIntervalMs);
    _peer_epoch = _rules.reservePeerEpoch();
    if (!_peer_epoch) return false;
  }
  if (_peer_nonce_counter == UINT32_MAX) return false;
  const uint32_t counter = ++_peer_nonce_counter;
  uint8_t input[sizeof(NonceDomain) + 8];
  memcpy(input, NonceDomain, sizeof(NonceDomain));
  for (unsigned i = 0; i < 4; ++i) {
    input[sizeof(NonceDomain) + i] = _peer_epoch >> (8 * i);
    input[sizeof(NonceDomain) + 4 + i] = counter >> (8 * i);
  }
  uint8_t signature[SIGNATURE_SIZE];
  self_id.sign(signature, input, sizeof(input));
  memcpy(nonce, signature, PolicyPeerSession::NonceSize);
  return true;
}

PolicyPeerSession* MyMesh::findPolicyPeer(Context context, const uint8_t* key, bool allocate) {
  PolicyPeerSession* free = nullptr;
  for (auto& session : _policy_peers) {
    session.expire(millis());
    if (!session.free() && session.context() == context && memcmp(session.peer(), key, PUB_KEY_SIZE) == 0) {
      return &session;
    }
    if (session.free() && !free) free = &session;
  }
  return allocate ? free : nullptr;
}

void MyMesh::receivePeerHandshake(const mesh::Packet& packet) {
  if (!packet.received_over_radio || packet.getRouteType() != ROUTE_TYPE_DIRECT || packet.getPathHashCount()
      || packet.payload_len != sizeof(PolicyPeerSession::Frame) || !_rules.forwardingAllowed()
      || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)) return;
  PolicyPeerSession::Frame frame;
  memcpy(&frame, packet.payload, sizeof(frame));
  const auto* name = peerContextName(frame.context);
  if (!*name || !self_id.matches(frame.target) || !peerPermitted(frame.context, frame.source)
      || !_sync_work.admit(millis()) || getTables()->wasSeen(&packet)) return;
  const bool challenge = frame.type == PolicyPeerSession::Type::Challenge;
  auto* session = findPolicyPeer(frame.context, frame.source, challenge);
  if (!session || session->active() || !session->accept(frame, name, _rules.syncKey(), self_id, millis())) return;
  getTables()->markSeen(&packet);
  if (!challenge) {
    if (session->active()) policyPeerConnected(*session);
    return;
  }
  uint8_t nonce[PolicyPeerSession::NonceSize];
  if (nextPolicyPeerNonce(nonce)) session->setResponseNonce(nonce);
  else session->reset();
}

void MyMesh::servicePolicyPeers() {
  for (auto& session : _policy_peers) {
    if (session.free()) continue;
    session.expire(millis());
    if (session.free()) continue;
    if (!peerPermitted(session.context(), session.peer()) || !*peerContextName(session.context())) session.reset();
  }
  if (!_rules.forwardingAllowed() || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)
      || _mgr->getOutboundTotal() || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;

  for (auto& session : _policy_peers) {
    PolicyPeerSession::Frame frame;
    if (!session.prepare(frame, peerContextName(session.context()), _rules.syncKey(), self_id)) continue;
    auto* packet = createControlData(reinterpret_cast<const uint8_t*>(&frame), sizeof(frame));
    if (!packet) return;
    sendZeroHop(packet);
    session.markHandshakeSent(millis());
    if (session.active()) policyPeerConnected(session);
    _next_policy_tx = futureMillis(PolicyIntervalMs);
    return;
  }
}

bool MyMesh::handlePeerCommand(const char* command, char* reply, bool canWrite) {
  const char* args;
  if (!matchCommand(command, "peer", &args)) return false;
  if (!canWrite) { strcpy(reply, "Err - admin permission required"); return true; }
  const bool connect = matchCommand(args, "connect", &args);
  const bool disconnect = !connect && matchCommand(args, "disconnect", &args);
  if (!connect && !disconnect && !matchCommand(args, "status", &args)) {
    strcpy(reply, "Err - use rules peer connect|disconnect|status domain|subnet <key>");
    return true;
  }
  Context context;
  if (matchCommand(args, "domain", &args)) context = Context::Domain;
  else if (matchCommand(args, "subnet", &args)) context = Context::Subnet;
  else { strcpy(reply, "Err - use domain or subnet scope"); return true; }

  uint8_t key[PUB_KEY_SIZE];
  if (!savemesh::isHex(args, 2 * sizeof(key)) || !mesh::Utils::fromHex(key, sizeof(key), args)
      || !peerPermitted(context, key)) {
    strcpy(reply, "Err - expected an eligible full trusted peer key");
    return true;
  }
  auto* session = findPolicyPeer(context, key, connect);
  if (disconnect) {
    if (session) session->reset();
    strcpy(reply, "OK - peer disconnected");
    return true;
  }
  if (!connect) {
    snprintf(reply, 150, "peer=%s", !session ? "offline" : session->active() ? "authenticated" : "pending");
    return true;
  }
  if (!_rules.forwardingAllowed() || !*peerContextName(context)
      || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)) {
    strcpy(reply, "Err - configure a policy scope and sync key");
  } else if (!session) {
    strcpy(reply, "Err - policy peer capacity reached");
  } else if (!session->free()) {
    strcpy(reply, session->active() ? "OK - peer authenticated" : "OK - peer authentication pending");
  } else {
    uint8_t nonce[PolicyPeerSession::NonceSize];
    const bool queued = nextPolicyPeerNonce(nonce) && session->start(key, context, nonce, millis());
    strcpy(reply, queued ? "OK - peer challenge queued" : "Err - peer freshness storage unavailable");
  }
  return true;
}

PolicyPeerSession* MyMesh::openPolicyFrame(const mesh::Packet& packet, PolicyPeerSession::Context context,
                                           uint8_t* data, size_t size, const void* associated,
                                           size_t associatedSize) {
  if (packet.payload_len != PolicyHeaderSize + size + PolicyTagSize || !packet.isRouteDirect()
      || packet.getPathHashCount() || !packet.received_over_radio || !_rules.forwardingAllowed()
      || !mesh::Utils::isZeroes(packet.payload + 5, PolicyNonceSize - 4)
      || !_sync_work.admit(millis())) return nullptr;
  uint32_t sequence = 0;
  for (unsigned i = 0; i < sizeof(sequence); ++i) sequence |= uint32_t(packet.payload[1 + i]) << (8 * i);
  for (auto& session : _policy_peers) {
    session.expire(millis());
    if (!session.active() || session.context() != context || !session.canReceiveSequence(sequence)
        || !peerPermitted(context, session.peer())) continue;
    GCM<AES128> cipher;
    if (!cipher.setKey(session.receiveKey(), CIPHER_KEY_SIZE) || !cipher.setIV(packet.payload + 1, PolicyNonceSize)) continue;
    cipher.addAuthData(packet.payload, 1);
    if (associatedSize) cipher.addAuthData(associated, associatedSize);
    cipher.decrypt(data, packet.payload + PolicyHeaderSize, size);
    if (!cipher.checkTag(packet.payload + PolicyHeaderSize + size, PolicyTagSize)) continue;
    session.markReceived(sequence);
    return &session;
  }
  return nullptr;
}

bool MyMesh::queuePolicyFrame(PolicyPeerSession& session, uint8_t type, const uint8_t* data, size_t size,
                              const TransportKey& transport, const void* associated, size_t associatedSize) {
  if (size > MAX_PACKET_PAYLOAD - PolicyHeaderSize - PolicyTagSize) return false;
  const auto sequence = session.nextTransmitSequence();
  if (!sequence) { session.reset(); return false; }
  uint8_t payload[MAX_PACKET_PAYLOAD]{};
  payload[0] = type;
  for (unsigned i = 0; i < sizeof(sequence); ++i) payload[1 + i] = sequence >> (8 * i);
  GCM<AES128> cipher;
  if (!cipher.setKey(session.transmitKey(), CIPHER_KEY_SIZE) || !cipher.setIV(payload + 1, PolicyNonceSize)) return false;
  cipher.addAuthData(payload, 1);
  if (associatedSize) cipher.addAuthData(associated, associatedSize);
  cipher.encrypt(payload + PolicyHeaderSize, data, size);
  cipher.computeTag(payload + PolicyHeaderSize + size, PolicyTagSize);
  auto* packet = createControlData(payload, PolicyHeaderSize + size + PolicyTagSize);
  if (!packet) return false;
  session.markTransmitted(sequence);
  _next_policy_tx = futureMillis(PolicyIntervalMs);
  if (transport.isNull()) {
    sendZeroHop(packet);
  } else {
    uint16_t codes[] = {transport.calcTransportCode(packet), 0};
    sendZeroHop(packet, codes);
  }
  return true;
}

bool MyMesh::policyScopeReceived(mesh::Packet& packet, RuleStore::Scope scope) {
  if (scope == RuleStore::Global) {
    return !packet.hasTransportCodes() && !(region_map.getWildcard().flags & REGION_DENY_FLOOD);
  }
  if (scope == RuleStore::Subnet) return !packet.hasTransportCodes();
  if (scope != RuleStore::Region || !packet.hasTransportCodes()) return false;
  const auto* region = region_map.findMatch(&packet, REGION_DENY_FLOOD);
  return region && region == region_map.findByName(_rules.scopeName(RuleStore::Region));
}
