#include "MyMesh.h"

namespace {
using Context = PolicyPeerSession::Context;
constexpr uint8_t Query = 0xAA;
constexpr uint8_t Proof = 0xAB;
constexpr uint8_t Chunk = 0xAC;
constexpr unsigned long TransferWindow = 50 * 60 * 1000UL;
// One block number, followed by the next portion of the signed snapshot.
constexpr size_t BlockSize = 150;
}

bool MyMesh::isPeerOnboardingPacket(const mesh::Packet& packet) {
  return packet.getPayloadType() == PAYLOAD_TYPE_CONTROL && packet.payload_len
      && packet.payload[0] >= Query && packet.payload[0] <= Chunk;
}

#ifdef HARDENED_MANUAL_ONBOARDING_ONLY
bool MyMesh::handlePeerOnboardingCommand(const char* command, char* reply) {
  const char* args;
  if (!savemesh::matchCommand(command, "peer", &args)) return false;
  strcpy(reply, "Err - use manual onboarding on this build");
  return true;
}
#else

bool MyMesh::peerOnboardingBusy() const {
  return _peer_onboarding >= PeerOnboardingState::Request && _peer_onboarding <= PeerOnboardingState::Sending;
}

bool MyMesh::handlePeerOnboardingCommand(const char* command, char* reply) {
  const char* args;
  if (!savemesh::matchCommand(command, "peer", &args)) return false;
  if (!*args) {
    const char* state = peerOnboardingBusy() ? "pending" : _peer_onboarding == PeerOnboardingState::Failed ? "failed"
                     : _rules.onboarding() && _rules.peerPolicyStaged() ? "staged" : "idle";
    snprintf(reply, 150, "peer=%s received=%lu transit=%s", state, static_cast<unsigned long>(_onboarding_offset),
             _rules.transitAllowed() && !_prefs.disable_fwd ? "available" : "held");
    return true;
  }
  if (savemesh::matchesValue(args, "cancel")) {
    _peer_onboarding = PeerOnboardingState::Idle;
    _onboarding_offset = 0;
    strcpy(reply, "OK - peer transfer cleared");
    return true;
  }
  const char* key;
  if (!savemesh::matchCommand(args, "fetch", &key) || !savemesh::isHex(key, PUB_KEY_SIZE * 2)) {
    strcpy(reply, "Err - use onboarding peer fetch <key>");
    return true;
  }
  uint8_t provider[PUB_KEY_SIZE];
  if (!_rules.onboarding() || !_rules.forwardingAllowed() || peerOnboardingBusy()
      || !mesh::Utils::fromHex(provider, sizeof(provider), key)
      || !_rules.publisherAllowed(RuleStore::Subnet, provider, self_id)) {
    strcpy(reply, "Err - need held onboarding and an approved subnet publisher");
    return true;
  }
  auto* session = findPolicyPeer(Context::Subnet, provider, false);
  if (!session || !session->active() || !peerPermitted(Context::Subnet, provider)
      || !nextPolicyPeerNonce(_onboarding_proof.request)) {
    strcpy(reply, "Err - need authenticated subnet session and freshness storage");
    return true;
  }
  memcpy(_onboarding_peer, provider, sizeof(_onboarding_peer));
  _onboarding_review_revision = 0;
  _onboarding_offset = 0;
  _onboarding_expiry = futureMillis(TransferWindow);
  _peer_onboarding = PeerOnboardingState::Request;
  strcpy(reply, "OK - policy snapshot request queued");
  return true;
}

void MyMesh::receivePeerOnboarding(mesh::Packet& packet) {
  if (!policyScopeReceived(packet, RuleStore::Subnet)) return;
  if (packet.payload[0] == Query) {
    if (peerOnboardingBusy() || !_rules.transitAllowed()) return;
    RuleStore::PeerPolicyProof proof{};
    auto* session = openPolicyFrame(packet, Context::Subnet, proof.request, sizeof(proof.request));
    if (!session || !_rules.exportPeerPolicy(_onboarding_policy, proof, self_id, session->peer())) return;
    _onboarding_proof = proof;
    memcpy(_onboarding_peer, session->peer(), sizeof(_onboarding_peer));
    _onboarding_offset = 0;
    _onboarding_expiry = futureMillis(TransferWindow);
    _peer_onboarding = PeerOnboardingState::SendProof;
    return;
  }
  if (!_rules.onboarding() || millisHasNowPassed(_onboarding_expiry)) return;
  if (packet.payload[0] == Proof && _peer_onboarding == PeerOnboardingState::Proof) {
    RuleStore::PeerPolicyProof proof{};
    auto* session = openPolicyFrame(packet, Context::Subnet, reinterpret_cast<uint8_t*>(&proof), sizeof(proof));
    if (!session || memcmp(session->peer(), _onboarding_peer, PUB_KEY_SIZE) != 0
        || memcmp(proof.request, _onboarding_proof.request, sizeof(proof.request)) != 0
        || !_rules.verifyPeerPolicyProof(proof, _onboarding_peer, self_id)) return;
    _onboarding_proof = proof;
    _peer_onboarding = PeerOnboardingState::Receiving;
    return;
  }
  if (packet.payload[0] != Chunk || _peer_onboarding != PeerOnboardingState::Receiving) return;
  const auto total = RuleStore::PeerPolicy::wireSize(_onboarding_proof.count);
  constexpr size_t overhead = PolicyHeaderSize + PolicyTagSize + 1;
  if (packet.payload_len <= overhead || packet.payload_len > overhead + BlockSize) return;
  const size_t size = packet.payload_len - overhead;
  uint8_t data[1 + BlockSize];
  auto* session = openPolicyFrame(packet, Context::Subnet, data, 1 + size,
                                  &_onboarding_proof, sizeof(_onboarding_proof));
  if (!session || memcmp(session->peer(), _onboarding_peer, PUB_KEY_SIZE) != 0) return;
  const size_t expected = total - _onboarding_offset < BlockSize ? total - _onboarding_offset : BlockSize;
  if (size != expected || data[0] != _onboarding_offset / BlockSize) {
    _peer_onboarding = PeerOnboardingState::Failed;
    return;
  }
  memcpy(reinterpret_cast<uint8_t*>(&_onboarding_policy) + _onboarding_offset, data + 1, size);
  _onboarding_offset += size;
  if (_onboarding_offset == total) {
    const bool staged = _rules.stagePeerPolicy(_onboarding_policy, _onboarding_proof, _onboarding_peer, self_id);
    _peer_onboarding = staged ? PeerOnboardingState::Staged : PeerOnboardingState::Failed;
  }
}

void MyMesh::sendPeerOnboarding() {
  static_assert(1 + BlockSize + PolicyHeaderSize + PolicyTagSize <= MAX_PACKET_PAYLOAD);
  static_assert(sizeof(RuleStore::PeerPolicyProof) + PolicyHeaderSize + PolicyTagSize <= MAX_PACKET_PAYLOAD);
  if (!peerOnboardingBusy()) return;
  auto* session = findPolicyPeer(Context::Subnet, _onboarding_peer, false);
  if (millisHasNowPassed(_onboarding_expiry) || !session || !session->active()
      || !peerPermitted(Context::Subnet, _onboarding_peer)) {
    _peer_onboarding = PeerOnboardingState::Failed;
    return;
  }
  if (!_rules.forwardingAllowed() || _mgr->getOutboundTotal()
      || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;
  const TransportKey unscoped{};
  if (_peer_onboarding == PeerOnboardingState::Request) {
    if (queuePolicyFrame(*session, Query, _onboarding_proof.request, sizeof(_onboarding_proof.request), unscoped)) {
      _peer_onboarding = PeerOnboardingState::Proof;
    }
  } else if (_peer_onboarding == PeerOnboardingState::SendProof || _peer_onboarding == PeerOnboardingState::Sending) {
    if (!_rules.transitAllowed() || !_rules.publisherAllowed(RuleStore::Subnet, self_id.pub_key, self_id)
        || !_rules.peerPolicyMatches(_onboarding_policy, _onboarding_proof.count)) {
      _peer_onboarding = PeerOnboardingState::Failed;
      return;
    }
    if (_peer_onboarding == PeerOnboardingState::SendProof) {
      if (queuePolicyFrame(*session, Proof, reinterpret_cast<const uint8_t*>(&_onboarding_proof),
                           sizeof(_onboarding_proof), unscoped)) _peer_onboarding = PeerOnboardingState::Sending;
      return;
    }
    const auto total = RuleStore::PeerPolicy::wireSize(_onboarding_proof.count);
    const size_t size = total - _onboarding_offset < BlockSize ? total - _onboarding_offset : BlockSize;
    uint8_t data[1 + BlockSize];
    data[0] = _onboarding_offset / BlockSize;
    memcpy(data + 1, reinterpret_cast<const uint8_t*>(&_onboarding_policy) + _onboarding_offset, size);
    if (queuePolicyFrame(*session, Chunk, data, 1 + size, unscoped, &_onboarding_proof, sizeof(_onboarding_proof))) {
      _onboarding_offset += size;
      if (_onboarding_offset == total) _peer_onboarding = PeerOnboardingState::Idle;
    }
  }
}
#endif
