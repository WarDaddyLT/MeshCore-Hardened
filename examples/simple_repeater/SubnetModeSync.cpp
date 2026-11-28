#include "MyMesh.h"

namespace {
constexpr uint8_t SubnetModeType = 0xA7;
using Context = PolicyPeerSession::Context;
}

bool MyMesh::isSubnetModePacket(const mesh::Packet& packet) {
  return packet.getPayloadType() == PAYLOAD_TYPE_CONTROL && packet.payload_len
      && packet.payload[0] == SubnetModeType;
}

void MyMesh::receiveSubnetMode(mesh::Packet& packet) {
  if (!policyScopeReceived(packet, RuleStore::Subnet)
      || (_next_policy_commit && !millisHasNowPassed(_next_policy_commit))) return;
  RuleStore::SubnetModeRecord record{};
  auto* session = openPolicyFrame(packet, Context::Subnet, reinterpret_cast<uint8_t*>(&record), sizeof(record));
  if (!session || (memcmp(record.origin, session->peer(), PUB_KEY_SIZE) != 0 && !_rules.relayAllowed(session->peer()))) return;
  const auto previousMode = _rules.mode();
  if (_rules.mergeSubnetMode(record, self_id) != RuleStore::Changed) return;
  if (_rules.mode() > previousMode) clearOutboundQueue();
  _next_policy_commit = futureMillis(2000);
  queueSubnetMode();
}

void MyMesh::sendSubnetMode() {
  static_assert(PolicyHeaderSize + sizeof(RuleStore::SubnetModeRecord) + PolicyTagSize <= MAX_PACKET_PAYLOAD,
                "Signed subnet mode exceeds packet capacity");
  if (_subnet_mode_cursor >= PolicyPeerCapacity || !_rules.forwardingAllowed() || _mgr->getOutboundTotal()
      || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;
  const auto& record = _rules.subnetModeRecord();
  if (!_rules.subnetModeRevision() || !_rules.publisherAllowed(RuleStore::Subnet, record.origin, self_id)) {
    _subnet_mode_cursor = PolicyPeerCapacity;
    return;
  }
  for (; _subnet_mode_cursor < PolicyPeerCapacity; ++_subnet_mode_cursor) {
    auto& session = _policy_peers[_subnet_mode_cursor];
    if (!session.active() || session.context() != Context::Subnet
        || memcmp(session.peer(), record.origin, PUB_KEY_SIZE) == 0) continue;
    const TransportKey unscoped{};
    if (queuePolicyFrame(session, SubnetModeType, reinterpret_cast<const uint8_t*>(&record), sizeof(record), unscoped)) {
      ++_subnet_mode_cursor;
    }
    return;
  }
}
