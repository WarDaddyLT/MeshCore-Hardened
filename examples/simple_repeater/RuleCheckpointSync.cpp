#include "MyMesh.h"
#include "CliParse.h"

namespace {
constexpr uint8_t RootType = 0xA2;
constexpr uint8_t RecordType = 0xA3;
static_assert(RuleStore::Capacity < 32, "Checkpoint receipt mask must fit in 32 bits");
constexpr unsigned long ReceiveWindowMs = 30 * 60000;
}

bool MyMesh::isCheckpointPacket(const mesh::Packet& packet) {
  return packet.getPayloadType() == PAYLOAD_TYPE_CONTROL && packet.payload_len
      && (packet.payload[0] == RootType || packet.payload[0] == RecordType);
}

bool MyMesh::checkpointTransport(RuleStore::Scope scope, TransportKey& transport) {
  if (scope == RuleStore::Global) return true;
  if (scope != RuleStore::Region) return false;
  const auto* region = region_map.findByName(_rules.scopeName(scope));
  return region && region_map.getTransportKeysFor(*region, &transport, 1) == 1 && !transport.isNull();
}

void MyMesh::handleCheckpointCommand(const char* args, char* reply, bool canWrite) {
  if (!*args) {
    const char* state = _checkpoint_transfer == CheckpointTransfer::Idle ? "idle"
                      : _checkpoint_transfer == CheckpointTransfer::Sending ? "sending" : "receiving";
    snprintf(reply, 150, "checkpoint=%s records=%u", state, static_cast<unsigned>(_checkpoint.count));
    return;
  }
  if (!canWrite) { strcpy(reply, "Err - admin permission required"); return; }
  if (_checkpoint_transfer != CheckpointTransfer::Idle) { strcpy(reply, "Err - checkpoint busy"); return; }
  RuleStore::Scope scope;
  if (savemesh::matchesValue(args, "global")) scope = RuleStore::Global;
  else if (savemesh::matchesValue(args, "region")) scope = RuleStore::Region;
  else { strcpy(reply, "Err - use rules checkpoint global or region"); return; }
  TransportKey transport{};
  if (mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE) || !checkpointTransport(scope, transport)
      || !_rules.makeCheckpoint(scope, self_id, _checkpoint, _checkpoint_records)) {
    strcpy(reply, "Err - configure policy scope and sync key");
    return;
  }
  if (_rules.installCheckpoint(_checkpoint, _checkpoint_records, _checkpoint.count, self_id, true) != RuleStore::Changed) {
    strcpy(reply, "Err - checkpoint storage unavailable");
    return;
  }
  _checkpoint_transfer = CheckpointTransfer::Sending;
  _checkpoint_reconcile &= ~(uint8_t(1) << scope);
  _checkpoint_cursor = 0;
  _checkpoint_peer_cursor = 0;
  memset(_checkpoint_sender, 0, sizeof(_checkpoint_sender));
  if (_sync_cursor < RuleStore::Capacity) queuePolicySync();
  strcpy(reply, "OK - checkpoint committed and queued");
}

void MyMesh::receiveCheckpointPacket(mesh::Packet& packet) {
  const bool root = packet.payload[0] == RootType;
  if (_checkpoint_transfer != (root ? CheckpointTransfer::Idle : CheckpointTransfer::Receiving)) return;
  uint8_t data[1 + RuleStore::WireSize];
  const size_t size = root ? sizeof(_checkpoint) : sizeof(data);
  auto* session = openPolicyFrame(packet, PolicyPeerSession::Context::Domain, data, size,
                                  root ? nullptr : &_checkpoint, root ? 0 : sizeof(_checkpoint));
  if (!session) return;
  if (root) {
    memcpy(&_checkpoint, data, sizeof(_checkpoint));
    if (!policyScopeReceived(packet, static_cast<RuleStore::Scope>(_checkpoint.scope))
        || (memcmp(_checkpoint.origin, session->peer(), PUB_KEY_SIZE) != 0 && !_rules.relayAllowed(session->peer()))
        || _rules.checkCheckpoint(_checkpoint, self_id) != RuleStore::Changed) return;
    memcpy(_checkpoint_sender, session->peer(), PUB_KEY_SIZE);
    _checkpoint_transfer = CheckpointTransfer::Receiving;
    _checkpoint_received = 0;
    _checkpoint_expiry = futureMillis(ReceiveWindowMs);
  } else {
    if (millisHasNowPassed(_checkpoint_expiry)) { _checkpoint_transfer = CheckpointTransfer::Idle; return; }
    if (memcmp(_checkpoint_sender, session->peer(), PUB_KEY_SIZE) != 0
        || !policyScopeReceived(packet, static_cast<RuleStore::Scope>(_checkpoint.scope))
        || (memcmp(_checkpoint.origin, session->peer(), PUB_KEY_SIZE) != 0 && !_rules.relayAllowed(session->peer()))) return;
    const uint8_t index = data[0];
    if (index >= _checkpoint.count || (_checkpoint_received & (uint32_t(1) << index))) return;
    auto& record = _checkpoint_records[index];
    memcpy(&record, data + 1, RuleStore::WireSize);
    memcpy(record.origin, _checkpoint.origin, PUB_KEY_SIZE);
    _checkpoint_received |= uint32_t(1) << index;
  }

  if (_checkpoint_received != (uint32_t(1) << _checkpoint.count) - 1) return;
  _checkpoint_transfer = CheckpointTransfer::Idle;
  if (_rules.installCheckpoint(_checkpoint, _checkpoint_records, _checkpoint.count, self_id) == RuleStore::Changed) {
    _checkpoint_transfer = CheckpointTransfer::Sending;
    _checkpoint_cursor = 0;
    _checkpoint_peer_cursor = 0;
    if (_sync_cursor < RuleStore::Capacity) queuePolicySync();
  }
}

void MyMesh::sendCheckpointPacket() {
  if (_checkpoint_transfer == CheckpointTransfer::Receiving && millisHasNowPassed(_checkpoint_expiry)) {
    _checkpoint_transfer = CheckpointTransfer::Idle;
  }
  if (!_rules.forwardingAllowed() || _mgr->getOutboundTotal() != 0
      || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)
      || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;
  if (_checkpoint_transfer == CheckpointTransfer::Idle && _checkpoint_reconcile) {
    for (const auto scope : {RuleStore::Global, RuleStore::Region}) {
      const uint8_t pending = uint8_t(1) << scope;
      if (!(_checkpoint_reconcile & pending)) continue;
      _checkpoint_reconcile &= ~pending;
      if (!_rules.makeCheckpoint(scope, self_id, _checkpoint, _checkpoint_records)) continue;
      _checkpoint_cursor = 0;
      _checkpoint_peer_cursor = 0;
      memset(_checkpoint_sender, 0, sizeof(_checkpoint_sender));
      _checkpoint_transfer = CheckpointTransfer::Sending;
      break;
    }
  }
  if (_checkpoint_transfer != CheckpointTransfer::Sending) return;
  const auto scope = static_cast<RuleStore::Scope>(_checkpoint.scope);
  TransportKey transport{};
  if (!checkpointTransport(scope, transport) || !_rules.publisherAllowed(scope, _checkpoint.origin, self_id)) {
    _checkpoint_transfer = CheckpointTransfer::Idle;
    return;
  }
  if (!self_id.matches(_checkpoint.origin)) {
    const auto decision = _rules.decide(RuleStore::Repeater, _checkpoint.origin);
    if (decision == RuleStore::Denied || (_rules.mode() == RuleStore::Locked && decision != RuleStore::Allowed)) {
      _checkpoint_transfer = CheckpointTransfer::Idle;
      return;
    }
  }

  constexpr size_t MaxPeers = sizeof(_policy_peers) / sizeof(_policy_peers[0]);
  for (; _checkpoint_peer_cursor < MaxPeers; ++_checkpoint_peer_cursor, _checkpoint_cursor = 0) {
    auto& session = _policy_peers[_checkpoint_peer_cursor];
    const bool root = _checkpoint_cursor == 0;
    if (!session.active() || session.context() != PolicyPeerSession::Context::Domain
        || memcmp(session.peer(), _checkpoint_sender, PUB_KEY_SIZE) == 0
        || memcmp(session.peer(), _checkpoint.origin, PUB_KEY_SIZE) == 0
        || (!root && memcmp(session.peer(), _checkpoint_target, PUB_KEY_SIZE) != 0)) continue;
    uint8_t data[1 + RuleStore::WireSize];
    size_t size = sizeof(_checkpoint);
    if (root) {
      memcpy(_checkpoint_target, session.peer(), PUB_KEY_SIZE);
      memcpy(data, &_checkpoint, size);
    } else {
      size = sizeof(data);
      data[0] = _checkpoint_cursor - 1;
      memcpy(data + 1, &_checkpoint_records[data[0]], RuleStore::WireSize);
    }
    if (queuePolicyFrame(session, root ? RootType : RecordType, data, size, transport,
                         root ? nullptr : &_checkpoint, root ? 0 : sizeof(_checkpoint))
        && ++_checkpoint_cursor > _checkpoint.count) {
      _checkpoint_cursor = 0;
      ++_checkpoint_peer_cursor;
    }
    return;
  }
  _checkpoint_transfer = CheckpointTransfer::Idle;
}
