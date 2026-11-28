#include "MyMesh.h"
#include "CliParse.h"
#include <AES.h>
#include <GCM.h>

namespace {
constexpr uint8_t RootType = 0xA2;
constexpr uint8_t RecordType = 0xA3;
constexpr size_t NonceSize = 12;
constexpr size_t HeaderSize = 1 + NonceSize;
constexpr size_t TagSize = 12;
constexpr size_t RootSize = HeaderSize + sizeof(RuleStore::Checkpoint) + TagSize;
constexpr size_t RecordSize = HeaderSize + 1 + RuleStore::WireSize + TagSize;
static_assert(RootSize <= MAX_PACKET_PAYLOAD && RecordSize <= MAX_PACKET_PAYLOAD, "Checkpoint frames must fit LoRa");
static_assert(RuleStore::Capacity < 32, "Checkpoint receipt mask must fit in 32 bits");
constexpr unsigned long TransferIntervalMs = 60000;
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
  _checkpoint_cursor = 0;
  if (_sync_cursor < RuleStore::Capacity) _sync_cursor = 0;
  strcpy(reply, "OK - checkpoint committed and queued");
}

void MyMesh::receiveCheckpointPacket(mesh::Packet& packet) {
  const bool root = packet.payload[0] == RootType;
  if (packet.payload_len != (root ? RootSize : RecordSize) || !packet.isRouteFlood() || !recv_pkt_region
      || !packet.received_over_radio || !_rules.forwardingAllowed()
      || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)) return;
  if (_checkpoint_transfer != (root ? CheckpointTransfer::Idle : CheckpointTransfer::Receiving)) return;
  if (!_sync_work.admit(millis())) return;

  GCM<AES128> cipher;
  if (!cipher.setKey(_rules.syncKey(), CIPHER_KEY_SIZE) || !cipher.setIV(packet.payload + 1, NonceSize)) return;
  cipher.addAuthData(packet.payload, 1);
  if (!root) cipher.addAuthData(reinterpret_cast<const uint8_t*>(&_checkpoint), sizeof(_checkpoint));
  uint8_t data[1 + RuleStore::WireSize];
  const size_t size = packet.payload_len - HeaderSize - TagSize;
  cipher.decrypt(data, packet.payload + HeaderSize, size);
  if (!cipher.checkTag(packet.payload + HeaderSize + size, TagSize)) return;

  if (root) {
    memcpy(&_checkpoint, data, sizeof(_checkpoint));
    if (_checkpoint.scope == RuleStore::Region && (recv_pkt_region->isWildcard()
        || strcmp(recv_pkt_region->name, _rules.scopeName(RuleStore::Region)) != 0)) return;
    if (_rules.checkCheckpoint(_checkpoint, self_id) != RuleStore::Changed) return;
    _checkpoint_transfer = CheckpointTransfer::Receiving;
    _checkpoint_received = 0;
    _checkpoint_expiry = futureMillis(ReceiveWindowMs);
  } else {
    if (millisHasNowPassed(_checkpoint_expiry)) { _checkpoint_transfer = CheckpointTransfer::Idle; return; }
    if (_checkpoint.scope == RuleStore::Region && (recv_pkt_region->isWildcard()
        || strcmp(recv_pkt_region->name, _rules.scopeName(RuleStore::Region)) != 0)) return;
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
    if (_sync_cursor < RuleStore::Capacity) _sync_cursor = 0;
  }
}

void MyMesh::sendCheckpointPacket() {
  if (_checkpoint_transfer == CheckpointTransfer::Receiving && millisHasNowPassed(_checkpoint_expiry)) {
    _checkpoint_transfer = CheckpointTransfer::Idle;
  }
  if (_checkpoint_transfer != CheckpointTransfer::Sending || !_rules.forwardingAllowed()
      || _mgr->getOutboundTotal() != 0 || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)
      || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;
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

  const bool root = _checkpoint_cursor == 0;
  uint8_t payload[RecordSize];
  uint8_t data[1 + RuleStore::WireSize];
  const size_t size = root ? sizeof(_checkpoint) : sizeof(data);
  payload[0] = root ? RootType : RecordType;
  if (root) {
    memcpy(data, &_checkpoint, size);
  } else {
    data[0] = _checkpoint_cursor - 1;
    memcpy(data + 1, &_checkpoint_records[data[0]], RuleStore::WireSize);
  }
  getRNG()->random(payload + 1, NonceSize);
  GCM<AES128> cipher;
  if (!cipher.setKey(_rules.syncKey(), CIPHER_KEY_SIZE) || !cipher.setIV(payload + 1, NonceSize)) return;
  cipher.addAuthData(payload, 1);
  if (!root) cipher.addAuthData(reinterpret_cast<const uint8_t*>(&_checkpoint), sizeof(_checkpoint));
  cipher.encrypt(payload + HeaderSize, data, size);
  cipher.computeTag(payload + HeaderSize + size, TagSize);
  auto* packet = createControlData(payload, HeaderSize + size + TagSize);
  if (!packet) return;
  _next_policy_tx = futureMillis(TransferIntervalMs);
  sendFloodScoped(transport, packet, 0, _prefs.path_hash_mode + 1);
  if (++_checkpoint_cursor > _checkpoint.count) _checkpoint_transfer = CheckpointTransfer::Idle;
}
