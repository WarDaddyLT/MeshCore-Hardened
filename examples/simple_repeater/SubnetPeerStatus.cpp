#include "MyMesh.h"

namespace {
constexpr uint8_t QueryType = 0xA8;
constexpr uint8_t StatusType = 0xA9;
constexpr unsigned long QueryWindowMs = 12 * 60 * 1000UL;
constexpr unsigned long ConfirmedWindowMs = 5 * 60 * 1000UL;
using Context = PolicyPeerSession::Context;

uint32_t decodeWord(const uint8_t* bytes) {
  uint32_t result = 0;
  for (unsigned i = 0; i < 4; ++i) result |= uint32_t(bytes[i]) << (8 * i);
  return result;
}

void encodeWord(uint8_t* bytes, uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) bytes[i] = value >> (8 * i);
}
}

bool MyMesh::isSubnetStatusPacket(const mesh::Packet& packet) {
  return packet.getPayloadType() == PAYLOAD_TYPE_CONTROL && packet.payload_len
      && (packet.payload[0] == QueryType || packet.payload[0] == StatusType);
}

MyMesh::SubnetPeerStatus* MyMesh::findSubnetStatus(const uint8_t* key, bool allocate) {
  SubnetPeerStatus* empty = nullptr;
  for (auto& status : _subnet_status) {
    if (memcmp(status.peer, key, PUB_KEY_SIZE) == 0) return &status;
    if (!empty && !_rules.trustedPeer(status.peer)) empty = &status;
  }
  if (!allocate || !empty) return nullptr;
  *empty = {};
  memcpy(empty->peer, key, PUB_KEY_SIZE);
  return empty;
}

void MyMesh::policyPeerConnected(const PolicyPeerSession& session) {
  if (session.context() == Context::Domain) {
    queuePolicySync();
    for (const auto scope : {RuleStore::Global, RuleStore::Region}) {
      if (_rules.hasCheckpointFloor(scope, self_id)) _checkpoint_reconcile |= uint8_t(1) << scope;
    }
    return;
  }
  auto* status = findSubnetStatus(session.peer(), false);
  if (status) {
    status->confirmed_until = 0;
    status->query = 0;
    status->reply_query = 0;
    status->query_sent = false;
  }
  queueSubnetMode();
}

bool MyMesh::handleSubnetStatusCommand(const char* command, char* reply, bool canWrite) {
  const char* args;
  if (!savemesh::matchCommand(command, "peer", &args)) return false;
  if (!canWrite) { strcpy(reply, "Err - admin permission required"); return true; }
  const bool query = savemesh::matchCommand(args, "query", &args);
  uint8_t key[PUB_KEY_SIZE];
  if (!savemesh::isHex(args, 2 * sizeof(key)) || !mesh::Utils::fromHex(key, sizeof(key), args)
      || !_rules.trustedPeer(key)) {
    strcpy(reply, "Err - use subnet peer [query] <trusted repeater key>");
    return true;
  }
  auto* session = findPolicyPeer(Context::Subnet, key, false);
  const bool online = session && session->active() && peerPermitted(Context::Subnet, key);
  auto* status = findSubnetStatus(key, query && online);
  if (query) {
    if (!online || !status) { strcpy(reply, "Err - authenticate subnet peer first"); return true; }
    if (++_next_subnet_query == 0) ++_next_subnet_query;
    status->query = _next_subnet_query;
    status->query_sent = false;
    status->query_until = futureMillis(QueryWindowMs);
    status->confirmed_until = 0;
    strcpy(reply, "OK - subnet status query queued");
    return true;
  }

  const bool seen = status && decodeWord(status->last_reply.request);
  const bool fresh = seen && online && status->confirmed_until && !millisHasNowPassed(status->confirmed_until);
  const auto& local = _rules.subnetModeRecord();
  const bool current = fresh && memcmp(local.revision, status->last_reply.revision, sizeof(local.revision)) == 0
                             && memcmp(local.origin, status->last_reply.publisher, PUB_KEY_SIZE) == 0;
  const bool pending = status && status->query && !millisHasNowPassed(status->query_until);
  if (!seen) {
    snprintf(reply, 150, "confirmation=unknown pending=%u", pending);
    return true;
  }
  constexpr const char* Modes[] = {"normal", "restricted", "protected", "locked"};
  const auto& observation = status->last_reply;
  snprintf(reply, 150, "confirmation=%s pending=%u rev=%08lx%08lx effective=%s transit=%s",
           current ? "confirmed" : "stale", pending, static_cast<unsigned long>(decodeWord(observation.revision + 4)),
           static_cast<unsigned long>(decodeWord(observation.revision)), Modes[observation.effective_mode],
           observation.transit ? "available" : "held");
  return true;
}

void MyMesh::receiveSubnetStatus(mesh::Packet& packet) {
  if (!policyScopeReceived(packet, RuleStore::Subnet)) return;
  SubnetStatusReply data{};
  const bool query = packet.payload[0] == QueryType;
  const size_t length = query ? sizeof(data.request) : sizeof(data);
  auto* session = openPolicyFrame(packet, Context::Subnet, reinterpret_cast<uint8_t*>(&data), length);
  if (!session) return;
  const uint32_t request = decodeWord(data.request);
  if (!request) return;
  auto* status = findSubnetStatus(session->peer(), query);
  if (!status) return;
  if (query) {
    status->reply_query = request;
    status->reply_until = futureMillis(QueryWindowMs);
    return;
  }
  if (request != status->query || !status->query_sent || millisHasNowPassed(status->query_until)
      || data.effective_mode > RuleStore::Locked || data.transit > 1) return;
  status->query = 0;
  status->query_sent = false;
  status->last_reply = data;
  status->confirmed_until = futureMillis(ConfirmedWindowMs);
  const auto& local = _rules.subnetModeRecord();
  if (memcmp(local.revision, data.revision, sizeof(local.revision)) != 0
      || memcmp(local.origin, data.publisher, PUB_KEY_SIZE) != 0) queueSubnetMode();
}

void MyMesh::sendSubnetStatus() {
  static_assert(PolicyHeaderSize + sizeof(SubnetStatusReply) + PolicyTagSize <= MAX_PACKET_PAYLOAD,
                "Subnet status exceeds packet capacity");
  if (!_rules.forwardingAllowed() || _mgr->getOutboundTotal()
      || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;
  for (auto& status : _subnet_status) {
    const bool respond = status.reply_query && !millisHasNowPassed(status.reply_until);
    const bool request = status.query && !status.query_sent && !millisHasNowPassed(status.query_until);
    if (!respond && !request) continue;
    auto* session = findPolicyPeer(Context::Subnet, status.peer, false);
    if (!session || !session->active() || !peerPermitted(Context::Subnet, status.peer)) continue;

    SubnetStatusReply data{};
    encodeWord(data.request, respond ? status.reply_query : status.query);
    if (respond) {
      const auto& mode = _rules.subnetModeRecord();
      memcpy(data.revision, mode.revision, sizeof(data.revision));
      memcpy(data.publisher, mode.origin, sizeof(data.publisher));
      data.effective_mode = _rules.mode();
      data.transit = _rules.transitAllowed() && !_prefs.disable_fwd;
    }
    const TransportKey unscoped{};
    if (queuePolicyFrame(*session, respond ? StatusType : QueryType, reinterpret_cast<const uint8_t*>(&data),
                         respond ? sizeof(data) : sizeof(data.request), unscoped)) {
      if (respond) status.reply_query = 0;
      else status.query_sent = true;
    }
    return;
  }
}
