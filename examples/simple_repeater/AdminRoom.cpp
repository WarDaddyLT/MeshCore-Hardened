#include "MyMesh.h"

#ifndef HARDENED_NO_ADMIN_ROOM

namespace {
constexpr size_t AdvertChunkSize = 48;
constexpr size_t AdvertDigestSize = 32;
constexpr unsigned long RoomTimeout = 5 * 60 * 1000UL;
constexpr unsigned long AdvertTimeout = 5 * 60 * 1000UL;
constexpr unsigned long ReplyInterval = 2000;
constexpr unsigned long OnDemandAdvertInterval = 60 * 1000UL;

bool isReadCommand(const char* command) {
  const char* args;
  return savemesh::matchesValue(command, "count") || savemesh::matchesValue(command, "status")
      || savemesh::matchCommand(command, "list", &args) || savemesh::matchCommand(command, "show", &args);
}
}

bool MyMesh::prepareAdminRoomIdentity() {
  if (_room_identity_loaded) return _room_identity.pub_key[0] != self_id.pub_key[0];
  for (unsigned attempt = 0; attempt < 16; attempt++) {
    mesh::LocalIdentity candidate(getRNG());
    if (candidate.pub_key[0] == self_id.pub_key[0] || candidate.pub_key[0] == 0
        || candidate.pub_key[0] == 0xFF) continue;
    if (!_rules.saveRoomIdentity(candidate)) return false;
    _room_identity = candidate;
    _room_identity_loaded = true;
    return true;
  }
  return false;
}

const char* MyMesh::adminRoomName(char* buffer) const {
  if (_rules.roomName()[0]) return _rules.roomName();
  snprintf(buffer, MAX_ADVERT_DATA_SIZE, "%.25s Admin", _prefs.node_name);
  return buffer;
}

mesh::Packet* MyMesh::createAdminRoomAdvert() {
  char name[MAX_ADVERT_DATA_SIZE];
  uint8_t data[MAX_ADVERT_DATA_SIZE];
  AdvertDataBuilder builder(ADV_TYPE_ROOM, adminRoomName(name));
  return createAdvert(_room_identity, data, builder.encodeTo(data));
}

bool MyMesh::handleAdminRoomCommand(const char* command, char* reply, bool usb) {
  using savemesh::matchCommand;
  using savemesh::matchesValue;

  const char* args;
  if (matchesValue(command, "get admin.enabled")) {
    strcpy(reply, _rules.roomEnabled() && _room_identity_loaded ? "on" : "off");
  } else if (matchesValue(command, "get admin.name")) {
    char name[MAX_ADVERT_DATA_SIZE];
    strcpy(reply, adminRoomName(name));
  } else if (matchCommand(command, "set admin.enabled", &args)) {
    uint8_t enabled;
    if (!usb || !savemesh::parseOnOff(args, &enabled)) {
      strcpy(reply, "Err - use USB with on or off");
    } else if ((enabled && !prepareAdminRoomIdentity()) || !_rules.setRoomEnabled(enabled)) {
      strcpy(reply, "Err - room identity storage unavailable");
    } else {
      for (auto& session : _room_sessions) session = RoomSession{};
      _admin_advert_length = 0;
      strcpy(reply, "OK");
    }
  } else if (matchCommand(command, "set admin.name", &args)) {
    if (!usb || !AdvertDataParser::isValidName(args) || !_rules.setRoomName(args)) {
      strcpy(reply, "Err - use USB with a valid room name");
    } else {
      _admin_advert_length = 0;
      strcpy(reply, "OK");
    }
  } else if (matchesValue(command, "get admin.pubkey")) {
    if (_room_identity_loaded) mesh::Utils::toHex(reply, _room_identity.pub_key, PUB_KEY_SIZE);
    else strcpy(reply, "Err - room identity unavailable");
  } else if (matchCommand(command, "get admin.advert", &args)) {
    if (!_rules.roomEnabled() || !_room_identity_loaded || _room_identity.pub_key[0] == self_id.pub_key[0]) {
      strcpy(reply, "Err - admin room disabled");
      return true;
    }
    if (_admin_advert_length && millisHasNowPassed(_admin_advert_expires)) _admin_advert_length = 0;
    if (!*args && !_admin_advert_length) {
      auto packet = createAdminRoomAdvert();
      if (packet) {
        packet->header |= ROUTE_TYPE_FLOOD;
        packet->path_len = 0;
        _admin_advert_length = packet->writeTo(_admin_advert);
        releasePacket(packet);
        _admin_advert_expires = futureMillis(AdvertTimeout);
      }
    }
    if (!_admin_advert_length) {
      strcpy(reply, "Err - start with get admin.advert");
      return true;
    }

    uint8_t digest[AdvertDigestSize];
    char hash[2 * AdvertDigestSize + 1];
    mesh::Utils::sha256(digest, sizeof(digest), _admin_advert, _admin_advert_length);
    mesh::Utils::toHex(hash, digest, sizeof(digest));
    unsigned count = (_admin_advert_length + AdvertChunkSize - 1) / AdvertChunkSize;
    if (!*args) {
      snprintf(reply, 150, "id=%.16s parts=%u bytes=%u sha256=%s", hash, count,
               static_cast<unsigned>(_admin_advert_length), hash);
    } else {
      uint16_t index;
      if (!savemesh::parseUnsigned(args, &index) || index >= count) {
        strcpy(reply, "Err - invalid part index");
        return true;
      }
      size_t offset = index * AdvertChunkSize;
      size_t size = _admin_advert_length - offset;
      if (size > AdvertChunkSize) size = AdvertChunkSize;
      int header_size = snprintf(reply, 150, "id=%.16s part=%u/%u ", hash,
                                static_cast<unsigned>(index), count);
      mesh::Utils::toHex(reply + header_size, _admin_advert + offset, size);
    }
  } else if (matchesValue(command, "admin.advert once")) {
    if (!_rules.roomEnabled() || !_room_identity_loaded || _room_identity.pub_key[0] == self_id.pub_key[0]) {
      strcpy(reply, "Err - admin room disabled");
    } else if (_next_room_advert && !millisHasNowPassed(_next_room_advert)) {
      strcpy(reply, "Err - admin advert cooldown");
    } else if (auto packet = createAdminRoomAdvert()) {
      sendZeroHop(packet);
      _next_room_advert = futureMillis(OnDemandAdvertInterval);
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Err - radio queue full");
    }
  } else {
    return false;
  }
  return true;
}

void MyMesh::sendAdminRoomPacket(mesh::Packet* request, mesh::Packet* response,
                                 const RoomSession& session, unsigned long delay) {
  if (!response) return;
  if (response->getPayloadType() != PAYLOAD_TYPE_ACK) {
    // Mesh's encoders default to the primary source hash. The encrypted
    // payload already uses the secondary identity's shared secret.
    response->payload[PATH_HASH_SIZE] = _room_identity.pub_key[0];
  }
  if (session.path_len != OUT_PATH_UNKNOWN) {
    sendDirect(response, session.path, session.path_len, delay);
  } else if (request->isRouteFlood()) {
    sendFloodReply(response, delay, request->getPathHashSize());
  } else {
    sendZeroHop(response, delay);
  }
}

bool MyMesh::receiveAdminRoom(mesh::Packet* packet) {
  if (!_room_identity_loaded || !_rules.roomEnabled() || _room_identity.pub_key[0] == self_id.pub_key[0]
      || !packet->received_over_radio || packet->payload_len == 0
      || packet->payload[0] != _room_identity.pub_key[0]
      || (packet->isRouteDirect() && packet->getPathHashCount() != 0)
      || (packet->isRouteFlood() && !recv_pkt_region)) return false;
  uint8_t type = packet->getPayloadType();
  bool login = type == PAYLOAD_TYPE_ANON_REQ;
  if (!login && type != PAYLOAD_TYPE_TXT_MSG && type != PAYLOAD_TYPE_REQ && type != PAYLOAD_TYPE_PATH) return false;
  if (getTables()->wasSeen(packet)) return true;

  size_t prefix_size = login ? 1 + PUB_KEY_SIZE : 2;
  if (packet->payload_len <= prefix_size + CIPHER_MAC_SIZE) return false;
  ClientInfo* client = nullptr;
  uint8_t secret[PUB_KEY_SIZE];
  uint8_t data[MAX_PACKET_PAYLOAD + 1];
  int length = 0;
  for (int i = 0; i < acl.getNumClients(); i++) {
    auto peer = acl.getClientByIdx(i);
    if (login ? !peer->id.matches(packet->payload + 1) : !peer->id.isHashMatch(packet->payload + 1)) continue;
    if ((peer->permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST || shouldDenyClient(peer->id)) continue;
    if (!_room_work.admit(millis())) return false;
    _room_identity.calcSharedSecret(secret, peer->id);
    length = mesh::Utils::MACThenDecrypt(secret, data, packet->payload + prefix_size,
                                        packet->payload_len - prefix_size);
    if (length > 0) {
      client = peer;
      break;
    }
  }
  if (!client) return false;
  getTables()->markSeen(packet);
  data[length] = 0;

  RoomSession* session = nullptr;
  RoomSession* available = nullptr;
  for (auto& entry : _room_sessions) {
    if (entry.expires && client->id.matches(entry.key)) {
      session = &entry;
      break;
    }
    if (!available && (!entry.expires || millisHasNowPassed(entry.expires))) available = &entry;
  }

  if (login) {
    if (length < 9 || data[8] || (_next_room_reply && !millisHasNowPassed(_next_room_reply))) return true;
    uint32_t stamp;
    memcpy(&stamp, data, sizeof(stamp));
    if (session && stamp <= session->last_stamp) return true;
    if (!session) {
      session = available;
      if (!session) return true;
      *session = RoomSession{};
      memcpy(session->key, client->id.pub_key, PUB_KEY_SIZE);
      session->path_len = OUT_PATH_UNKNOWN;
    }
    session->last_stamp = stamp;
    session->expires = futureMillis(RoomTimeout);
    session->path_len = OUT_PATH_UNKNOWN;

    uint8_t response[13]{};
    uint32_t now = getRTCClock()->getCurrentTimeUnique();
    memcpy(response, &now, sizeof(now));
    response[6] = client->isAdmin() ? 1 : 0;
    response[7] = client->permissions;
    getRNG()->random(response + 8, 4);
    response[12] = 1; // native room login response format
    mesh::Packet* reply = packet->isRouteFlood()
        ? createPathReturn(client->id, secret, packet->path, packet->path_len,
                           PAYLOAD_TYPE_RESPONSE, response, sizeof(response))
        : createDatagram(PAYLOAD_TYPE_RESPONSE, client->id, secret, response, sizeof(response));
    sendAdminRoomPacket(packet, reply, *session, 300);
    _next_room_reply = futureMillis(ReplyInterval);
    return true;
  }

  if (!session || millisHasNowPassed(session->expires)) return true;
  if (type == PAYLOAD_TYPE_PATH) {
    uint8_t encoded = data[0];
    if (mesh::Packet::isValidPathLen(encoded)) {
      size_t bytes = static_cast<size_t>(encoded & 63) * ((encoded >> 6) + 1);
      if (bytes + 2 <= static_cast<size_t>(length)) {
        session->path_len = mesh::Packet::copyPath(session->path, data + 1, encoded);
      }
    }
    return true;
  }

  if (length < 5 || (_next_room_reply && !millisHasNowPassed(_next_room_reply))) return true;
  uint32_t stamp;
  memcpy(&stamp, data, sizeof(stamp));
  if (stamp < session->last_stamp) return true;
  bool retry = stamp == session->last_stamp;
  session->last_stamp = stamp;
  session->expires = futureMillis(RoomTimeout);
  if (type == PAYLOAD_TYPE_REQ) {
    if (data[4] == 0x02 && length >= 9 && packet->isRouteDirect()) {
      uint32_t hash;
      mesh::Utils::sha256(reinterpret_cast<uint8_t*>(&hash), sizeof(hash), data, 9,
                          client->id.pub_key, PUB_KEY_SIZE);
      if (auto ack = createAck(hash)) {
        ack->payload[ack->payload_len++] = 0; // no stored posts pending
        sendAdminRoomPacket(packet, ack, *session, 300);
        _next_room_reply = futureMillis(ReplyInterval);
      }
    }
    return true;
  }

  if (length <= 5 || (data[4] >> 2) != TXT_TYPE_PLAIN) return true;
  const char* text = reinterpret_cast<const char*>(data + 5);
  uint32_t hash;
  mesh::Utils::sha256(reinterpret_cast<uint8_t*>(&hash), sizeof(hash), data, 5 + strlen(text),
                      client->id.pub_key, PUB_KEY_SIZE);
  sendAdminRoomPacket(packet, createAck(hash), *session, 200);
  _next_room_reply = futureMillis(ReplyInterval);
  if (retry) return true;

  uint8_t response[9 + 150]{};
  uint32_t now = getRTCClock()->getCurrentTimeUnique();
  memcpy(response, &now, sizeof(now));
  response[4] = TXT_TYPE_SIGNED_PLAIN << 2;
  memcpy(response + 5, _room_identity.pub_key, 4);
  char* output = reinterpret_cast<char*>(response + 9);
  const char* args;
  if (savemesh::matchCommand(text, "rules", &args) && isReadCommand(args)) {
    bool sync_requested = false;
    _rules.handleCommand(args, output, self_id, &client->id, stamp, *getRNG(), false, false, sync_requested);
  } else {
    strcpy(output, "Read only. Use rules count, status, list or show. Edit rules through repeater CLI.");
  }
  auto reply = createDatagram(PAYLOAD_TYPE_TXT_MSG, client->id, secret, response, 9 + strlen(output));
  sendAdminRoomPacket(packet, reply, *session, 600);
  return true;
}

#endif
