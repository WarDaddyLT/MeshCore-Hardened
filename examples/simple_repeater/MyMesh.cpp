#include "MyMesh.h"
#include <algorithm>
#include <AES.h>
#include <GCM.h>

/* ------------------------------ Config -------------------------------- */

#ifndef LORA_FREQ
  #define LORA_FREQ 915.0
#endif
#ifndef LORA_BW
  #define LORA_BW 250
#endif
#ifndef LORA_SF
  #define LORA_SF 10
#endif
#ifndef LORA_CR
  #define LORA_CR 5
#endif
#ifndef LORA_TX_POWER
  #define LORA_TX_POWER 20
#endif

#ifndef ADVERT_NAME
  #define ADVERT_NAME "repeater"
#endif
#ifndef ADVERT_LAT
  #define ADVERT_LAT 0.0
#endif
#ifndef ADVERT_LON
  #define ADVERT_LON 0.0
#endif

#ifndef SERVER_RESPONSE_DELAY
  #define SERVER_RESPONSE_DELAY 300
#endif

#ifndef TXT_ACK_DELAY
  #define TXT_ACK_DELAY 200
#endif

#define FIRMWARE_VER_LEVEL       2

#define REQ_TYPE_GET_STATUS         0x01 // same as _GET_STATS
#define REQ_TYPE_KEEP_ALIVE         0x02
#define REQ_TYPE_GET_TELEMETRY_DATA 0x03
#define REQ_TYPE_GET_ACCESS_LIST    0x05
#define REQ_TYPE_GET_NEIGHBOURS     0x06
#define REQ_TYPE_GET_OWNER_INFO     0x07     // FIRMWARE_VER_LEVEL >= 2

#define RESP_SERVER_LOGIN_OK        0 // response to ANON_REQ

#define ANON_REQ_TYPE_REGIONS      0x01
#define ANON_REQ_TYPE_OWNER        0x02
#define ANON_REQ_TYPE_BASIC        0x03   // just remote clock

#define CLI_REPLY_DELAY_MILLIS      600

static constexpr uint8_t PolicyType = 0xA1;
static constexpr size_t PolicyNonceSize = 12;
static constexpr size_t PolicyTagSize = 12;
static constexpr size_t PolicyHeaderSize = 1 + PolicyNonceSize;
static constexpr size_t PolicyDataSize = RuleStore::FingerprintSize + RuleStore::WireSize;
static constexpr size_t PolicyPayloadSize = PolicyHeaderSize + PolicyDataSize + PolicyTagSize;
static_assert(PolicyPayloadSize <= MAX_PACKET_PAYLOAD, "Policy update must fit one control packet");

using savemesh::matchCommand;
using savemesh::matchesValue;
using savemesh::parseUnsigned;

void MyMesh::putNeighbour(const mesh::Identity &id, uint32_t timestamp, float snr) {
#if MAX_NEIGHBOURS // check if neighbours enabled
  // find existing neighbour, else use least recently updated
  uint32_t oldest_timestamp = 0xFFFFFFFF;
  NeighbourInfo *neighbour = &neighbours[0];
  for (int i = 0; i < MAX_NEIGHBOURS; i++) {
    // if neighbour already known, we should update it
    if (id.matches(neighbours[i].id)) {
      neighbour = &neighbours[i];
      break;
    }

    // otherwise we should update the least recently updated neighbour
    if (neighbours[i].heard_timestamp < oldest_timestamp) {
      neighbour = &neighbours[i];
      oldest_timestamp = neighbour->heard_timestamp;
    }
  }

  // update neighbour info
  neighbour->id = id;
  neighbour->advert_timestamp = timestamp;
  neighbour->heard_timestamp = getRTCClock()->getCurrentTime();
  neighbour->snr = (int8_t)(snr * 4);
#endif
}

uint8_t MyMesh::handleLoginReq(const mesh::Identity& sender, const uint8_t* secret, uint32_t sender_timestamp, const uint8_t* data, bool is_flood) {
  // Mesh dispatch has already matched the shared secret against the received packet.
  ClientInfo* client = acl.getClient(sender.pub_key, PUB_KEY_SIZE);
  if (sender_timestamp <= (client ? client->last_timestamp : 0)) return 0;

  if (!client || data[0] != 0) {
    const char* password = reinterpret_cast<const char*>(data);
    // Open is the current CLI equivalent of Normal. Strict modes retain the ACL
    // login path and prevent password-based enrollment or promotion.
    bool admin_password_matches = _prefs.password[0]
        && strncmp(password, _prefs.password, sizeof(_prefs.password)) == 0;
    if (admin_password_matches) {
      if (!client || !client->isAdmin()) {
        if (!_rules.isReady() || _rules.restricted() || acl.needsRecovery()) return 0;
        uint8_t permissions = client ? client->permissions & ~PERM_ACL_ROLE_MASK : 0;
        permissions |= PERM_ACL_ADMIN;
        if (!acl.updatePermissions(self_id, sender.pub_key, PUB_KEY_SIZE, permissions)) return 0;
        client = acl.getClient(sender.pub_key, PUB_KEY_SIZE);
      }
    } else {
      if (strncmp(password, _prefs.guest_password, sizeof(_prefs.guest_password)) != 0
          || (client && (client->permissions & PERM_ACL_ROLE_MASK) != PERM_ACL_GUEST)) return 0;
      if (!client) {
        client = acl.putClient(sender, PERM_ACL_GUEST, true);
        if (!client) return 0;
        memcpy(client->shared_secret, secret, PUB_KEY_SIZE);
      }
    }
  }

  client->last_timestamp = sender_timestamp;
  client->last_activity = getRTCClock()->getCurrentTime();
  if (is_flood) {
    client->out_path_len = OUT_PATH_UNKNOWN;  // need to rediscover out_path
  }

  uint32_t now = getRTCClock()->getCurrentTimeUnique();
  memcpy(reply_data, &now, 4);   // response packets always prefixed with timestamp
  reply_data[4] = RESP_SERVER_LOGIN_OK;
  reply_data[5] = 0;  // Legacy: was recommended keep-alive interval (secs / 16)
  reply_data[6] = client->isAdmin() ? 1 : 0;
  reply_data[7] = client->permissions;
  getRNG()->random(&reply_data[8], 4);   // random blob to help packet-hash uniqueness
  reply_data[12] = FIRMWARE_VER_LEVEL;  // New field

  return 13;  // reply length
}

uint8_t MyMesh::handleAnonRegionsReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data) {
  if (anon_limiter.allow(rtc_clock.getCurrentTime())) {
    // request data has: {reply-path-len}{reply-path}
    reply_path_len = *data++;
    if (!mesh::Packet::isValidPathLen(reply_path_len)) return 0;  // reject - bad encoding

    mesh::Packet::writePath(reply_path, data, reply_path_len);
    // data += (uint8_t)reply_path_len * reply_path_hash_size;

    memcpy(reply_data, &sender_timestamp, 4);   // prefix with sender_timestamp, like a tag
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply_data[4], &now, 4);     // include our clock (for easy clock sync, and packet hash uniqueness)

    return 8 + region_map.exportNamesTo((char *) &reply_data[8], sizeof(reply_data) - 12, REGION_DENY_FLOOD);   // reply length
  }
  return 0;
}

uint8_t MyMesh::handleAnonOwnerReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data) {
  if (anon_limiter.allow(rtc_clock.getCurrentTime())) {
    // request data has: {reply-path-len}{reply-path}
    reply_path_len = *data++;
    if (!mesh::Packet::isValidPathLen(reply_path_len)) return 0;  // reject - bad encoding

    mesh::Packet::writePath(reply_path, data, reply_path_len);
    // data += (uint8_t)reply_path_len * reply_path_hash_size;

    memcpy(reply_data, &sender_timestamp, 4);   // prefix with sender_timestamp, like a tag
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply_data[4], &now, 4);     // include our clock (for easy clock sync, and packet hash uniqueness)
    sprintf((char *) &reply_data[8], "%s\n%s", _prefs.node_name, _prefs.owner_info);

    return 8 + strlen((char *) &reply_data[8]);   // reply length
  }
  return 0;
}

uint8_t MyMesh::handleAnonClockReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data) {
  if (anon_limiter.allow(rtc_clock.getCurrentTime())) {
    // request data has: {reply-path-len}{reply-path}
    reply_path_len = *data++;
    if (!mesh::Packet::isValidPathLen(reply_path_len)) return 0;  // reject - bad encoding

    mesh::Packet::writePath(reply_path, data, reply_path_len);
    // data += (uint8_t)reply_path_len * reply_path_hash_size;

    memcpy(reply_data, &sender_timestamp, 4);   // prefix with sender_timestamp, like a tag
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply_data[4], &now, 4);     // include our clock (for easy clock sync, and packet hash uniqueness)
    reply_data[8] = 0;  // features
#ifdef WITH_RS232_BRIDGE
    reply_data[8] |= 0x01;  // is bridge, type UART
#elif WITH_ESPNOW_BRIDGE
    reply_data[8] |= 0x03;  // is bridge, type ESP-NOW
#endif
    if (_prefs.disable_fwd) {   // is this repeater currently disabled
      reply_data[8] |= 0x80;  // is disabled
    }
    // TODO:  add some kind of moving-window utilisation metric, so can query 'how busy' is this repeater
    return 9;   // reply length
  }
  return 0;
}

int MyMesh::handleRequest(ClientInfo *sender, uint32_t sender_timestamp, uint8_t *payload, size_t payload_len) {
  // uint32_t now = getRTCClock()->getCurrentTimeUnique();
  // memcpy(reply_data, &now, 4);   // response packets always prefixed with timestamp
  memcpy(reply_data, &sender_timestamp, 4); // reflect sender_timestamp back in response packet (kind of like a 'tag')

  if (payload[0] == REQ_TYPE_GET_STATUS) {  // guests can also access this now
    RepeaterStats stats;
    stats.batt_milli_volts = board.getBattMilliVolts();
    stats.curr_tx_queue_len = _mgr->getOutboundTotal();
    stats.noise_floor = (int16_t)_radio->getNoiseFloor();
    stats.last_rssi = (int16_t)radio_driver.getLastRSSI();
    stats.n_packets_recv = radio_driver.getPacketsRecv();
    stats.n_packets_sent = radio_driver.getPacketsSent();
    stats.total_air_time_secs = getTotalAirTime() / 1000;
    stats.total_up_time_secs = uptime_millis / 1000;
    stats.n_sent_flood = getNumSentFlood();
    stats.n_sent_direct = getNumSentDirect();
    stats.n_recv_flood = getNumRecvFlood();
    stats.n_recv_direct = getNumRecvDirect();
    stats.err_events = _err_flags;
    stats.last_snr = (int16_t)(radio_driver.getLastSNR() * 4);
    stats.n_direct_dups = ((SimpleMeshTables *)getTables())->getNumDirectDups();
    stats.n_flood_dups = ((SimpleMeshTables *)getTables())->getNumFloodDups();
    stats.total_rx_air_time_secs = getReceiveAirTime() / 1000;
    stats.n_recv_errors = radio_driver.getPacketsRecvErrors();
    memcpy(&reply_data[4], &stats, sizeof(stats));

    return 4 + sizeof(stats); //  reply_len
  }
  if (payload[0] == REQ_TYPE_GET_TELEMETRY_DATA) {
    uint8_t perm_mask = ~(payload[1]); // NEW: first reserved byte (of 4), is now inverse mask to apply to permissions

    telemetry.reset();
    telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);

    // query other sensors -- target specific
    if ((sender->permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST) {
      perm_mask = 0x00;  // just base telemetry allowed
    }
    sensors.querySensors(perm_mask, telemetry);

	// This default temperature will be overridden by external sensors (if any)
    float temperature = board.getMCUTemperature();
    if(!isnan(temperature)) { // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
      telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature); // Built-in MCU Temperature
    }

    uint8_t tlen = telemetry.getSize();
    memcpy(&reply_data[4], telemetry.getBuffer(), tlen);
    return 4 + tlen; // reply_len
  }
  if (payload[0] == REQ_TYPE_GET_ACCESS_LIST && sender->isAdmin()) {
    uint8_t res1 = payload[1];   // reserved for future  (extra query params)
    uint8_t res2 = payload[2];
    if (res1 == 0 && res2 == 0) {
      uint8_t ofs = 4;
      for (int i = 0; i < acl.getNumClients() && ofs + 7 <= sizeof(reply_data) - 4; i++) {
        auto c = acl.getClientByIdx(i);
        if (c->permissions == 0) continue;  // skip deleted entries
        memcpy(&reply_data[ofs], c->id.pub_key, 6); ofs += 6;  // just 6-byte pub_key prefix
        reply_data[ofs++] = c->permissions;
      }
      return ofs;
    }
  }
  if (payload[0] == REQ_TYPE_GET_NEIGHBOURS) {
    uint8_t request_version = payload[1];
    if (request_version == 0) {

      // reply data offset (after response sender_timestamp/tag)
      int reply_offset = 4;

      // get request params
      uint8_t count = payload[2]; // how many neighbours to fetch (0-255)
      uint16_t offset;
      memcpy(&offset, &payload[3], 2); // offset from start of neighbours list (0-65535)
      uint8_t order_by = payload[5]; // how to order neighbours. 0=newest_to_oldest, 1=oldest_to_newest, 2=strongest_to_weakest, 3=weakest_to_strongest
      uint8_t pubkey_prefix_length = payload[6]; // how many bytes of neighbour pub key we want
      // we also send a 4 byte random blob in payload[7...10] to help packet uniqueness

      MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS count=%d, offset=%d, order_by=%d, pubkey_prefix_length=%d", count, offset, order_by, pubkey_prefix_length);

      // clamp pub key prefix length to max pub key length
      if(pubkey_prefix_length > PUB_KEY_SIZE){
        pubkey_prefix_length = PUB_KEY_SIZE;
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS invalid pubkey_prefix_length=%d clamping to %d", pubkey_prefix_length, PUB_KEY_SIZE);
      }

      // create copy of neighbours list, skipping empty entries so we can sort it separately from main list
      int16_t neighbours_count = 0;
#if MAX_NEIGHBOURS
      NeighbourInfo* sorted_neighbours[MAX_NEIGHBOURS];
      for (int i = 0; i < MAX_NEIGHBOURS; i++) {
        auto neighbour = &neighbours[i];
        if (neighbour->heard_timestamp > 0) {
          sorted_neighbours[neighbours_count] = neighbour;
          neighbours_count++;
        }
      }

      // sort neighbours based on order
      if (order_by == 0) {
        // sort by newest to oldest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting newest to oldest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->heard_timestamp > b->heard_timestamp; // desc
        });
      } else if (order_by == 1) {
        // sort by oldest to newest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting oldest to newest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->heard_timestamp < b->heard_timestamp; // asc
        });
      } else if (order_by == 2) {
        // sort by strongest to weakest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting strongest to weakest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->snr > b->snr; // desc
        });
      } else if (order_by == 3) {
        // sort by weakest to strongest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting weakest to strongest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->snr < b->snr; // asc
        });
      }
#endif

      // build results buffer
      int results_count = 0;
      int results_offset = 0;
      uint8_t results_buffer[130];
      for(int index = 0; index < count && index + offset < neighbours_count; index++){

        // stop if we can't fit another entry in results
        int entry_size = pubkey_prefix_length + 4 + 1;
        if(results_offset + entry_size > sizeof(results_buffer)){
          MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS no more entries can fit in results buffer");
          break;
        }

#if MAX_NEIGHBOURS
        // add next neighbour to results
        auto neighbour = sorted_neighbours[index + offset];
        uint32_t heard_seconds_ago = getRTCClock()->getCurrentTime() - neighbour->heard_timestamp;
        memcpy(&results_buffer[results_offset], neighbour->id.pub_key, pubkey_prefix_length); results_offset += pubkey_prefix_length;
        memcpy(&results_buffer[results_offset], &heard_seconds_ago, 4); results_offset += 4;
        memcpy(&results_buffer[results_offset], &neighbour->snr, 1); results_offset += 1;
        results_count++;
#endif

      }

      // build reply
      MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS neighbours_count=%d results_count=%d", neighbours_count, results_count);
      memcpy(&reply_data[reply_offset], &neighbours_count, 2); reply_offset += 2;
      memcpy(&reply_data[reply_offset], &results_count, 2); reply_offset += 2;
      memcpy(&reply_data[reply_offset], &results_buffer, results_offset); reply_offset += results_offset;

      return reply_offset;
    }
  } else if (payload[0] == REQ_TYPE_GET_OWNER_INFO) {
    sprintf((char *) &reply_data[4], "%s\n%s\n%s", FIRMWARE_VERSION, _prefs.node_name, _prefs.owner_info);
    return 4 + strlen((char *) &reply_data[4]);
  }
  return 0; // unknown command
}

mesh::Packet *MyMesh::createSelfAdvert() {
  uint8_t app_data[MAX_ADVERT_DATA_SIZE];
  uint8_t app_data_len = _cli.buildAdvertData(ADV_TYPE_REPEATER, app_data);

  return createAdvert(self_id, app_data, app_data_len);
}

File MyMesh::openAppend(const char *fname) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return _fs->open(fname, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return _fs->open(fname, "a");
#else
  return _fs->open(fname, "a", true);
#endif
}

static uint8_t max_loop_minimal[] =  { 0, /* 1-byte */  4, /* 2-byte */  2, /* 3-byte */  1 };
static uint8_t max_loop_moderate[] = { 0, /* 1-byte */  2, /* 2-byte */  1, /* 3-byte */  1 };
static uint8_t max_loop_strict[] =   { 0, /* 1-byte */  1, /* 2-byte */  1, /* 3-byte */  1 };

bool MyMesh::isLooped(const mesh::Packet* packet, const uint8_t max_counters[]) {
  uint8_t hash_size = packet->getPathHashSize();
  uint8_t hash_count = packet->getPathHashCount();
  uint8_t n = 0;
  const uint8_t* path = packet->path;
  while (hash_count > 0) {      // count how many times this node is already in the path
    if (self_id.isHashMatch(path, hash_size)) n++;
    hash_count--;
    path += hash_size;
  }
  return n >= max_counters[hash_size];
}

void MyMesh::sendFloodReply(mesh::Packet* packet, unsigned long delay_millis, uint8_t path_hash_size) {
  TransportKey req_scope;
  bool is_wildcard = recv_pkt_region != NULL && recv_pkt_region->isWildcard();
  bool req_scope_known = recv_pkt_region != NULL && !is_wildcard
                      && region_map.getTransportKeysFor(*recv_pkt_region, &req_scope, 1) > 0;

  switch (mesh::chooseReplyScope(req_scope_known, is_wildcard, !default_scope.isNull())) {
    case mesh::REPLY_SCOPE_REQUEST:
      sendFloodScoped(req_scope, packet, delay_millis, path_hash_size);   // reply with same scope as request
      break;
    case mesh::REPLY_SCOPE_DEFAULT:
      // requester's scope is unknown: DIRECT request (no transport codes), or code matched no Region.
      // un-scoped would be dropped at hop 0 by repeaters running flood.max.unscoped=0
      sendFloodScoped(default_scope, packet, delay_millis, path_hash_size);
      break;
    case mesh::REPLY_SCOPE_NONE:
      sendFlood(packet, delay_millis, path_hash_size);  // send un-scoped
      break;
  }
}

bool MyMesh::allowPacketForward(const mesh::Packet *packet) {
  if (_prefs.disable_fwd) return false;
  if (packet->isRouteFlood()
      && mesh::isFloodHopLimitExceeded(packet, _prefs.flood_max, _prefs.flood_max_unscoped, _prefs.flood_max_advert)) {
    return false;
  }
  if (packet->isRouteFlood() && recv_pkt_region == NULL) {
    MESH_DEBUG_PRINTLN("allowPacketForward: unknown transport code, or wildcard not allowed for FLOOD packet");
    return false;
  }
  if (packet->isRouteFlood() && _prefs.loop_detect != LOOP_DETECT_OFF) {
    const uint8_t* maximums;
    if (_prefs.loop_detect == LOOP_DETECT_MINIMAL) {
      maximums = max_loop_minimal;
    } else if (_prefs.loop_detect == LOOP_DETECT_MODERATE) {
      maximums = max_loop_moderate;
    } else {
      maximums = max_loop_strict;
    }
    if (isLooped(packet, maximums)) {
      MESH_DEBUG_PRINTLN("allowPacketForward: FLOOD packet loop detected!");
      return false;
    }
  }
  if (shouldDropByFilter(packet)) {
    ++_filter_drops;
    return false;
  }
  if (packet->isRouteDirect() && shouldDropAdvert(packet, false)) {
    ++_identity_drops;
    return false;
  }
  return !shouldDropByRate(packet, _radio_forward_budget);
}

bool MyMesh::shouldDropByFilter(const mesh::Packet* packet) const {
  return savemesh::shouldDropOneByte(packet, _filter_prefs.filter_1byte || _rules.filterEnabled(RuleStore::OneByte))
      || savemesh::shouldDropData(packet, _filter_prefs.filter_data || _rules.filterEnabled(RuleStore::Data))
      || ((_filter_prefs.filter_public || _rules.filterEnabled(RuleStore::Public)) && isPublicChannelPacket(packet));
}

bool MyMesh::shouldDropByRate(const mesh::Packet* packet, ForwardBudget& budget) {
  uint16_t limit = _rules.unknownRate();
  if (!limit) return false;
  uint8_t type = packet->getPayloadType();
  if (type != PAYLOAD_TYPE_GRP_TXT && type != PAYLOAD_TYPE_GRP_DATA && type != PAYLOAD_TYPE_ANON_REQ) return false;
  uint32_t now = millis();
  if (now - budget.window_start >= 60000) {
    budget.count = 0;
    budget.window_start = now;
  }
  if (budget.count < limit) {
    ++budget.count;
    return false;
  }
  ++_rate_drops;
  return true;
}

bool MyMesh::shouldDropAdvert(const mesh::Packet* packet, bool signature_verified) const {
  constexpr size_t SignedPrefixSize = PUB_KEY_SIZE + sizeof(uint32_t);
  constexpr size_t AdvertPrefixSize = SignedPrefixSize + SIGNATURE_SIZE;
  if (packet->getPayloadType() != PAYLOAD_TYPE_ADVERT) return false;
  if (packet->payload_len < AdvertPrefixSize) return true;

  size_t app_len = std::min<size_t>(packet->payload_len - AdvertPrefixSize, MAX_ADVERT_DATA_SIZE);
  const uint8_t* app_data = packet->payload + AdvertPrefixSize;
  AdvertDataParser parser(app_data, app_len);
  if (!parser.isValid()) return false;

  RuleStore::Subject subject;
  if (parser.getType() == ADV_TYPE_REPEATER) subject = RuleStore::Repeater;
  else if (parser.getType() == ADV_TYPE_CHAT) subject = RuleStore::Client;
  else return false;

  auto decision = _rules.decide(subject, packet->payload);
  if (decision != RuleStore::Denied && (decision != RuleStore::Unknown || !_rules.restricted())) return false;
  if (signature_verified) return true;

  // Mesh dispatch verifies flood adverts before onAdvertRecv. Routed direct
  // traffic and bridge exports can reach their forwarding gate earlier.
  uint8_t message[SignedPrefixSize + MAX_ADVERT_DATA_SIZE];
  memcpy(message, packet->payload, SignedPrefixSize);
  memcpy(message + SignedPrefixSize, app_data, app_len);
  mesh::Identity id(packet->payload);
  return id.verify(packet->payload + SignedPrefixSize, message, SignedPrefixSize + app_len);
}

bool MyMesh::shouldDenyClient(const mesh::Identity& id) {
  auto decision = _rules.decide(RuleStore::Client, id.pub_key);
  if (decision == RuleStore::Denied) return true;
  if (decision == RuleStore::Allowed || !_rules.restricted()) return false;
  auto client = acl.getClient(id.pub_key, PUB_KEY_SIZE);
  return !client || (client->permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST;
}

const char *MyMesh::getLogDateTime() {
  static char tmp[32];
  uint32_t now = getRTCClock()->getCurrentTime();
  DateTime dt = DateTime(now);
  sprintf(tmp, "%02d:%02d:%02d - %d/%d/%d U", dt.hour(), dt.minute(), dt.second(), dt.day(), dt.month(),
          dt.year());
  return tmp;
}

void MyMesh::logRxRaw(float snr, float rssi, const uint8_t raw[], int len) {
#if MESH_PACKET_LOGGING
  Serial.print(getLogDateTime());
  Serial.print(" RAW: ");
  mesh::Utils::printHex(Serial, raw, len);
  Serial.println();
#endif
}

void MyMesh::logRx(mesh::Packet *pkt, int len, float score) {
#ifdef WITH_BRIDGE
  if (_prefs.bridge_pkt_src == 1 && !shouldDropByFilter(pkt) && !shouldDropAdvert(pkt, false)
      && !shouldDropByRate(pkt, _bridge_forward_budget)) {
    bridge.sendPacket(pkt);
  }
#endif

  if (_logging) {
    File f = openAppend(PACKET_LOG_FILE);
    if (f) {
      f.print(getLogDateTime());
      f.printf(": RX, len=%d (type=%d, route=%s, payload_len=%d) SNR=%d RSSI=%d score=%d", len,
               pkt->getPayloadType(), pkt->isRouteDirect() ? "D" : "F", pkt->payload_len,
               (int)_radio->getLastSNR(), (int)_radio->getLastRSSI(), (int)(score * 1000));

      if (pkt->getPayloadType() == PAYLOAD_TYPE_PATH || pkt->getPayloadType() == PAYLOAD_TYPE_REQ ||
          pkt->getPayloadType() == PAYLOAD_TYPE_RESPONSE || pkt->getPayloadType() == PAYLOAD_TYPE_TXT_MSG) {
        f.printf(" [%02X -> %02X]\n", (uint32_t)pkt->payload[1], (uint32_t)pkt->payload[0]);
      } else {
        f.printf("\n");
      }
      f.close();
    }
  }
}

void MyMesh::logTx(mesh::Packet *pkt, int len) {
#ifdef WITH_BRIDGE
  if (_prefs.bridge_pkt_src == 0 && !shouldDropByFilter(pkt) && !shouldDropAdvert(pkt, false)
      && !shouldDropByRate(pkt, _bridge_forward_budget)) {
    bridge.sendPacket(pkt);
  }
#endif

  if (_logging) {
    File f = openAppend(PACKET_LOG_FILE);
    if (f) {
      f.print(getLogDateTime());
      f.printf(": TX, len=%d (type=%d, route=%s, payload_len=%d)", len, pkt->getPayloadType(),
               pkt->isRouteDirect() ? "D" : "F", pkt->payload_len);

      if (pkt->getPayloadType() == PAYLOAD_TYPE_PATH || pkt->getPayloadType() == PAYLOAD_TYPE_REQ ||
          pkt->getPayloadType() == PAYLOAD_TYPE_RESPONSE || pkt->getPayloadType() == PAYLOAD_TYPE_TXT_MSG) {
        f.printf(" [%02X -> %02X]\n", (uint32_t)pkt->payload[1], (uint32_t)pkt->payload[0]);
      } else {
        f.printf("\n");
      }
      f.close();
    }
  }
}

void MyMesh::logTxFail(mesh::Packet *pkt, int len) {
  if (_logging) {
    File f = openAppend(PACKET_LOG_FILE);
    if (f) {
      f.print(getLogDateTime());
      f.printf(": TX FAIL!, len=%d (type=%d, route=%s, payload_len=%d)\n", len, pkt->getPayloadType(),
               pkt->isRouteDirect() ? "D" : "F", pkt->payload_len);
      f.close();
    }
  }
}

int MyMesh::calcRxDelay(float score, uint32_t air_time) const {
  if (_prefs.rx_delay_base <= 0.0f) return 0;
  return (int)((pow(_prefs.rx_delay_base, 0.85f - score) - 1.0) * air_time);
}

uint32_t MyMesh::getRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}
uint32_t MyMesh::getDirectRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.direct_tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}

mesh::DispatcherAction MyMesh::onRecvPacket(mesh::Packet* pkt) {
  if (pkt->getRouteType() == ROUTE_TYPE_TRANSPORT_FLOOD) {
    recv_pkt_region = region_map.findMatch(pkt, REGION_DENY_FLOOD);
  } else if (pkt->getRouteType() == ROUTE_TYPE_FLOOD) {
    if (region_map.getWildcard().flags & REGION_DENY_FLOOD) {
      recv_pkt_region = NULL;
    } else {
      recv_pkt_region =  &region_map.getWildcard();
    }
  } else {
    recv_pkt_region = NULL;
  }
  if (pkt->getPayloadType() == PAYLOAD_TYPE_CONTROL && pkt->payload_len == PolicyPayloadSize
      && pkt->payload[0] == PolicyType) {
    return receivePolicyUpdate(pkt);
  }
  if (receiveAdminRoom(pkt)) return ACTION_RELEASE;
  return Mesh::onRecvPacket(pkt);
}

mesh::DispatcherAction MyMesh::receivePolicyUpdate(mesh::Packet* packet) {
  if (!packet->isRouteFlood() || !recv_pkt_region || !packet->received_over_radio
      || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)
      || getTables()->wasSeen(packet)) return ACTION_RELEASE;
  if (_next_policy_commit && !millisHasNowPassed(_next_policy_commit)) return ACTION_RELEASE;

  GCM<AES128> cipher;
  if (!cipher.setKey(_rules.syncKey(), CIPHER_KEY_SIZE) || !cipher.setIV(packet->payload + 1, PolicyNonceSize)) {
    return ACTION_RELEASE;
  }
  cipher.addAuthData(packet->payload, 1);
  uint8_t data[PolicyDataSize];
  cipher.decrypt(data, packet->payload + PolicyHeaderSize, sizeof(data));
  if (!cipher.checkTag(packet->payload + PolicyHeaderSize + sizeof(data), PolicyTagSize)) return ACTION_RELEASE;
  RuleStore::Rule rule{};
  memcpy(&rule, data + RuleStore::FingerprintSize, RuleStore::WireSize);
  if (rule.scope == RuleStore::Region && (recv_pkt_region->isWildcard()
      || strcmp(recv_pkt_region->name, _rules.scopeName(RuleStore::Region)) != 0)) return ACTION_RELEASE;
  auto result = _rules.mergeRule(rule, data, self_id);
  if (result == RuleStore::Rejected) return ACTION_RELEASE;
  getTables()->markSeen(packet);
  if (result == RuleStore::Current) return ACTION_RELEASE;
  _next_policy_commit = futureMillis(2000);
  return routeRecvPacket(packet);
}

void MyMesh::sendPolicyUpdate() {
  if (_sync_cursor >= RuleStore::Capacity || _mgr->getOutboundTotal() != 0
      || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)
      || (_next_policy_tx && !millisHasNowPassed(_next_policy_tx))) return;
  for (; _sync_cursor < RuleStore::Capacity; ++_sync_cursor) {
    const auto* rule = _rules.exportRule(_sync_cursor);
    if (!rule || (!self_id.matches(rule->origin) && !_rules.trustedPeer(rule->origin))) continue;
    TransportKey transport{};
    if (rule->scope == RuleStore::Region) {
      auto region = region_map.findByName(_rules.scopeName(RuleStore::Region));
      if (!region || region_map.getTransportKeysFor(*region, &transport, 1) != 1 || transport.isNull()) continue;
    }
    uint8_t payload[PolicyPayloadSize];
    payload[0] = PolicyType;
    getRNG()->random(payload + 1, PolicyNonceSize);
    GCM<AES128> cipher;
    if (!cipher.setKey(_rules.syncKey(), CIPHER_KEY_SIZE) || !cipher.setIV(payload + 1, PolicyNonceSize)) return;
    cipher.addAuthData(payload, 1);
    uint8_t data[PolicyDataSize];
    memcpy(data, rule->origin, RuleStore::FingerprintSize);
    memcpy(data + RuleStore::FingerprintSize, rule, RuleStore::WireSize);
    cipher.encrypt(payload + PolicyHeaderSize, data, sizeof(data));
    cipher.computeTag(payload + PolicyHeaderSize + sizeof(data), PolicyTagSize);
    auto packet = createControlData(payload, sizeof(payload));
    if (!packet) return;
    ++_sync_cursor;
    _next_policy_tx = futureMillis(60 * 1000);
    sendFloodScoped(transport, packet, 0, _prefs.path_hash_mode + 1);
    return;
  }
}

bool MyMesh::handleSyncCommand(const char* command, char* reply, bool usb, bool can_write) {
  if (matchesValue(command, "sync status")) {
    snprintf(reply, 150, "domain=%s region=%s key=%s sync=%s", _rules.scopeName(RuleStore::Global),
             _rules.scopeName(RuleStore::Region),
             mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE) ? "off" : "set",
             _sync_cursor < RuleStore::Capacity ? "queued" : "idle");
    return true;
  }
  if (matchesValue(command, "sync")) {
    if (!can_write) strcpy(reply, "Err - write permission required");
    else if (!_rules.scopeName(RuleStore::Global)[0] || mesh::Utils::isZeroes(_rules.syncKey(), CIPHER_KEY_SIZE)) {
      strcpy(reply, "Err - configure a policy domain and key");
    }
    else {
      _sync_cursor = 0;
      strcpy(reply, "OK - policy sync queued");
    }
    return true;
  }
  const char* arg;
  if (matchCommand(command, "sync.key", &arg)) {
    uint8_t key[CIPHER_KEY_SIZE]{};
    bool ok = usb && (matchesValue(arg, "off")
        || (savemesh::isHex(arg, 2 * sizeof(key)) && mesh::Utils::fromHex(key, sizeof(key), arg)
            && !mesh::Utils::isZeroes(key, sizeof(key)))) && _rules.setSyncKey(key);
    if (ok && mesh::Utils::isZeroes(key, sizeof(key))) _sync_cursor = RuleStore::Capacity;
    strcpy(reply, ok ? "OK" : "Err - use USB with a private 16-byte sync key");
    return true;
  }
  RuleStore::Scope scope;
  if (matchCommand(command, "domain", &arg)) scope = RuleStore::Global;
  else if (matchCommand(command, "region", &arg)) scope = RuleStore::Region;
  else scope = RuleStore::Local;
  if (scope != RuleStore::Local) {
    bool ok = usb && _rules.setScope(scope, arg);
    strcpy(reply, ok ? "OK" : "Err - use USB and an unused valid scope");
    return true;
  }
  bool trust = matchCommand(command, "trust", &arg);
  if (trust || matchCommand(command, "untrust", &arg)) {
    uint8_t key[PUB_KEY_SIZE];
    bool ok = usb && savemesh::isHex(arg, 2 * sizeof(key)) && mesh::Utils::fromHex(key, sizeof(key), arg)
           && _rules.setTrustedPeer(key, trust, self_id);
    strcpy(reply, ok ? "OK" : "Err - use USB and a valid peer key");
    return true;
  }
  return false;
}

void MyMesh::onAnonDataRecv(mesh::Packet *packet, const uint8_t *secret, const mesh::Identity &sender,
                            uint8_t *data, size_t len) {
  if (len <= sizeof(uint32_t) || shouldDenyClient(sender)) return;
  if (packet->getPayloadType() == PAYLOAD_TYPE_ANON_REQ) { // received an initial request by a possible admin
                                                           // client (unknown at this stage)
    uint32_t timestamp;
    memcpy(&timestamp, data, 4);

    data[len] = 0;  // ensure null terminator
    uint8_t reply_len;

    reply_path_len = 0xFF;
    if (data[4] == 0 || data[4] >= ' ') {   // is password, ie. a login request
      reply_len = handleLoginReq(sender, secret, timestamp, &data[4], packet->isRouteFlood());
    } else if (data[4] == ANON_REQ_TYPE_REGIONS && packet->isRouteDirect()) {
      reply_len = handleAnonRegionsReq(sender, timestamp, &data[5]);
    } else if (data[4] == ANON_REQ_TYPE_OWNER && packet->isRouteDirect()) {
      reply_len = handleAnonOwnerReq(sender, timestamp, &data[5]);
    } else if (data[4] == ANON_REQ_TYPE_BASIC && packet->isRouteDirect()) {
      reply_len = handleAnonClockReq(sender, timestamp, &data[5]);
    } else {
      reply_len = 0;  // unknown/invalid request type
    }

    if (reply_len == 0) return;   // invalid request

    // a DIRECT login can reply via the stored out_path, as onPeerDataRecv() does for REQ
    ClientInfo* client = acl.getClient(sender.pub_key, PUB_KEY_SIZE);
    bool have_out_path = client != NULL && client->out_path_len != OUT_PATH_UNKNOWN;

    auto route = mesh::chooseReplyRoute(packet->isRouteFlood(), reply_path_len != 0xFF, have_out_path);

    if (route == mesh::REPLY_ROUTE_PATH_RETURN) {
      // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the response
      mesh::Packet* path = createPathReturn(sender, secret, packet->path, packet->path_len,
                                            PAYLOAD_TYPE_RESPONSE, reply_data, reply_len);
      if (path) sendFloodReply(path, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
      return;
    }

    mesh::Packet* reply = createDatagram(PAYLOAD_TYPE_RESPONSE, sender, secret, reply_data, reply_len);
    if (reply == NULL) return;

    if (route == mesh::REPLY_ROUTE_DIRECT_SUPPLIED) {
      sendDirect(reply, reply_path, reply_path_len, SERVER_RESPONSE_DELAY);
    } else if (route == mesh::REPLY_ROUTE_DIRECT_OUT_PATH) {
      sendDirect(reply, client->out_path, client->out_path_len, SERVER_RESPONSE_DELAY);
    } else {
      sendFloodReply(reply, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
    }
  }
}

int MyMesh::searchPeersByHash(const uint8_t *hash) {
  int n = 0;
  for (int i = 0; i < acl.getNumClients(); i++) {
    if (acl.getClientByIdx(i)->id.isHashMatch(hash)) {
      matching_peer_indexes[n++] = i; // store the INDEXES of matching contacts (for subsequent 'peer' methods)
    }
  }
  return n;
}

void MyMesh::getPeerSharedSecret(uint8_t *dest_secret, int peer_idx) {
  int i = matching_peer_indexes[peer_idx];
  if (i >= 0 && i < acl.getNumClients()) {
    // lookup pre-calculated shared_secret
    memcpy(dest_secret, acl.getClientByIdx(i)->shared_secret, PUB_KEY_SIZE);
  } else {
    MESH_DEBUG_PRINTLN("getPeerSharedSecret: Invalid peer idx: %d", i);
  }
}

static bool isShare(const mesh::Packet *packet) {
  if (packet->hasTransportCodes()) {
    return packet->transport_codes[0] == 0 && packet->transport_codes[1] == 0;  // codes { 0, 0 } means 'send to nowhere'
  }
  return false;
}

void MyMesh::noteDirectNeighbour(const mesh::Identity& id, bool repeater) {
  const uint8_t empty[RuleStore::ChannelKeySize]{};
  if (memcmp(_rules.neighbourChannel(), empty, sizeof(empty)) == 0) return;
  uint32_t now = getRTCClock()->getCurrentTime();
  for (size_t i = 0; i < _notice_count; i++) {
    if (id.matches(_notices[i].key)) {
      _notices[i].last_seen = now;
      return;
    }
  }
  if (_notice_count == NoticeCapacity) return;
  auto& entry = _notices[_notice_count++];
  memcpy(entry.key, id.pub_key, PUB_KEY_SIZE);
  entry.last_seen = now;
  entry.repeater = repeater;
  entry.pending = true;
}

void MyMesh::sendNeighbourNotice() {
  if (_next_notice && !millisHasNowPassed(_next_notice)) return;
  if (_mgr->getOutboundTotal() != 0) return;
  for (size_t i = 0; i < _notice_count; i++) {
    auto& entry = _notices[i];
    if (!entry.pending) continue;
    mesh::GroupChannel channel{};
    memcpy(channel.secret, _rules.neighbourChannel(), RuleStore::ChannelKeySize);
    mesh::Utils::sha256(channel.hash, sizeof(channel.hash), channel.secret, RuleStore::ChannelKeySize);

    uint8_t message[80];
    uint32_t stamp = getRTCClock()->getCurrentTimeUnique();
    memcpy(message, &stamp, sizeof(stamp));
    message[4] = TXT_TYPE_PLAIN << 2;
    char fingerprint[13];
    mesh::Utils::toHex(fingerprint, entry.key, 6);
    size_t length = snprintf(reinterpret_cast<char*>(message + 5), sizeof(message) - 5,
                             "MeshCore Hardened: direct %s %s",
                             entry.repeater ? "repeater" : "client", fingerprint);
    auto packet = createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, channel, message, 5 + length);
    if (!packet) return;
    if (region_map.getDefaultRegion() && !default_scope.isNull()) {
      sendFloodScoped(default_scope, packet, 0, _prefs.path_hash_mode + 1);
    } else {
      sendZeroHop(packet);
    }
    entry.pending = false;
    _next_notice = futureMillis(5 * 60 * 1000UL);
    return;
  }
}

void MyMesh::handleNeighbourCommand(const char* command, char* reply, bool usb) {
  const uint8_t empty[RuleStore::ChannelKeySize]{};
  const char* arg;
  if (matchesValue(command, "status")) {
    bool enabled = memcmp(_rules.neighbourChannel(), empty, sizeof(empty)) != 0;
    unsigned pending = 0;
    for (size_t i = 0; i < _notice_count; i++) pending += _notices[i].pending;
    snprintf(reply, 150, "channel=%s observed=%u pending=%u",
             enabled ? "set" : "off", static_cast<unsigned>(_notice_count), pending);
    return;
  }
  if (matchCommand(command, "show", &arg)) {
    uint16_t index;
    if (!parseUnsigned(arg, &index) || index >= _notice_count) {
      strcpy(reply, "Err - no neighbour at that index");
      return;
    }
    const auto& entry = _notices[index];
    char key[PUB_KEY_SIZE * 2 + 1];
    mesh::Utils::toHex(key, entry.key, PUB_KEY_SIZE);
    snprintf(reply, 150, "%s %s last=%lu", entry.repeater ? "repeater" : "client",
             key, static_cast<unsigned long>(entry.last_seen));
    return;
  }
  if (!usb) {
    strcpy(reply, "Err - use USB for neighbour settings");
    return;
  }
  if (matchesValue(command, "reset")) {
    _notice_count = 0;
    strcpy(reply, "OK");
    return;
  }
  if (!matchCommand(command, "channel", &arg)) {
    strcpy(reply, "Err - use neighbours status/show/reset/channel");
    return;
  }
  uint8_t key[RuleStore::ChannelKeySize]{};
  if (!matchesValue(arg, "off")) {
    const uint8_t public_key[] = {0x8b, 0x33, 0x87, 0xc9, 0xc5, 0xcd, 0xea, 0x6a,
                                  0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72};
    if (!savemesh::isHex(arg, 2 * sizeof(key)) || !mesh::Utils::fromHex(key, sizeof(key), arg)
        || memcmp(key, empty, sizeof(key)) == 0 || memcmp(key, public_key, sizeof(key)) == 0) {
      strcpy(reply, "Err - expected a 16-byte private channel key");
      return;
    }
  }
  if (!_rules.setNeighbourChannel(key)) {
    strcpy(reply, "Err - channel storage write failed");
    return;
  }
  _notice_count = 0;
  strcpy(reply, "OK");
}

void MyMesh::onAdvertRecv(mesh::Packet *packet, const mesh::Identity &id, uint32_t timestamp,
                          const uint8_t *app_data, size_t app_data_len) {
  if (shouldDropAdvert(packet, true)) {
    ++_identity_drops;
    packet->markDoNotRetransmit();
    return;
  }
  mesh::Mesh::onAdvertRecv(packet, id, timestamp, app_data, app_data_len); // chain to super impl

  // if this a zero hop advert (and not via 'Share'), add it to neighbours
  if (packet->getPathHashCount() == 0 && !isShare(packet)) {
    AdvertDataParser parser(app_data, app_data_len);
    if (parser.isValid() && parser.getType() == ADV_TYPE_REPEATER) { // just keep neigbouring Repeaters
      putNeighbour(id, timestamp, packet->getSNR());
    }
    if (packet->received_over_radio && parser.isValid() && (!packet->isRouteFlood() || recv_pkt_region)) {
      if (parser.getType() == ADV_TYPE_REPEATER) noteDirectNeighbour(id, true);
      else if (parser.getType() == ADV_TYPE_CHAT
               && _rules.decide(RuleStore::Client, id.pub_key) == RuleStore::Allowed) {
        noteDirectNeighbour(id, false);
      }
    }
  }
}

void MyMesh::onPeerDataRecv(mesh::Packet *packet, uint8_t type, int sender_idx, const uint8_t *secret,
                            uint8_t *data, size_t len) {
  int i = matching_peer_indexes[sender_idx];
  if (i < 0 || i >= acl.getNumClients()) { // get from our known_clients table (sender SHOULD already be known in this context)
    MESH_DEBUG_PRINTLN("onPeerDataRecv: invalid peer idx: %d", i);
    return;
  }
  ClientInfo* client = acl.getClientByIdx(i);
  if (len <= sizeof(uint32_t) || shouldDenyClient(client->id)) return;

  if (type == PAYLOAD_TYPE_REQ) { // request (from a Known admin client!)
    uint32_t timestamp;
    memcpy(&timestamp, data, 4);

    if (timestamp > client->last_timestamp) { // prevent replay attacks
      int reply_len = handleRequest(client, timestamp, &data[4], len - 4);
      if (reply_len == 0) return; // invalid command

      client->last_timestamp = timestamp;
      client->last_activity = getRTCClock()->getCurrentTime();

      if (packet->isRouteFlood()) {
        // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the response
        mesh::Packet *path = createPathReturn(client->id, secret, packet->path, packet->path_len,
                                              PAYLOAD_TYPE_RESPONSE, reply_data, reply_len);
        if (path) sendFloodReply(path, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
      } else {
        mesh::Packet *reply =
            createDatagram(PAYLOAD_TYPE_RESPONSE, client->id, secret, reply_data, reply_len);
        if (reply) {
          if (client->out_path_len != OUT_PATH_UNKNOWN) { // we have an out_path, so send DIRECT
            sendDirect(reply, client->out_path, client->out_path_len, SERVER_RESPONSE_DELAY);
          } else {
            sendFloodReply(reply, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
          }
        }
      }
    } else {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: possible replay attack detected");
    }
  } else if (type == PAYLOAD_TYPE_TXT_MSG && len > 5
             && (client->permissions & PERM_ACL_ROLE_MASK) != PERM_ACL_GUEST) {
    uint32_t sender_timestamp;
    memcpy(&sender_timestamp, data, 4); // timestamp (by sender's RTC clock - which could be wrong)
    uint8_t flags = (data[4] >> 2);        // message attempt number, and other flags

    if (!(flags == TXT_TYPE_PLAIN || flags == TXT_TYPE_CLI_DATA || flags == TXT_TYPE_CLI_COMMAND)) {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: unsupported text type received: flags=%02x", (uint32_t)flags);
    } else if (sender_timestamp >= client->last_timestamp) { // prevent replay attacks
      bool is_retry = (sender_timestamp == client->last_timestamp);
      client->last_timestamp = sender_timestamp;
      client->last_activity = getRTCClock()->getCurrentTime();

      // len can be > original length, but 'text' will be padded with zeroes
      data[len] = 0; // need to make a C string again, with null terminator
      if (!client->isAdmin()) {
        const char* command = reinterpret_cast<const char*>(&data[5]);
        while (*command == ' ') ++command;
        if (strlen(command) > 4 && command[2] == '|') command += 3;
        const char* args;
        if (!matchCommand(command, "rules", &args)) return;
      }

      if (flags == TXT_TYPE_PLAIN) { // for legacy CLI, send Acks
        uint32_t ack_hash; // calc truncated hash of the message timestamp + text + sender pub_key, to prove
                           // to sender that we got it
        mesh::Utils::sha256((uint8_t *)&ack_hash, 4, data, 5 + strlen((char *)&data[5]), client->id.pub_key,
                            PUB_KEY_SIZE);

        mesh::Packet *ack = createAck(ack_hash);
        if (ack) {
          if (client->out_path_len == OUT_PATH_UNKNOWN) {
            sendFloodReply(ack, TXT_ACK_DELAY, packet->getPathHashSize());
          } else {
            sendDirect(ack, client->out_path, client->out_path_len, TXT_ACK_DELAY);
          }
        }
      }

      uint8_t temp[166];
      char *command = (char *)&data[5];
      char *reply = (char *)&temp[5];
      // An ACL command can remove or move the entry for the current sender.
      const mesh::Identity sender = client->id;
      uint8_t cli_reply_path[MAX_PATH_SIZE];
      uint8_t cli_reply_path_len = client->out_path_len;
      if (cli_reply_path_len != OUT_PATH_UNKNOWN) {
        mesh::Packet::copyPath(cli_reply_path, client->out_path, cli_reply_path_len);
      }
      if (is_retry) {
        *reply = 0;
      } else {
        handleCommand(sender_timestamp, command, reply, client);
      }
      int text_len = strlen(reply);
      if (text_len > 0) {
        uint32_t timestamp = getRTCClock()->getCurrentTimeUnique();
        if (timestamp == sender_timestamp) {
          // WORKAROUND: the two timestamps need to be different, in the CLI view
          timestamp++;
        }
        memcpy(temp, &timestamp, 4);        // mostly an extra blob to help make packet_hash unique
        temp[4] = (TXT_TYPE_CLI_DATA << 2); // NOTE: legacy was: TXT_TYPE_PLAIN

        auto reply = createDatagram(PAYLOAD_TYPE_TXT_MSG, sender, secret, temp, 5 + text_len);
        if (reply) {
          if (cli_reply_path_len == OUT_PATH_UNKNOWN) {
            sendFloodReply(reply, CLI_REPLY_DELAY_MILLIS, packet->getPathHashSize());
          } else {
            sendDirect(reply, cli_reply_path, cli_reply_path_len, CLI_REPLY_DELAY_MILLIS);
          }
        }
      }
    } else {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: possible replay attack detected");
    }
  }
}

bool MyMesh::onPeerPathRecv(mesh::Packet *packet, int sender_idx, const uint8_t *secret, uint8_t *path,
                            uint8_t path_len, uint8_t extra_type, uint8_t *extra, uint8_t extra_len) {
  // TODO: prevent replay attacks
  int i = matching_peer_indexes[sender_idx];

  if (i >= 0 && i < acl.getNumClients()) { // get from our known_clients table (sender SHOULD already be known in this context)
    MESH_DEBUG_PRINTLN("PATH to client, path_len=%d", (uint32_t)path_len);
    auto client = acl.getClientByIdx(i);
    if (shouldDenyClient(client->id)) return false;

    // store a copy of path, for sendDirect()
    client->out_path_len = mesh::Packet::copyPath(client->out_path, path, path_len);
    client->last_activity = getRTCClock()->getCurrentTime();
  } else {
    MESH_DEBUG_PRINTLN("onPeerPathRecv: invalid peer idx: %d", i);
  }

  // NOTE: no reciprocal path send!!
  return false;
}

#define CTL_TYPE_NODE_DISCOVER_REQ   0x80
#define CTL_TYPE_NODE_DISCOVER_RESP  0x90

void MyMesh::onControlDataRecv(mesh::Packet* packet) {
  uint8_t type = packet->payload[0] & 0xF0;    // just test upper 4 bits
  if (type == CTL_TYPE_NODE_DISCOVER_REQ && packet->payload_len >= 6
      && !_prefs.disable_fwd && discover_limiter.allow(rtc_clock.getCurrentTime())
      && !isHiddenNode()   // this node wishes to NOT be discoverable
  ) {
    int i = 1;
    uint8_t  filter = packet->payload[i++];
    uint32_t tag;
    memcpy(&tag, &packet->payload[i], 4); i += 4;
    uint32_t since;
    if (packet->payload_len >= i+4) {   // optional since field
      memcpy(&since, &packet->payload[i], 4); i += 4;
    } else {
      since = 0;
    }

    if ((filter & (1 << ADV_TYPE_REPEATER)) != 0 && _prefs.discovery_mod_timestamp >= since) {
      bool prefix_only = packet->payload[0] & 1;
      uint8_t data[6 + PUB_KEY_SIZE];
      data[0] = CTL_TYPE_NODE_DISCOVER_RESP | ADV_TYPE_REPEATER;   // low 4-bits for node type
      data[1] = packet->_snr;   // let sender know the inbound SNR ( x 4)
      memcpy(&data[2], &tag, 4);     // include tag from request, for client to match to
      memcpy(&data[6], self_id.pub_key, PUB_KEY_SIZE);
      auto resp = createControlData(data, prefix_only ? 6 + 8 : 6 + PUB_KEY_SIZE);
      if (resp) {
        sendZeroHop(resp, getRetransmitDelay(resp)*4);  // apply random delay (widened x4), as multiple nodes can respond to this
      }
    }
  } else if (type == CTL_TYPE_NODE_DISCOVER_RESP && packet->payload_len >= 6) {
    uint8_t node_type = packet->payload[0] & 0x0F;
    if (node_type != ADV_TYPE_REPEATER) {
      return;
    }
    if (packet->payload_len < 6 + PUB_KEY_SIZE) {
      MESH_DEBUG_PRINTLN("onControlDataRecv: DISCOVER_RESP pubkey too short: %d", (uint32_t)packet->payload_len);
      return;
    }

    if (pending_discover_tag == 0 || millisHasNowPassed(pending_discover_until)) {
      pending_discover_tag = 0;
      return;
    }
    uint32_t tag;
    memcpy(&tag, &packet->payload[2], 4);
    if (tag != pending_discover_tag) {
      return;
    }

    mesh::Identity id(&packet->payload[6]);
    if (id.matches(self_id)) {
      return;
    }
    putNeighbour(id, rtc_clock.getCurrentTime(), packet->getSNR());
  }
}

void MyMesh::sendNodeDiscoverReq() {
  uint8_t data[10];
  data[0] = CTL_TYPE_NODE_DISCOVER_REQ; // prefix_only=0
  data[1] = (1 << ADV_TYPE_REPEATER);
  getRNG()->random(&data[2], 4); // tag
  memcpy(&pending_discover_tag, &data[2], 4);
  pending_discover_until = futureMillis(60000);
  uint32_t since = 0;
  memcpy(&data[6], &since, 4);

  auto pkt = createControlData(data, sizeof(data));
  if (pkt) {
    sendZeroHop(pkt);
  }
}

MyMesh::MyMesh(mesh::MainBoard &board, mesh::Radio &radio, mesh::MillisecondClock &ms, mesh::RNG &rng,
               mesh::RTCClock &rtc, mesh::MeshTables &tables)
    : mesh::Mesh(radio, ms, rng, rtc, *new StaticPoolPacketManager(32), tables),
      region_map(key_store), temp_map(key_store),
      _cli(board, rtc, sensors, region_map, acl, &_prefs, this),
      telemetry(MAX_PACKET_PAYLOAD - 4),
      discover_limiter(4, 120),  // max 4 every 2 minutes
      anon_limiter(4, 180)   // max 4 every 3 minutes
#if defined(WITH_RS232_BRIDGE)
      , bridge(&_prefs, WITH_RS232_BRIDGE, _mgr, &rtc)
#endif
#if defined(WITH_ESPNOW_BRIDGE)
      , bridge(&_prefs, _mgr, &rtc)
#endif
{
  last_millis = 0;
  uptime_millis = 0;
  next_local_advert = next_flood_advert = 0;
  set_radio_at = revert_radio_at = 0;
  _logging = false;
  region_load_active = false;
  recv_pkt_region = NULL;

#if MAX_NEIGHBOURS
  memset(neighbours, 0, sizeof(neighbours));
#endif

  // defaults
  _prefs.airtime_factor = 1.0;
  _prefs.rx_delay_base = 0.0f;   // turn off by default, was 10.0;
  _prefs.tx_delay_factor = 0.5f; // was 0.25f
  _prefs.direct_tx_delay_factor = 0.3f; // was 0.2
  StrHelper::strncpy(_prefs.node_name, ADVERT_NAME, sizeof(_prefs.node_name));
  _prefs.node_lat = ADVERT_LAT;
  _prefs.node_lon = ADVERT_LON;
  _prefs.freq = LORA_FREQ;
  _prefs.sf = LORA_SF;
  _prefs.bw = LORA_BW;
  _prefs.cr = LORA_CR;
  _prefs.tx_power_dbm = LORA_TX_POWER;
  _prefs.advert_interval = 1;        // default to 2 minutes for NEW installs
  _prefs.flood_advert_interval = 47; // 47 hours
  _prefs.flood_max = 64;
  _prefs.flood_max_unscoped = 64;
  _prefs.flood_max_advert = 8;
  _prefs.interference_threshold = 0; // disabled
  _prefs.cad_enabled = 0;            // hardware CAD before TX (off by default; 'set cad on')
  _prefs.loop_detect = LOOP_DETECT_MINIMAL;

  // bridge defaults
  _prefs.bridge_enabled = 1;    // enabled
  _prefs.bridge_delay   = 500;  // milliseconds
  _prefs.bridge_pkt_src = 0;    // logTx
  _prefs.bridge_baud = 115200;  // baud rate
  _prefs.bridge_channel = 1;    // channel 1

  StrHelper::strncpy(_prefs.bridge_secret, "LVSITANOS", sizeof(_prefs.bridge_secret));

  // GPS defaults
  _prefs.gps_enabled = 0;
  _prefs.gps_interval = 0;
  _prefs.advert_loc_policy = ADVERT_LOC_PREFS;

  _prefs.adc_multiplier = 0.0f; // 0.0f means use default board multiplier

#if defined(USE_SX1262) || defined(USE_SX1268)
#ifdef SX126X_RX_BOOSTED_GAIN
  _prefs.rx_boosted_gain = SX126X_RX_BOOSTED_GAIN;
#else
  _prefs.rx_boosted_gain = 1; // enabled by default;
#endif
#endif
  _prefs.radio_fem_rxgain = 1;
  _prefs.radio_fem_txgain = 0;

  pending_discover_tag = 0;
  pending_discover_until = 0;

  memset(default_scope.key, 0, sizeof(default_scope.key));
}

void MyMesh::begin(FILESYSTEM *fs) {
  mesh::Mesh::begin();
  _fs = fs;
  // load persisted prefs
  _cli.loadPrefs(_fs);
  repairRepeaterPrefs();
  _filter_prefs.begin(_fs);
  acl.begin(_fs, self_id);
  _rules.begin(_fs, self_id);
  _room_identity_loaded = _rules.loadRoomIdentity(_room_identity)
                       && _room_identity.pub_key[0] != self_id.pub_key[0];
  // TODO: key_store.begin();
  region_map.load(_fs);

  // establish default-scope
  {
    RegionEntry* r = region_map.getDefaultRegion();
    if (r) {
      region_map.getTransportKeysFor(*r, &default_scope, 1);
    } else {
#ifdef DEFAULT_FLOOD_SCOPE_NAME
      r = region_map.findByName(DEFAULT_FLOOD_SCOPE_NAME);
      if (r == NULL) {
        r = region_map.putRegion(DEFAULT_FLOOD_SCOPE_NAME, 0);  // auto-create the default scope region
        if (r) { r->flags = 0; }   // Allow-flood
      }
      if (r) {
        region_map.setDefaultRegion(r);
        region_map.getTransportKeysFor(*r, &default_scope, 1);
      }
#endif
    }
  }

#if defined(WITH_BRIDGE)
  if (_prefs.bridge_enabled) {
    bridge.begin();
  }
#endif

  radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  radio_driver.setTxPower(_prefs.tx_power_dbm);

  radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);
  MESH_DEBUG_PRINTLN("RX Boosted Gain Mode: %s",
                     radio_driver.getRxBoostedGainMode() ? "Enabled" : "Disabled");

  board.attachDynamicPrefs(_prefs.getCustom());

  updateAdvertTimer();
  updateFloodAdvertTimer();

  board.setAdcMultiplier(_prefs.adc_multiplier);

#if ENV_INCLUDE_GPS == 1
  applyGpsPrefs();
#endif
}

void MyMesh::sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis, uint8_t path_hash_size) {
  if (scope.isNull()) {
    sendFlood(pkt, delay_millis, path_hash_size);
  } else {
    uint16_t codes[2];
    codes[0] = scope.calcTransportCode(pkt);
    codes[1] = 0;  // REVISIT: set to 'home' Region, for sender/return region?
    sendFlood(pkt, codes, delay_millis, path_hash_size);
  }
}

void MyMesh::applyTempRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, int timeout_mins) {
  set_radio_at = futureMillis(2000); // give CLI reply some time to be sent back, before applying temp radio params
  pending_freq = freq;
  pending_bw = bw;
  pending_sf = sf;
  pending_cr = cr;

  revert_radio_at = futureMillis(2000 + timeout_mins * 60 * 1000); // schedule when to revert radio params
}

bool MyMesh::formatFileSystem() {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return InternalFS.format();
#elif defined(RP2040_PLATFORM)
  return LittleFS.format();
#elif defined(ESP32)
  return SPIFFS.format();
#else
#error "need to implement file system erase"
  return false;
#endif
}

void MyMesh::sendSelfAdvertisement(int delay_millis, bool flood) {
  mesh::Packet *pkt = createSelfAdvert();
  if (pkt) {
    if (flood) {
      sendFloodScoped(default_scope, pkt, delay_millis, _prefs.path_hash_mode + 1);
    } else {
      sendZeroHop(pkt, delay_millis);
    }
  } else {
    MESH_DEBUG_PRINTLN("ERROR: unable to create advertisement packet!");
  }
}

void MyMesh::updateAdvertTimer() {
  if (_prefs.advert_interval > 0) { // schedule local advert timer
    next_local_advert = futureMillis(((uint32_t)_prefs.advert_interval) * 2 * 60 * 1000);
  } else {
    next_local_advert = 0; // stop the timer
  }
}

void MyMesh::updateFloodAdvertTimer() {
  if (_prefs.flood_advert_interval > 0) { // schedule flood advert timer
    next_flood_advert = futureMillis(((uint32_t)_prefs.flood_advert_interval) * 60 * 60 * 1000);
  } else {
    next_flood_advert = 0; // stop the timer
  }
}

void MyMesh::dumpLogFile() {
#if defined(RP2040_PLATFORM)
  File f = _fs->open(PACKET_LOG_FILE, "r");
#else
  File f = _fs->open(PACKET_LOG_FILE);
#endif
  if (f) {
    while (f.available()) {
      int c = f.read();
      if (c < 0) break;
      Serial.print((char)c);
    }
    f.close();
  }
}

void MyMesh::setTxPower(int8_t power_dbm) {
  radio_driver.setTxPower(power_dbm);
}

bool MyMesh::setRxBoostedGain(bool enable) {
  return radio_driver.setRxBoostedGainMode(enable);
}

#if defined(USE_LR2021)
bool MyMesh::configSideDetectors(const uint8_t sideDetSFs[], uint8_t num, float bw) {
  return radio_driver.configSideDetectors(sideDetSFs, num, bw);
}
#endif

void MyMesh::formatNeighborsReply(char *reply) {
  char *dp = reply;

#if MAX_NEIGHBOURS
  // create copy of neighbours list, skipping empty entries so we can sort it separately from main list
  int16_t neighbours_count = 0;
  NeighbourInfo* sorted_neighbours[MAX_NEIGHBOURS];
  for (int i = 0; i < MAX_NEIGHBOURS; i++) {
    auto neighbour = &neighbours[i];
    if (neighbour->heard_timestamp > 0) {
      sorted_neighbours[neighbours_count] = neighbour;
      neighbours_count++;
    }
  }

  // sort neighbours newest to oldest
  std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
    return a->heard_timestamp > b->heard_timestamp; // desc
  });

  for (int i = 0; i < neighbours_count && dp - reply < 134; i++) {
    NeighbourInfo *neighbour = sorted_neighbours[i];

    // add new line if not first item
    if (i > 0) *dp++ = '\n';

    char hex[10];
    // get 4 bytes of neighbour id as hex
    mesh::Utils::toHex(hex, neighbour->id.pub_key, 4);

    // add next neighbour
    uint32_t secs_ago = getRTCClock()->getCurrentTime() - neighbour->heard_timestamp;
    sprintf(dp, "%s:%d:%d", hex, secs_ago, neighbour->snr);
    while (*dp)
      dp++; // find end of string
  }
#endif
  if (dp == reply) { // no neighbours, need empty response
    strcpy(dp, "-none-");
    dp += 6;
  }
  *dp = 0; // null terminator
}

void MyMesh::removeNeighbor(const uint8_t *pubkey, int key_len) {
#if MAX_NEIGHBOURS
  for (int i = 0; i < MAX_NEIGHBOURS; i++) {
    NeighbourInfo *neighbour = &neighbours[i];
    if (memcmp(neighbour->id.pub_key, pubkey, key_len) == 0) {
      neighbours[i] = NeighbourInfo(); // clear neighbour entry
    }
  }
#endif
}

void MyMesh::startRegionsLoad() {
  temp_map.resetFrom(region_map);   // rebuild regions in a temp instance
  memset(load_stack, 0, sizeof(load_stack));
  load_stack[0] = &temp_map.getWildcard();
  region_load_active = true;
}

bool MyMesh::saveRegions() {
  return region_map.save(_fs);
}

void MyMesh::onDefaultRegionChanged(const RegionEntry* r) {
  if (r) {
    region_map.getTransportKeysFor(*r, &default_scope, 1);
  } else {
    memset(default_scope.key, 0, sizeof(default_scope.key));
  }
}

void MyMesh::formatStatsReply(char *reply) {
  StatsFormatHelper::formatCoreStats(reply, board, *_ms, _err_flags, _mgr);
}

void MyMesh::formatRadioStatsReply(char *reply) {
  StatsFormatHelper::formatRadioStats(reply, _radio, radio_driver, getTotalAirTime(), getReceiveAirTime());
}

void MyMesh::formatPacketStatsReply(char *reply) {
  StatsFormatHelper::formatPacketStats(reply, radio_driver, getNumSentFlood(), getNumSentDirect(),
                                       getNumRecvFlood(), getNumRecvDirect());
}

void MyMesh::saveIdentity(const mesh::LocalIdentity &new_id) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  IdentityStore store(*_fs, "");
#elif defined(ESP32)
  IdentityStore store(*_fs, "/identity");
#elif defined(RP2040_PLATFORM)
  IdentityStore store(*_fs, "/identity");
#else
#error "need to define saveIdentity()"
#endif
  store.save("_main", new_id);
}

void MyMesh::clearStats() {
  radio_driver.resetStats();
  resetStats();
  ((SimpleMeshTables *)getTables())->resetStats();
}

bool MyMesh::repairRepeaterPrefs() {
  bool changed = savemesh::repair(_prefs);
  if (changed && !_cli.savePrefs(_fs)) {
    MESH_DEBUG_PRINTLN("Unable to save repaired repeater preferences");
  }
  return changed;
}

bool MyMesh::handleProtectedPrefsCommand(uint32_t sender_timestamp, char* command, char* reply) {
  const char* arg;
  uint16_t value;

  if (matchCommand(command, "set path.hash.mode", &arg)) {
    if (!parseUnsigned(arg, &value) || !savemesh::isPathHashModeAllowed(value)) {
      strcpy(reply, "Error: path.hash.mode must be 1 or 2");
    } else {
      _cli.handleCommand(sender_timestamp, command, reply);
    }
    return true;
  }
  if (matchCommand(command, "set multi.acks", &arg)) {
    if (!parseUnsigned(arg, &value) || !savemesh::isMultiAcksAllowed(value)) {
      strcpy(reply, "Error: multi.acks must be 1");
    } else {
      _cli.handleCommand(sender_timestamp, command, reply);
    }
    return true;
  }
  if (matchCommand(command, "set loop.detect", &arg)) {
    if (!matchesValue(arg, "minimal") && !matchesValue(arg, "moderate")
        && !matchesValue(arg, "strict")) {
      strcpy(reply, "Error: loop.detect must be minimal, moderate or strict");
    } else {
      _cli.handleCommand(sender_timestamp, command, reply);
    }
    return true;
  }
  if (matchCommand(command, "set advert.interval", &arg)) {
    if (!parseUnsigned(arg, &value) || !savemesh::isAdvertIntervalAllowed(value)) {
      strcpy(reply, "Error: advert.interval must be 0");
    } else {
      _cli.handleCommand(sender_timestamp, command, reply);
    }
    return true;
  }
  if (matchCommand(command, "set flood.advert.interval", &arg)) {
    if (!parseUnsigned(arg, &value) || !savemesh::isFloodAdvertIntervalAllowed(value)) {
      strcpy(reply, "Error: flood.advert.interval must be 0 or 47-168 hours");
    } else {
      _cli.handleCommand(sender_timestamp, command, reply);
    }
    return true;
  }
  return false;
}

void MyMesh::handleFilterCommand(const char* name, const char* arg, uint8_t& setting, char* reply) {
  while (*arg == ' ') arg++;
  if (*arg == 0) {
    sprintf(reply, "> filter %s %s", name, setting ? "on" : "off");
    return;
  }

  uint8_t value;
  if (!savemesh::parseOnOff(arg, &value)) {
    strcpy(reply, "Error, must be: on or off");
    return;
  }

  if (setting == value) {
    sprintf(reply, "OK - filter %s %s", name, value ? "on" : "off");
    return;
  }

  uint8_t previous = setting;
  setting = value;
  if (_filter_prefs.save(_fs)) {
    sprintf(reply, "OK - filter %s %s", name, value ? "on" : "off");
  } else {
    setting = previous;  // keep RAM and flash in agreement
    strcpy(reply, "Error - could not save filter settings");
  }
}

void MyMesh::handleCommand(uint32_t sender_timestamp, char *command, char *reply,
                           const ClientInfo* client, bool ethernet) {
  if (region_load_active && (!client || client->isAdmin())) {
    if (StrHelper::isBlank(command)) {  // empty/blank line, signal to terminate 'load' operation
      region_map = temp_map;  // copy over the temp instance as new current map
      region_load_active = false;

      sprintf(reply, "OK - loaded %d regions", region_map.getCount());
    } else {
      char *np = command;
      while (*np == ' ') np++;   // skip indent
      int indent = np - command;

      char *ep = np;
      while (RegionMap::is_name_char(*ep)) ep++;
      if (*ep) { *ep++ = 0; }  // set null terminator for end of name

      while (*ep && *ep != 'F') ep++;  // look for (optional) flags

      if (indent > 0 && indent < 8 && strlen(np) > 0) {
        auto parent = load_stack[indent - 1];
        if (parent) {
          auto old = region_map.findByName(np);
          auto nw = temp_map.putRegion(np, parent->id, old ? old->id : 0);  // carry-over the current ID (if name already exists)
          if (nw) {
            nw->flags = old ? old->flags : (*ep == 'F' ? 0 : REGION_DENY_FLOOD);   // carry-over flags from curr

            load_stack[indent] = nw;  // keep pointers to parent regions, to resolve parent_id's
          }
        }
      }
      reply[0] = 0;
    }
    return;
  }

  while (*command == ' ') command++; // skip leading spaces

  if (strlen(command) > 4 && command[2] == '|') { // optional prefix (for companion radio CLI)
    memcpy(reply, command, 3);                    // reflect the prefix back
    reply += 3;
    command += 3;
  }

  const char* args;
  if (!ethernet && (!client || client->isAdmin()) && handleAdminRoomCommand(command, reply, !client)) return;
  if (!ethernet && (!client || client->isAdmin()) && matchCommand(command, "neighbours", &args)) {
    handleNeighbourCommand(args, reply, !client);
    return;
  }
  if (matchCommand(command, "rules", &args)) {
    if (ethernet) {
      strcpy(reply, "Err - use USB or authenticated mesh CLI");
      return;
    }
    if (matchesValue(args, "drops")) {
      snprintf(reply, 150, "filter=%lu identity=%lu rate=%lu",
               static_cast<unsigned long>(_filter_drops), static_cast<unsigned long>(_identity_drops),
               static_cast<unsigned long>(_rate_drops));
      return;
    }
    bool can_write = !client || (client->permissions & PERM_ACL_ROLE_MASK) >= PERM_ACL_READ_WRITE;
    if (handleSyncCommand(args, reply, !client, can_write)) return;
    bool sync_requested = false;
    _rules.handleCommand(args, reply, self_id, client ? &client->id : nullptr,
                         sender_timestamp, *getRNG(), can_write, !client || client->isAdmin(), sync_requested);
    if (sync_requested) _sync_cursor = 0;
    return;
  }
  if (client && !client->isAdmin()) {
    strcpy(reply, "Err - admin permission required");
    return;
  }

  if (matchCommand(command, "password", &args)) {
    if (ethernet) {
      strcpy(reply, "Err - use USB or authenticated mesh CLI");
      return;
    }
    if (strlen(args) >= sizeof(_prefs.password)) {
      strcpy(reply, "Err - password too long");
      return;
    }
    char previous[sizeof(_prefs.password)];
    memcpy(previous, _prefs.password, sizeof(previous));
    StrHelper::strncpy(_prefs.password, args, sizeof(_prefs.password));
    if (!_cli.savePrefs(_fs)) {
      memcpy(_prefs.password, previous, sizeof(previous));
      strcpy(reply, "Err - password write failed");
      return;
    }
    strcpy(reply, *args ? "OK - password saved" : "OK - password enrollment disabled");
    return;
  }

  if (handleProtectedPrefsCommand(sender_timestamp, command, reply)) return;

  // handle ACL related commands
  if (memcmp(command, "setperm ", 8) == 0) {   // format:  setperm {pubkey-hex} {permissions-int8}
    if (ethernet) {
      strcpy(reply, "Err - use USB or authenticated mesh CLI");
      return;
    }
    char* hex = &command[8];
    while (*hex == ' ') ++hex;
    char* separator = strchr(hex, ' ');
    if (!separator) {
      strcpy(reply, "Err - bad params");
      return;
    }
    *separator++ = 0;
    while (*separator == ' ') ++separator;

    uint16_t permissions;
    if (!parseUnsigned(separator, &permissions) || permissions > UINT8_MAX) {
      strcpy(reply, "Err - invalid permissions");
      return;
    }

    size_t hex_len = strlen(hex);
    size_t key_len = hex_len / 2;
    uint8_t pubkey[PUB_KEY_SIZE];
    if (hex_len == 0 || hex_len % 2 != 0 || key_len > PUB_KEY_SIZE
        || !savemesh::isHex(hex, hex_len) || !mesh::Utils::fromHex(pubkey, key_len, hex)) {
      strcpy(reply, "Err - bad pubkey");
      return;
    }
    if (key_len < PUB_KEY_SIZE && (permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST) {
      unsigned matches = 0;
      for (int i = 0; i < acl.getNumClients(); ++i) {
        if (memcmp(acl.getClientByIdx(i)->id.pub_key, pubkey, key_len) == 0) ++matches;
      }
      if (matches > 1) {
        strcpy(reply, "Err - ambiguous key prefix");
        return;
      }
    }
    if (!acl.updatePermissions(self_id, pubkey, key_len, static_cast<uint8_t>(permissions))) {
      strcpy(reply, "Err - ACL update failed");
      return;
    }
    strcpy(reply, "OK");
  } else if (sender_timestamp == 0 && strcmp(command, "get acl") == 0) {
    Serial.println("ACL:");
    if (acl.needsRecovery()) Serial.println("ACL recovery required. Enroll a trusted key over USB.");
    for (int i = 0; i < acl.getNumClients(); i++) {
      auto c = acl.getClientByIdx(i);
      if (c->permissions == 0) continue;  // skip deleted (or guest) entries

      Serial.printf("%02X ", c->permissions);
      mesh::Utils::printHex(Serial, c->id.pub_key, PUB_KEY_SIZE);
      Serial.printf("\n");
    }
    reply[0] = 0;
  } else if (memcmp(command, "filter", 6) == 0 && StrHelper::isBlank(&command[6])) {
    sprintf(reply, "> 1byte %s, data %s, public %s",
            _filter_prefs.filter_1byte ? "on" : "off",
            _filter_prefs.filter_data ? "on" : "off",
            _filter_prefs.filter_public ? "on" : "off");
  } else if (memcmp(command, "filter 1byte", 12) == 0 && (command[12] == 0 || command[12] == ' ')) {
    handleFilterCommand("1byte", &command[12], _filter_prefs.filter_1byte, reply);
  } else if (memcmp(command, "filter data", 11) == 0 && (command[11] == 0 || command[11] == ' ')) {
    handleFilterCommand("data", &command[11], _filter_prefs.filter_data, reply);
  } else if (memcmp(command, "filter public", 13) == 0 && (command[13] == 0 || command[13] == ' ')) {
    handleFilterCommand("public", &command[13], _filter_prefs.filter_public, reply);
  } else if (memcmp(command, "discover.neighbors", 18) == 0) {
    const char* sub = command + 18;
    while (*sub == ' ') sub++;
    if (*sub != 0) {
      strcpy(reply, "Err - discover.neighbors has no options");
    } else {
      sendNodeDiscoverReq();
      strcpy(reply, "OK - Discover sent");
    }
  } else{
    _cli.handleCommand(sender_timestamp, command, reply);  // common CLI commands
  }
}

void MyMesh::loop() {
#ifdef WITH_BRIDGE
  bridge.loop();
#endif

  mesh::Mesh::loop();
  sendNeighbourNotice();
  sendPolicyUpdate();

  if (next_flood_advert && millisHasNowPassed(next_flood_advert)) {
    mesh::Packet *pkt = createSelfAdvert();
    uint32_t delay_millis = 0;
    if (pkt) sendFloodScoped(default_scope, pkt, delay_millis, _prefs.path_hash_mode + 1);

    updateFloodAdvertTimer(); // schedule next flood advert
    updateAdvertTimer();      // also schedule local advert (so they don't overlap)
  } else if (next_local_advert && millisHasNowPassed(next_local_advert)) {
    mesh::Packet *pkt = createSelfAdvert();
    if (pkt) sendZeroHop(pkt);

    updateAdvertTimer(); // schedule next local advert
  }

  if (set_radio_at && millisHasNowPassed(set_radio_at)) { // apply pending (temporary) radio params
    set_radio_at = 0;                                     // clear timer
    radio_driver.setParams(pending_freq, pending_bw, pending_sf, pending_cr);
    MESH_DEBUG_PRINTLN("Temp radio params");
  }

  if (revert_radio_at && millisHasNowPassed(revert_radio_at)) { // revert radio params to orig
    revert_radio_at = 0;                                        // clear timer
    radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
    MESH_DEBUG_PRINTLN("Radio params restored");
  }

  // update uptime
  uint32_t now = millis();
  uptime_millis += now - last_millis;
  last_millis = now;
}

// To check if there is pending work
bool MyMesh::hasPendingWork() const {
#if defined(WITH_BRIDGE)
  if (bridge.isRunning()) return true;  // bridge needs WiFi radio, can't sleep
#endif
  return _mgr->getOutboundTotal() > 0;
}
