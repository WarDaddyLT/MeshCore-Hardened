#include <gtest/gtest.h>
#include "PolicyPeerSession.h"
#include "ReceiveWork.h"
#include "RuleStore.h"

namespace {
class TestRandom : public mesh::RNG {
  uint8_t value = 0;
public:
  void random(uint8_t* dest, size_t size) override {
    const uint8_t next = ++value;
    for (size_t i = 0; i < size; ++i) dest[i] = next + i;
  }
};

std::string command(RuleStore& store, const mesh::LocalIdentity& node, TestRandom& rng,
                    const std::string& commandText, bool admin = true) {
  char reply[150]{};
  bool sync = false;
  store.handleCommand(commandText.c_str(), reply, node, nullptr, 0, rng, admin, admin, sync);
  return reply;
}

struct PolicyPair {
  TestRandom rng;
  mesh::LocalIdentity source{&rng};
  mesh::LocalIdentity receiver{&rng};
  MockFS sourceFs, receiverFs;
  RuleStore origin, target;

  void provision() {
    origin.begin(&sourceFs, source);
    target.begin(&receiverFs, receiver);
    for (auto* store : {&origin, &target}) {
      ASSERT_TRUE(store->setScope(RuleStore::Global, "fleet"));
      ASSERT_TRUE(store->setScope(RuleStore::Region, "north"));
      ASSERT_TRUE(store->setScope(RuleStore::Subnet, "bench"));
      EXPECT_FALSE(store->transitAllowed());
    }
    ASSERT_TRUE(origin.setTrustedPeer(receiver.pub_key, true, source));
    ASSERT_TRUE(target.setTrustedPeer(source.pub_key, true, receiver));
    ASSERT_TRUE(origin.setPublisher(RuleStore::Subnet, source.pub_key, true));
    ASSERT_TRUE(target.setPublisher(RuleStore::Subnet, source.pub_key, true));
    ASSERT_TRUE(target.setPublisher(RuleStore::Global, source.pub_key, true));
    ASSERT_TRUE(target.setPublisher(RuleStore::Region, source.pub_key, true));
    ASSERT_TRUE(origin.commitOnboarding(origin.revision(), source));
  }
};
}

TEST(HardenedPolicy, AdminPermissionAndDenyPrecedenceAcrossModes) {
  TestRandom rng;
  mesh::LocalIdentity local(&rng), client(&rng);
  MockFS fs;
  RuleStore store;
  store.begin(&fs, local);
  char key[PUB_KEY_SIZE * 2 + 1];
  mesh::Utils::toHex(key, client.pub_key, PUB_KEY_SIZE);
  const auto allow = std::string("add allow client ") + key;
  const auto deny = std::string("add deny client ") + key;

  EXPECT_EQ(store.mode(), RuleStore::Normal);
  EXPECT_EQ(command(store, local, rng, allow, false), "Err - write permission required");
  ASSERT_EQ(command(store, local, rng, allow).substr(0, 3), "OK ");
  EXPECT_EQ(store.decide(RuleStore::Client, client.pub_key), RuleStore::Allowed);
  ASSERT_EQ(command(store, local, rng, deny).substr(0, 3), "OK ");
  for (auto mode : {"protected", "locked", "normal"}) {
    ASSERT_EQ(command(store, local, rng, std::string("mode ") + mode), "OK");
    EXPECT_EQ(store.decide(RuleStore::Client, client.pub_key), RuleStore::Denied);
    EXPECT_EQ(store.decide(RuleStore::Repeater, client.pub_key), RuleStore::Denied);
  }
}

TEST(HardenedPolicy, SignedCheckpointKeepsDeletedRuleGoneAfterRestart) {
  PolicyPair pair;
  ASSERT_NO_FATAL_FAILURE(pair.provision());
  const auto reply = command(pair.origin, pair.source, pair.rng, "add filter public on global:fleet");
  ASSERT_EQ(reply.substr(0, 3), "OK ");
  auto old = *pair.origin.exportRule(0);
  ASSERT_EQ(pair.target.mergeRule(old, pair.source.pub_key, pair.receiver), RuleStore::Changed);
  ASSERT_EQ(command(pair.origin, pair.source, pair.rng, "delete " + reply.substr(3)), "OK");
  RuleStore::Checkpoint checkpoint{};
  RuleStore::Rule records[RuleStore::Capacity]{};
  ASSERT_TRUE(pair.origin.makeCheckpoint(RuleStore::Global, pair.source, checkpoint, records));
  ASSERT_EQ(checkpoint.count, 0);
  ASSERT_EQ(pair.target.installCheckpoint(checkpoint, records, 0, pair.receiver), RuleStore::Changed);
  EXPECT_FALSE(pair.target.filterEnabled(RuleStore::Public));
  RuleStore reboot;
  reboot.begin(&pair.receiverFs, pair.receiver);
  EXPECT_EQ(reboot.mergeRule(old, pair.source.pub_key, pair.receiver), RuleStore::Current);
  EXPECT_FALSE(reboot.filterEnabled(RuleStore::Public));
}

TEST(HardenedPolicy, PeerSnapshotAndRevocationKeepTransitHeld) {
  PolicyPair pair;
  ASSERT_NO_FATAL_FAILURE(pair.provision());
  ASSERT_EQ(command(pair.origin, pair.source, pair.rng, "add filter data on global:fleet").substr(0, 3), "OK ");
  ASSERT_EQ(command(pair.origin, pair.source, pair.rng, "subnet mode protected"), "OK");
  RuleStore::PeerPolicy body{};
  RuleStore::PeerPolicyProof proof{};
  proof.request[0] = 7;
  ASSERT_TRUE(pair.origin.exportPeerPolicy(body, proof, pair.source, pair.receiver.pub_key));
  EXPECT_FALSE(pair.target.verifyPeerPolicyProof(proof, pair.source.pub_key, pair.source));
  auto tampered = body;
  tampered.rules[0].value ^= 1;
  EXPECT_FALSE(pair.target.stagePeerPolicy(tampered, proof, pair.source.pub_key, pair.receiver));
  pair.receiverFs.fail_writes = true;
  EXPECT_FALSE(pair.target.stagePeerPolicy(body, proof, pair.source.pub_key, pair.receiver));
  EXPECT_FALSE(pair.target.transitAllowed());
  pair.receiverFs.fail_writes = false;
  pair.receiverFs.fail_rename = true;
  EXPECT_FALSE(pair.target.stagePeerPolicy(body, proof, pair.source.pub_key, pair.receiver));
  EXPECT_FALSE(pair.target.transitAllowed());
  pair.receiverFs.fail_rename = false;
  ASSERT_TRUE(pair.target.stagePeerPolicy(body, proof, pair.source.pub_key, pair.receiver));
  EXPECT_FALSE(pair.target.transitAllowed());
  EXPECT_EQ(pair.target.mode(), RuleStore::Protected);
  RuleStore reboot;
  reboot.begin(&pair.receiverFs, pair.receiver);
  EXPECT_TRUE(reboot.peerPolicyStaged());
  ASSERT_TRUE(reboot.setTrustedPeer(pair.source.pub_key, false, pair.receiver));
  EXPECT_FALSE(reboot.commitOnboarding(reboot.revision(), pair.receiver));
  EXPECT_FALSE(reboot.transitAllowed());
  ASSERT_TRUE(reboot.startOnboarding());
  EXPECT_FALSE(reboot.commitOnboarding(reboot.revision() - 1, pair.receiver));
  ASSERT_TRUE(reboot.commitOnboarding(reboot.revision(), pair.receiver));
  EXPECT_TRUE(reboot.transitAllowed());
}

TEST(HardenedPolicy, SubnetScopeAndLocalModePrecedence) {
  PolicyPair pair;
  ASSERT_NO_FATAL_FAILURE(pair.provision());
  ASSERT_EQ(command(pair.origin, pair.source, pair.rng, "subnet mode locked"), "OK");
  const auto locked = pair.origin.subnetModeRecord();
  auto altered = locked;
  altered.mode = RuleStore::Normal;
  EXPECT_EQ(pair.target.mergeSubnetMode(altered, pair.receiver), RuleStore::Rejected);
  EXPECT_EQ(pair.target.mergeSubnetMode(locked, pair.receiver), RuleStore::Changed);
  ASSERT_EQ(command(pair.target, pair.receiver, pair.rng, "mode protected"), "OK");
  ASSERT_EQ(command(pair.origin, pair.source, pair.rng, "subnet mode normal"), "OK");
  ASSERT_EQ(pair.target.mergeSubnetMode(pair.origin.subnetModeRecord(), pair.receiver), RuleStore::Changed);
  EXPECT_EQ(pair.target.mergeSubnetMode(locked, pair.receiver), RuleStore::Current);
  EXPECT_EQ(pair.target.mode(), RuleStore::Protected);
  MockFS outsideFs;
  RuleStore outside;
  outside.begin(&outsideFs, pair.receiver);
  ASSERT_TRUE(outside.setScope(RuleStore::Subnet, "different"));
  ASSERT_TRUE(outside.setPublisher(RuleStore::Subnet, pair.source.pub_key, true));
  EXPECT_EQ(outside.mergeSubnetMode(locked, pair.receiver), RuleStore::Rejected);
  EXPECT_EQ(outside.mode(), RuleStore::Normal);
}

TEST(HardenedPolicy, PeerProofRequiresCorrectScopeAndFreshConfirmation) {
  TestRandom rng;
  mesh::LocalIdentity alice(&rng), bob(&rng);
  PolicyPeerSession a, b;
  PolicyPeerSession::Frame challenge{}, response{}, confirm{};
  uint8_t first[PolicyPeerSession::NonceSize]{1};
  uint8_t second[PolicyPeerSession::NonceSize]{2};
  uint8_t configured[CIPHER_KEY_SIZE]{3};
  uint8_t different[CIPHER_KEY_SIZE]{4};

  ASSERT_TRUE(a.start(bob.pub_key, PolicyPeerSession::Context::Subnet, first, 10));
  ASSERT_TRUE(a.prepare(challenge, "bench", configured, alice));
  a.markHandshakeSent(10);
  EXPECT_FALSE(b.accept(challenge, "outside", configured, bob, 11));
  EXPECT_FALSE(b.accept(challenge, "bench", different, bob, 11));
  ASSERT_TRUE(b.accept(challenge, "bench", configured, bob, 11));
  b.setResponseNonce(second);
  ASSERT_TRUE(b.prepare(response, "bench", configured, bob));
  b.markHandshakeSent(12);
  ASSERT_TRUE(a.accept(response, "bench", configured, alice, 13));
  ASSERT_TRUE(a.prepare(confirm, "bench", configured, alice));
  a.markHandshakeSent(14);
  EXPECT_FALSE(b.active());
  ASSERT_TRUE(b.accept(confirm, "bench", configured, bob, 15));
  EXPECT_TRUE(b.active());
  EXPECT_EQ(memcmp(a.transmitKey(), b.receiveKey(), CIPHER_KEY_SIZE), 0);
  EXPECT_NE(memcmp(a.transmitKey(), a.receiveKey(), CIPHER_KEY_SIZE), 0);
  EXPECT_FALSE(b.accept(confirm, "bench", configured, bob, 16));
  b.markReceived(1);
  EXPECT_FALSE(b.canReceiveSequence(1));
  b.expire(3600016);
  EXPECT_TRUE(b.free());
}

TEST(HardenedPolicy, ProtectedProbationFollowsTheSeventyTwoHourRamp) {
  probation::Snapshot saved{};
  saved.entries[0].key[0] = 1;
  saved.entries[0].subject = RuleStore::Client;
  const uint8_t* key = saved.entries[0].key;
  const auto unknown = [](const uint8_t*, uint8_t) { return false; };
  constexpr uint32_t wall = 1767225600;
  constexpr unsigned expected[] = {0, 2, 4, 6};
  for (unsigned day = 0; day < 4; ++day) {
    probation::Ledger ledger;
    ledger.begin(saved);
    const uint64_t uptime = uint64_t(day) * 86400000;
    unsigned forwarded = 0;
    for (unsigned i = 0; i < probation::PerKeyPerMinute; ++i) {
      const uint32_t stamp = wall + i;
      forwarded += ledger.admit(key, RuleStore::Client, stamp, stamp, uptime, true, unknown);
    }
    EXPECT_EQ(forwarded, expected[day]) << "day " << day;
    EXPECT_FALSE(ledger.admit(key, RuleStore::Client, wall, wall, uptime, true, unknown));
  }
}

TEST(HardenedPolicy, AirtimeAndCategoryBudgetsLeaveIndependentCapacity) {
  forward_traffic::Policy policy{};
  policy.categories[forward_traffic::GroupText].set(1);
  forward_traffic::Budget packets;
  EXPECT_TRUE(packets.admit(PAYLOAD_TYPE_GRP_TXT, policy, 0, 100));
  EXPECT_FALSE(packets.admit(PAYLOAD_TYPE_GRP_TXT, policy, 0, 100));
  EXPECT_TRUE(packets.admit(PAYLOAD_TYPE_TXT_MSG, policy, 0, 100));
  EXPECT_TRUE(packets.admit(PAYLOAD_TYPE_GRP_TXT, policy, 0, 60100));

  forward_traffic::AirtimeBudget airtime;
  EXPECT_TRUE(airtime.admit(100, 80, 100, 100));
  EXPECT_TRUE(airtime.admit(100, 80, 100, 100));
  EXPECT_FALSE(airtime.admit(100, 80, 100, 100));
  EXPECT_TRUE(airtime.admit(500, 80, 100, 100));
}

TEST(HardenedPolicy, ReceiveChecksRejectIncompleteFramesBeforeCryptoWork) {
  mesh::Packet packet;
  packet.header = PAYLOAD_TYPE_GRP_TXT << PH_TYPE_SHIFT;
  packet.payload_len = 1 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE - 1;
  EXPECT_FALSE(receive_work::validFrame(packet));
  ++packet.payload_len;
  EXPECT_TRUE(receive_work::validFrame(packet));
  packet.header = PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT;
  packet.payload_len = PUB_KEY_SIZE + sizeof(uint32_t) + SIGNATURE_SIZE - 1;
  EXPECT_FALSE(receive_work::validFrame(packet));
  ++packet.payload_len;
  EXPECT_TRUE(receive_work::validFrame(packet));

  receive_work::Budget work(500, 2);
  EXPECT_TRUE(work.admit(100));
  EXPECT_TRUE(work.admit(100));
  EXPECT_FALSE(work.admit(599));
  EXPECT_TRUE(work.admit(600));
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
