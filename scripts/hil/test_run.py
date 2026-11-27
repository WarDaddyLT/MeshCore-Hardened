import unittest

from run import RAW_RX, decode_advert, find_unacknowledged_deny


class AdvertTest(unittest.TestCase):
    def test_same_advert_across_paths(self):
        key = bytes(range(32))
        stamp = 1795000020
        payload = key + stamp.to_bytes(4, "little") + bytes(64) + b"\x81test"
        direct = decode_advert(bytes((RAW_RX, 0, 0, 0x11, 0)) + payload, key)
        routed = decode_advert(bytes((RAW_RX, 0, 0, 0x10, 1, 2, 3, 4, 0x41, 0xab, 0xcd)) + payload,
                               key)
        self.assertEqual(direct["path"], [])
        self.assertEqual(routed["path"], ["abcd"])
        self.assertEqual(routed["stamp"], stamp)
        self.assertEqual(direct["advert"], routed["advert"])

    def test_rejects_unrelated_and_incomplete_events(self):
        prefix = bytes((RAW_RX, 0, 0, 0x11, 0))
        key = bytes(range(32))
        self.assertIsNone(decode_advert(prefix + key, key))
        self.assertIsNone(decode_advert(prefix + bytes(101), key))
        self.assertIsNone(decode_advert(bytes((RAW_RX, 0, 0)), key))


class CleanupTest(unittest.TestCase):
    def test_lost_acknowledgment_without_commit(self):
        class Device:
            def cli(self, command):
                return "rev=4 capacity=24"

        self.assertIsNone(find_unacknowledged_deny(Device(), "12" * 32, 4))

    def test_lost_acknowledgment_with_exact_local_rule(self):
        key = "12" * 32
        rule_id = "34" * 16

        class Device:
            def cli(self, command):
                return {
                    "rules status": "rev=5 capacity=24",
                    "rules list 0": f"next=1 {rule_id} deny client {key} local",
                    "rules list 1": "End",
                }[command]

        self.assertEqual(find_unacknowledged_deny(Device(), key, 4), rule_id)


if __name__ == "__main__":
    unittest.main()
