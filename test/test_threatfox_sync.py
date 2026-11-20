import unittest

from intel.threat_intel import sync_threatfox


class FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {"query_status": "ok", "data": [
            {"ioc": "malicious.example", "ioc_type": "domain", "malware": "demo",
             "confidence_level": 85, "first_seen": "2026-10-10 12:00:00 UTC"},
            {"ioc": "1.2.3.4:4444", "ioc_type": "ip:port", "confidence_level": 90},
            {"ioc": "abc", "ioc_type": "domain", "confidence_level": "bad"},
        ]}


class FakeSession:
    def post(self, *args, **kwargs):
        self.args, self.kwargs = args, kwargs
        return FakeResponse()


class FakeStore:
    def add_iocs(self, entries, default_source):
        self.entries = entries
        self.default_source = default_source
        return len(entries)


class ThreatFoxSyncTests(unittest.TestCase):
    def test_fetches_recent_iocs_and_filters_unsupported_types(self):
        session, store = FakeSession(), FakeStore()
        result = sync_threatfox(3, auth_key="secret-test-key", store=store, session=session)
        self.assertEqual(result["received"], 3)
        self.assertEqual(result["supported"], 2)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(store.entries[0]["type"], "domain")
        self.assertEqual(store.entries[0]["confidence"], 0.85)
        self.assertIn("Auth-Key", session.kwargs["headers"])
        self.assertTrue(session.kwargs["verify"])
        self.assertNotIn("secret-test-key", str(result))

    def test_requires_local_key_and_valid_days(self):
        with self.assertRaises(RuntimeError):
            sync_threatfox(1, auth_key="", store=FakeStore(), session=FakeSession())
        with self.assertRaises(ValueError):
            sync_threatfox(8, auth_key="key", store=FakeStore(), session=FakeSession())


if __name__ == "__main__":
    unittest.main()
