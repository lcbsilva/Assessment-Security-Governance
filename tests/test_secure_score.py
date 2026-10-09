import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_score import latest_secure_score


class LatestSecureScoreTests(unittest.TestCase):
    def test_selects_latest_timestamp_not_first_api_row(self):
        older = {"createdDateTime": "2026-01-01T00:00:00Z", "currentScore": 10}
        newer = {"createdDateTime": "2026-02-01T00:00:00Z", "currentScore": 20}
        self.assertEqual(latest_secure_score([older, newer]), newer)

    def test_handles_equivalent_timezone_offsets(self):
        utc = {"createdDateTime": "2026-02-01T00:00:00Z", "currentScore": 20}
        offset = {"createdDateTime": "2026-02-01T01:00:00+01:00", "currentScore": 30}
        self.assertEqual(latest_secure_score([utc, offset]), utc)

    def test_refuses_ambiguous_multi_snapshot_without_complete_timestamps(self):
        valid = {"createdDateTime": "2026-02-01T00:00:00Z", "currentScore": 20}
        missing = {"currentScore": 30}
        self.assertIsNone(latest_secure_score([valid, missing]))

    def test_single_snapshot_remains_usable_without_timestamp(self):
        row = {"currentScore": 20}
        self.assertEqual(latest_secure_score([row]), row)

    def test_empty_collection_has_no_snapshot(self):
        self.assertIsNone(latest_secure_score([]))


if __name__ == "__main__":
    unittest.main()
