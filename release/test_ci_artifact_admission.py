"""Positive and refusal probes for aggregate metadata retention admission."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_artifact_admission import admit


class Admission(unittest.TestCase):
    def test_empty_and_exact_boundary(self):
        self.assertEqual(admit([{'total_count': 0, 'artifacts': []}], 100, 100)['existing_artifact_count'], 0)
        page = {'total_count': 1, 'artifacts': [{'id': 1, 'size_in_bytes': 60}]}
        self.assertEqual(admit([page], 100, 40)['existing_artifact_bytes'], 60)
        with self.assertRaisesRegex(ValueError, 'quota'):
            admit([page], 100, 41)

    def test_pagination_cannot_hide_or_repeat_an_artifact(self):
        page = {'total_count': 2, 'artifacts': [{'id': 1, 'size_in_bytes': 10}]}
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            admit([page], 100, 10)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            admit([page, page], 100, 10)
        second = {'total_count': 2, 'artifacts': [{'id': 2, 'size_in_bytes': 20}]}
        self.assertEqual(admit([page, second], 100, 10)['existing_artifact_bytes'], 30)

    def test_malformed_api_and_mutating_inventory_refused(self):
        for row in [{'id': True, 'size_in_bytes': 2}, {'id': 1, 'size_in_bytes': -1}]:
            with self.assertRaises(ValueError):
                admit([{'total_count': 1, 'artifacts': [row]}], 100, 10)
        with self.assertRaisesRegex(ValueError, 'changed'):
            admit([{'total_count': 0, 'artifacts': []}, {'total_count': 1, 'artifacts': []}], 100, 10)


if __name__ == '__main__':
    unittest.main()
