"""Positive and refusal probes for aggregate metadata retention admission."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_artifact_admission
from ci_artifact_admission import admit


MIB = 1024 ** 2
POOL = 512 * MIB
TEST_ENV = {
    'GITHUB_REPOSITORY': ci_artifact_admission.REPOSITORY,
    'GH_TOKEN': 'fixture-only-token',
    'GITHUB_REF': 'refs/heads/main',
    'SOURCE_IS_PROTECTED': 'true',
}


class FakeResponse:
    """Small in-memory response that records the bounded read requested."""

    def __init__(self, page):
        self.body = json.dumps(page).encode('utf-8')
        self.read_limits = []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self, limit):
        self.read_limits.append(limit)
        return self.body[:limit]


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


class MainAdmission(unittest.TestCase):
    def run_main(self, args, env, page):
        response = FakeResponse(page)
        calls = []

        def fake_urlopen(request, timeout):
            calls.append((request, timeout))
            return response

        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
                patch.object(sys, 'argv', ['ci_artifact_admission.py', *args]), \
                patch.object(ci_artifact_admission.urllib.request, 'urlopen', side_effect=fake_urlopen), \
                contextlib.redirect_stdout(output):
            ci_artifact_admission.main()
        return output.getvalue(), calls, response

    def test_sdk_candidate_admits_exact_complete_workflow_reservation(self):
        page = {
            'total_count': 2,
            'artifacts': [
                {'id': 1, 'size_in_bytes': 144 * MIB},
                {'id': 2, 'size_in_bytes': 144 * MIB},
            ],
        }
        output, calls, response = self.run_main(['--sdk-candidate'], TEST_ENV, page)

        report = json.loads(output)
        self.assertEqual(7 * 32 * MIB, 224 * MIB)
        self.assertEqual(report['pending_workflow_metadata_ceiling_bytes'], 224 * MIB)
        self.assertEqual(report['existing_artifact_bytes'] + report['pending_workflow_metadata_ceiling_bytes'], POOL)
        self.assertTrue(report['SDK_candidate_upload_allowed'])
        self.assertFalse(report['SDK_release_publication_authorized'])
        self.assertFalse(report['SDK_payload_upload_allowed'])
        self.assertEqual(len(calls), 1)
        request, timeout = calls[0]
        self.assertEqual(request.full_url,
                         f'https://api.github.com/repos/{ci_artifact_admission.REPOSITORY}/actions/artifacts?per_page=100&page=1')
        self.assertEqual(timeout, 30)
        self.assertEqual(response.read_limits, [2 * MIB + 1])
        self.assertNotIn(TEST_ENV['GH_TOKEN'], output)

    def test_sdk_candidate_denied_when_224_mib_reservation_exceeds_pool(self):
        existing = 300 * MIB
        page = {
            'total_count': 3,
            'artifacts': [
                {'id': 1, 'size_in_bytes': 100 * MIB},
                {'id': 2, 'size_in_bytes': 100 * MIB},
                {'id': 3, 'size_in_bytes': 100 * MIB},
            ],
        }
        self.assertLessEqual(existing + 2 * 32 * MIB, POOL)
        self.assertGreater(existing + 7 * 32 * MIB, POOL)
        output = io.StringIO()
        calls = []

        with patch.dict(os.environ, TEST_ENV, clear=True), \
                patch.object(sys, 'argv', ['ci_artifact_admission.py', '--sdk-candidate']), \
                patch.object(ci_artifact_admission.urllib.request, 'urlopen',
                             side_effect=lambda request, timeout: calls.append((request, timeout)) or FakeResponse(page)), \
                contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, 'quota'):
                ci_artifact_admission.main()

        self.assertEqual(len(calls), 1)
        self.assertEqual(output.getvalue(), '')

    def test_sdk_candidate_refuses_unprotected_main_and_wrong_ref_before_http(self):
        cases = [
            ({**TEST_ENV, 'SOURCE_IS_PROTECTED': 'false'}, 'protected main'),
            ({**TEST_ENV, 'GITHUB_REF': 'refs/heads/release'}, 'protected main'),
        ]
        for env, message in cases:
            with self.subTest(env={'GITHUB_REF': env['GITHUB_REF'],
                                   'SOURCE_IS_PROTECTED': env['SOURCE_IS_PROTECTED']}):
                output = io.StringIO()
                with patch.dict(os.environ, env, clear=True), \
                        patch.object(sys, 'argv', ['ci_artifact_admission.py', '--sdk-candidate']), \
                        patch.object(ci_artifact_admission.urllib.request, 'urlopen') as urlopen, \
                        contextlib.redirect_stdout(output):
                    with self.assertRaisesRegex(ValueError, message):
                        ci_artifact_admission.main()
                urlopen.assert_not_called()
                self.assertEqual(output.getvalue(), '')

    def test_legacy_default_reserves_64_mib_and_does_not_claim_candidate_authority(self):
        page = {'total_count': 0, 'artifacts': []}
        unprotected_env = {**TEST_ENV, 'GITHUB_REF': 'refs/heads/feature',
                           'SOURCE_IS_PROTECTED': 'false'}
        output, calls, response = self.run_main([], unprotected_env, page)

        report = json.loads(output)
        self.assertEqual(report['pending_workflow_metadata_ceiling_bytes'], 2 * 32 * MIB)
        self.assertFalse(report['SDK_candidate_upload_allowed'])
        self.assertFalse(report['SDK_release_publication_authorized'])
        self.assertFalse(report['SDK_payload_upload_allowed'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(response.read_limits, [2 * MIB + 1])
        self.assertNotIn(unprotected_env['GH_TOKEN'], output)


if __name__ == '__main__':
    unittest.main()
