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
POOL = 1280 * MIB
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
                {'id': 1, 'size_in_bytes': (POOL - 320 * MIB) // 2},
                {'id': 2, 'size_in_bytes': (POOL - 320 * MIB) // 2},
            ],
        }
        output, calls, response = self.run_main(['--sdk-candidate'], TEST_ENV, page)

        report = json.loads(output)
        self.assertEqual(sum(ci_artifact_admission.SDK_ARTIFACT_CEILINGS.values()), 320 * MIB)
        self.assertEqual(report['pending_workflow_metadata_ceiling_bytes'], 320 * MIB)
        self.assertEqual(report['workflow_artifact_ceilings_bytes'], ci_artifact_admission.SDK_ARTIFACT_CEILINGS)
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

    def test_sdk_candidate_denied_when_complete_candidate_reservation_exceeds_pool(self):
        existing = POOL - 320 * MIB + 1
        page = {
            'total_count': 3,
            'artifacts': [
                {'id': 1, 'size_in_bytes': existing // 3},
                {'id': 2, 'size_in_bytes': existing // 3},
                {'id': 3, 'size_in_bytes': existing - 2 * (existing // 3)},
            ],
        }
        self.assertLessEqual(existing + 2 * 32 * MIB, POOL)
        self.assertLessEqual(existing + 7 * 32 * MIB, POOL)
        self.assertGreater(existing + sum(ci_artifact_admission.SDK_ARTIFACT_CEILINGS.values()), POOL)
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

    def test_proposal_reserves_only_its_two_producer_artifacts(self):
        page = {'total_count':1, 'artifacts':[{'id':1,'size_in_bytes':POOL - 64 * MIB}]}
        output, _, _ = self.run_main(['--sdk-candidate','--reference-proposal'], TEST_ENV, page)
        report = json.loads(output)
        self.assertEqual(report['pending_workflow_metadata_ceiling_bytes'], 64 * MIB)
        self.assertEqual(set(report['workflow_artifact_ceilings_bytes']), {'producer-macos','producer-linux'})
        self.assertTrue(report['reference_proposal'])
        self.assertFalse(report['SDK_release_publication_authorized'])
        page['artifacts'][0]['size_in_bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'quota'):
            self.run_main(['--sdk-candidate','--reference-proposal'], TEST_ENV, page)

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

    def test_native_policy_reservation_and_consumer_guard_agree(self):
        import ci_native
        import ci_sdk
        policy = json.loads((Path(__file__).parent / "ci-artifact-policy.json").read_text())
        self.assertEqual(policy["CI_artifact_pool_bytes"], POOL)
        self.assertEqual(policy["native_consumer_artifact_bytes"], 64 * MIB)
        self.assertEqual(ci_native.MAX_CONSUMER_OUTPUT_BYTES,
                         policy["native_consumer_artifact_bytes"]
                         - policy["native_consumer_framing_reserve_bytes"])
        for host in ("macos", "linux"):
            self.assertEqual(ci_artifact_admission.NATIVE_ARTIFACT_CEILINGS["consumer-" + host],
                             policy["native_consumer_artifact_bytes"])
            self.assertEqual(ci_artifact_admission.SDK_ARTIFACT_CEILINGS["consumer-" + host], 32 * MIB)
        self.assertEqual(ci_sdk.MAX_OUTPUT_BYTES, 32 * MIB - 64 * 1024)

    def test_native_workflow_reserves_the_entire_selected_dag(self):
        pending = sum(ci_artifact_admission.NATIVE_ARTIFACT_CEILINGS.values())
        self.assertEqual(pending, 448 * MIB)
        page = {'total_count': 1, 'artifacts': [{'id': 1, 'size_in_bytes': POOL - pending}]}
        output, _, _ = self.run_main(['--sdk-candidate', '--native-tooling'], TEST_ENV, page)
        report = json.loads(output)
        self.assertEqual(report['pending_workflow_metadata_ceiling_bytes'], pending)
        self.assertEqual(report['workflow_artifact_ceilings_bytes'], ci_artifact_admission.NATIVE_ARTIFACT_CEILINGS)
        self.assertFalse(report['SDK_release_publication_authorized'])
        page['artifacts'][0]['size_in_bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'quota'):
            self.run_main(['--sdk-candidate', '--native-tooling'], TEST_ENV, page)


if __name__ == '__main__':
    unittest.main()
