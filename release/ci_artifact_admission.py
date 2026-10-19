"""Bound aggregate public CI metadata retention before a protected build."""
import argparse
import json
import os
from pathlib import Path
import urllib.request

REPOSITORY = 'metaneutrons/ami-rust'
MIB = 1024**2
# The complete serialized normal workflow: seven existing 32 MiB artifacts
# plus a 96 MiB outer candidate/provenance artifact. The latter admits a
# 32 MiB archive, its exact SBOM copy and all signatures/proofs with headroom.
SDK_ARTIFACT_CEILINGS = {
    'producer-macos': 32 * MIB, 'producer-linux': 32 * MIB,
    'unsigned-common': 32 * MIB,
    'authenticated-macos': 32 * MIB, 'authenticated-linux': 32 * MIB,
    'consumer-macos': 32 * MIB, 'consumer-linux': 32 * MIB,
    'release-candidate-and-proofs': 96 * MIB,
}
NATIVE_ARTIFACT_CEILINGS = {
    'native-host-macos': 16 * MIB, 'native-host-linux': 16 * MIB,
    'unsigned-common': 64 * MIB,
    'authenticated-macos': 64 * MIB, 'authenticated-linux': 64 * MIB,
    'consumer-macos': 32 * MIB, 'consumer-linux': 32 * MIB,
    'release-candidate-and-proofs': 96 * MIB,
}


def admit(pages, ceiling, pending_bytes):
    if type(ceiling) is not int or type(pending_bytes) is not int or not 0 < pending_bytes <= ceiling:
        raise ValueError('invalid artifact admission policy')
    ids = set()
    total = 0
    expected = None
    for page in pages:
        if not isinstance(page, dict) or type(page.get('total_count')) is not int:
            raise ValueError('invalid artifact API response')
        if expected is None:
            expected = page['total_count']
        if expected != page['total_count']:
            raise ValueError('artifact set changed during admission; retry a fresh preflight')
        rows = page.get('artifacts')
        if not isinstance(rows, list):
            raise ValueError('artifact list missing')
        for row in rows:
            if (not isinstance(row, dict) or type(row.get('id')) is not int
                    or row['id'] <= 0 or row['id'] in ids
                    or type(row.get('size_in_bytes')) is not int or row['size_in_bytes'] < 0):
                raise ValueError('invalid or duplicate retained artifact')
            ids.add(row['id'])
            total += row['size_in_bytes']
        if total + pending_bytes > ceiling:
            raise ValueError('retained CI artifact quota would be exceeded')
    if expected is None or len(ids) != expected:
        raise ValueError('incomplete artifact inventory')
    return {'schema': 'ami-rust-CI-artifact-admission-v1',
            'existing_artifact_count': len(ids), 'existing_artifact_bytes': total,
            'pending_workflow_metadata_ceiling_bytes': pending_bytes,
            'global_artifact_pool_bytes': ceiling, 'SDK_payload_upload_allowed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-candidate', action='store_true')
    parser.add_argument('--reference-proposal', action='store_true',
                        help='reserve only the two unaccepted host-reference artifacts')
    parser.add_argument('--native-tooling', action='store_true',
                        help='reserve the native host/SDK authentication and consumer artifacts')
    args = parser.parse_args()
    if args.reference_proposal and not args.sdk_candidate:
        parser.error('--reference-proposal requires --sdk-candidate')
    if args.native_tooling and (not args.sdk_candidate or args.reference_proposal):
        parser.error('--native-tooling requires --sdk-candidate without --reference-proposal')
    policy = json.loads((Path(__file__).parent/'ci-resources.json').read_text())
    ceiling = policy['retention']['CI_artifact_pool_bytes']
    # Admit the entire serialized DAG before either matrix producer uploads:
    ceilings = NATIVE_ARTIFACT_CEILINGS if args.native_tooling else SDK_ARTIFACT_CEILINGS
    selected = {key:value for key,value in ceilings.items()
                if not args.reference_proposal or key.startswith('producer-')}
    pending = sum(selected.values()) if args.sdk_candidate else 2 * 32 * MIB
    if args.sdk_candidate and (os.environ.get('GITHUB_REF') != 'refs/heads/main'
                              or os.environ.get('SOURCE_IS_PROTECTED') != 'true'):
        raise ValueError('SDK candidate retention requires protected main')
    token = os.environ.get('GH_TOKEN')
    if not token or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('repository-scoped Actions read token required')
    pages = []
    for number in range(1, 21):
        url = f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts?per_page=100&page={number}'
        request = urllib.request.Request(url, headers={
            'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ami-rust-artifact-admission'})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(2*1024**2+1)
            if len(raw) > 2*1024**2:
                raise ValueError('artifact metadata response exceeds bound')
        page = json.loads(raw)
        pages.append(page)
        if not isinstance(page.get('artifacts'), list):
            raise ValueError('artifact API did not return the required inventory')
        if len(page['artifacts']) < 100:
            break
    report = admit(pages, ceiling, pending)
    report['SDK_candidate_upload_allowed'] = args.sdk_candidate
    if args.sdk_candidate:
        report['workflow_artifact_ceilings_bytes'] = selected
        report['reference_proposal'] = args.reference_proposal
    report['SDK_release_publication_authorized'] = False
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
