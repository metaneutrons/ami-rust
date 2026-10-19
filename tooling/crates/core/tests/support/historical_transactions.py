#!/usr/bin/env python3
"""Bounded differential filesystem proof for the RC1 host transaction API."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import traceback

REPO = Path(os.environ['AMI_RUST_DIFFERENTIAL_SOURCE']).resolve(strict=True)
EVIDENCE = Path(os.environ['AMI_RUST_DIFFERENTIAL_WORK']).resolve(strict=True)
RUNS = EVIDENCE / 'runs'
RUNS.mkdir(mode=0o700)
BINARY = Path(os.environ['AMI_RUST_DIFFERENTIAL_TEST_BINARY']).resolve(strict=True)
INSTALLER_PATH = REPO / 'release' / 'install.py'
TEST_PATH = REPO / 'release' / 'test_install.py'
PYTHON = Path(sys.executable).resolve(strict=True)
RESULTS = []
LOGS = []


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    root = REPO / 'tooling' / 'crates' / 'core' / 'src'
    return {str(path.relative_to(REPO)): sha256(path.read_bytes())
            for path in sorted(root.rglob('*.rs'))}


def snapshot(root):
    root = Path(root)
    if not root.exists() and not root.is_symlink():
        return None
    result = []
    pending = [(root, '.')]
    while pending:
        path, relative = pending.pop()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            result.append({'path': relative, 'kind': 'directory', 'mode': mode, 'uid': info.st_uid, 'gid': info.st_gid})
            children = sorted(os.scandir(path), key=lambda item: item.name, reverse=True)
            for child in children:
                child_path = Path(child.path)
                child_rel = child.name if relative == '.' else relative + '/' + child.name
                pending.append((child_path, child_rel))
        elif stat.S_ISREG(info.st_mode):
            data = path.read_bytes()
            result.append({'path': relative, 'kind': 'file', 'mode': mode, 'uid': info.st_uid, 'gid': info.st_gid,
                           'bytes': len(data), 'sha256': sha256(data)})
        elif stat.S_ISLNK(info.st_mode):
            result.append({'path': relative, 'kind': 'symlink', 'mode': mode, 'uid': info.st_uid, 'gid': info.st_gid,
                           'target': os.readlink(path)})
        else:
            result.append({'path': relative, 'kind': 'special', 'mode': mode, 'uid': info.st_uid, 'gid': info.st_gid})
    return sorted(result, key=lambda item: item['path'])


def save_log(name, payload):
    path = RUNS / (name + '.json')
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + '\n')
    LOGS.append(str(path.relative_to(EVIDENCE)))


def rust_call(name, plan):
    plan_path = RUNS / (name + '.plan.json')
    plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + '\n')
    env = {'PATH': os.defpath, 'HOME': str(Path.home().resolve(strict=True)),
           'LC_ALL': 'C', 'LANG': 'C'}
    env['AMI_RUST_TRANSACTION_PLAN'] = str(plan_path)
    command = [str(BINARY), '--ignored', '--exact', 'transaction_bridge_child', '--nocapture']
    proc = subprocess.run(command, cwd=REPO, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False, timeout=60)
    try:
        output = json.loads(plan_path.with_suffix('.result.json').read_bytes())
    except Exception:
        output = None
    save_log(name + '.rust', {'command': command, 'returncode': proc.returncode,
                              'stdout': proc.stdout, 'stderr': proc.stderr,
                              'parsed': output})
    if not isinstance(output, dict) or proc.returncode != (int(output.get('exit_code', 2)) if output.get('status') == 'refusal' else 0):
        raise AssertionError(f'Rust bridge failed for {name}: rc={proc.returncode}, stdout={proc.stdout!r}, stderr={proc.stderr!r}')
    return output


def py_call(name, proc):
    try:
        output = json.loads(proc.stdout) if proc.stdout.strip() else None
    except Exception:
        output = None
    save_log(name + '.python', {'returncode': proc.returncode,
                                'stdout': proc.stdout, 'stderr': proc.stderr,
                                'parsed': output})
    return output


def assert_equal(label, left, right):
    if left != right:
        raise AssertionError(f'{label} differs\nPython={json.dumps(left, sort_keys=True)}\nRust={json.dumps(right, sort_keys=True)}')


def assert_refusal(label, python_result, rust_result, python_code=2):
    if python_result.returncode != python_code:
        raise AssertionError(f'{label}: Python exit {python_result.returncode}, expected {python_code}')
    if rust_result.get('status') != 'refusal':
        raise AssertionError(f'{label}: Rust decision was {rust_result!r}')
    if rust_result.get('exit_code') not in (None, 2):
        raise AssertionError(f'{label}: Rust transaction exit code {rust_result.get("exit_code")}')


def ensure_mode(path, mode):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def create_install_plan(prefix, pin, bundle, receipt_path, files):
    return {'operation': 'publish', 'prefix': str(prefix), 'pin': str(pin) if pin else None,
            'bundle': str(bundle), 'receipt_path': str(receipt_path), 'files': files}


def main():
    actual_hash = sha256(PYTHON.read_bytes())
    pins = json.loads((REPO / 'release/ci-python-inputs.json').read_bytes())
    host = 'macos-aarch64' if sys.platform == 'darwin' else 'linux-x86_64'
    expected_hash = pins['hosts'][host]['runtime_sha256']
    assert PYTHON.stat().st_size == pins['hosts'][host]['runtime_bytes']
    assert sha256(INSTALLER_PATH.read_bytes()) == '0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984'
    assert sha256(TEST_PATH.read_bytes()) == '379ba1ab0f3795dd880c17ec46705bf976da9b21bc9a57f7884c573e73bcd64c'
    if actual_hash != expected_hash:
        raise AssertionError(f'pinned Python SHA mismatch: {actual_hash}')
    if Path(sys.executable).resolve() != PYTHON.resolve():
        raise AssertionError(f'wrong Python interpreter: {sys.executable}')

    sources_at_start = source_hashes()
    installer = load_module('ami_rust_release_installer', INSTALLER_PATH)
    tests = load_module('ami_rust_release_test_install', TEST_PATH)
    tests.InstallerFixture.setUpClass()
    fixture = tests.InstallerFixture('test_install_then_uninstall_removes_only_owned_tree')
    fixture.setUp()
    try:
        verified = installer.verify_bundle(str(fixture.bundle), str(fixture.trust_path))
        build_root = fixture.case / 'rust-input-files'
        build_root.mkdir(mode=0o700)
        files = []
        index = 0
        for name, contents in sorted(verified['sdk_files'].items()):
            mode = 0o755 if verified['sdk_modes'].get(name, 0o644) & 0o111 else 0o644
            source = build_root / f'{index:03d}.bin'
            index += 1
            source.write_bytes(contents)
            files.append({'path': 'sdk/' + name, 'source': str(source), 'mode': mode})
        for name, contents in sorted(verified['assets'].items()):
            source = build_root / f'{index:03d}.bin'
            index += 1
            source.write_bytes(contents)
            files.append({'path': 'payload/' + name, 'source': str(source), 'mode': 0o644})
        for name, contents in [('release.json', verified['manifest_raw']),
                               ('release.json.sig', verified['signature'])]:
            source = build_root / f'{index:03d}.bin'
            index += 1
            source.write_bytes(contents)
            files.append({'path': 'payload/' + name, 'source': str(source), 'mode': 0o644})

        source_bundle_before = snapshot(fixture.bundle)
        receipt_source = build_root / 'receipt.bin'
        homes = {}

        # Positive install and uninstall; receipt bytes are taken unchanged from
        # the legacy install and become input to the Rust filesystem API.
        positive_py = fixture.case / 'positive-python'
        positive_rs = fixture.case / 'positive-rust'
        ensure_mode(positive_py, 0o700)
        ensure_mode(positive_rs, 0o700)
        py_prefix, py_pin = positive_py / 'sdk-0.1.0-rc.3-local', positive_py / 'receipt.sha256'
        rs_prefix, rs_pin = positive_rs / 'sdk-0.1.0-rc.3-local', positive_rs / 'receipt.sha256'
        py_install = fixture._install(prefix=py_prefix, pin=py_pin, bundle=fixture.bundle)
        py_install_json = py_call('positive-install', py_install)
        if py_install.returncode != 0 or not py_install_json or py_install_json.get('status') != 'installed':
            raise AssertionError(f'legacy install failed: {py_install_json!r}')
        receipt_bytes = (py_prefix / 'install-receipt.json').read_bytes()
        receipt_source.write_bytes(receipt_bytes)
        receipt_value = json.loads(receipt_bytes)
        rust_install = rust_call('positive-install', create_install_plan(
            rs_prefix, rs_pin, fixture.bundle, receipt_source, files))
        if rust_install.get('status') != 'ok':
            raise AssertionError(f'Rust publish failed: {rust_install!r}')
        assert_equal('receipt digest', py_install_json['receipt_sha256'], rust_install['receipt_sha256'])
        assert_equal('published tree and external pin', snapshot(py_prefix.parent), snapshot(rs_prefix.parent))
        assert_equal('source bundle after install', source_bundle_before, snapshot(fixture.bundle))
        RESULTS.append({'case':'fresh-install', 'decision':'both accepted',
                        'receipt_sha256':py_install_json['receipt_sha256'],
                        'inventory_files':len(receipt_value['inventory']),
                        'tree_equal':True, 'bundle_preserved':True})

        inventory = [{'path': row['path'], 'bytes': row['bytes'], 'sha256': row['sha256']}
                     for row in receipt_value['inventory']]
        digest = py_install_json['receipt_sha256']
        # Correct uninstall leaves the external pin and bundle untouched.
        py_remove = fixture._uninstall(prefix=py_prefix, receipt_sha256=digest)
        py_remove_json = py_call('positive-uninstall', py_remove)
        if py_remove.returncode != 0 or not py_remove_json or py_remove_json.get('status') != 'uninstalled':
            raise AssertionError(f'legacy uninstall failed: {py_remove_json!r}')
        rust_remove = rust_call('positive-uninstall', {
            'operation':'remove', 'prefix':str(rs_prefix), 'inventory':inventory,
            'receipt_digest':digest})
        if rust_remove.get('status') != 'ok':
            raise AssertionError(f'Rust remove failed: {rust_remove!r}')
        assert_equal('uninstalled parent state with external pin retained',
                     snapshot(py_prefix.parent), snapshot(rs_prefix.parent))
        assert_equal('bundle after uninstall', source_bundle_before, snapshot(fixture.bundle))
        RESULTS.append({'case':'correct-uninstall', 'decision':'both accepted',
                        'external_pin_retained':True, 'bundle_preserved':True})

        # Occupied installation prefix: refusal must precede any staging mutation.
        py_home, rs_home = fixture.case / 'occupied-prefix-python', fixture.case / 'occupied-prefix-rust'
        ensure_mode(py_home, 0o700); ensure_mode(rs_home, 0o700)
        py_prefix, rs_prefix = py_home / 'sdk-0.1.0-rc.3-local', rs_home / 'sdk-0.1.0-rc.3-local'
        for prefix in (py_prefix, rs_prefix):
            prefix.mkdir(mode=0o700)
            (prefix / 'sentinel').write_bytes(b'occupied-prefix')
        before_py, before_rs = snapshot(py_home), snapshot(rs_home)
        py_result = fixture._install(prefix=py_prefix, pin=False, bundle=fixture.bundle)
        py_output = py_call('occupied-prefix', py_result)
        rust_result = rust_call('occupied-prefix', create_install_plan(
            rs_prefix, None, fixture.bundle, receipt_source, files))
        assert_refusal('occupied prefix', py_result, rust_result)
        assert_equal('occupied prefix effects', snapshot(py_home), snapshot(rs_home))
        assert_equal('occupied prefix was unchanged', before_py, snapshot(py_home))
        assert_equal('occupied prefix rust unchanged', before_rs, snapshot(rs_home))
        RESULTS.append({'case':'occupied-prefix', 'decision':'both refused',
                        'legacy_exit':py_result.returncode, 'rust_exit':rust_result.get('exit_code', 2),
                        'filesystem_unchanged':True})

        # Occupied external pin: neither implementation publishes the prefix.
        py_home, rs_home = fixture.case / 'occupied-pin-python', fixture.case / 'occupied-pin-rust'
        ensure_mode(py_home, 0o700); ensure_mode(rs_home, 0o700)
        py_prefix, rs_prefix = py_home / 'sdk-0.1.0-rc.3-local', rs_home / 'sdk-0.1.0-rc.3-local'
        py_pin, rs_pin = py_home / 'receipt.sha256', rs_home / 'receipt.sha256'
        for pin in (py_pin, rs_pin):
            pin.write_bytes(b'user-owned-existing-pin\n')
        before_py, before_rs = snapshot(py_home), snapshot(rs_home)
        py_result = fixture._install(prefix=py_prefix, pin=py_pin, bundle=fixture.bundle)
        py_output = py_call('occupied-pin', py_result)
        rust_result = rust_call('occupied-pin', create_install_plan(
            rs_prefix, rs_pin, fixture.bundle, receipt_source, files))
        assert_refusal('occupied receipt pin', py_result, rust_result)
        assert_equal('occupied pin effects', snapshot(py_home), snapshot(rs_home))
        assert_equal('occupied pin Python unchanged', before_py, snapshot(py_home))
        assert_equal('occupied pin Rust unchanged', before_rs, snapshot(rs_home))
        RESULTS.append({'case':'occupied-pin', 'decision':'both refused',
                        'legacy_exit':py_result.returncode, 'rust_exit':rust_result.get('exit_code', 2),
                        'prefix_unpublished':not py_prefix.exists() and not rs_prefix.exists(),
                        'filesystem_unchanged':True})

        # Helper produces a valid pair for uninstall-negative controls.
        def installed_pair(label):
            py_home, rs_home = fixture.case / (label + '-python'), fixture.case / (label + '-rust')
            ensure_mode(py_home, 0o700); ensure_mode(rs_home, 0o700)
            py_prefix, rs_prefix = py_home / 'sdk-0.1.0-rc.3-local', rs_home / 'sdk-0.1.0-rc.3-local'
            py_pin, rs_pin = py_home / 'receipt.sha256', rs_home / 'receipt.sha256'
            py_install = fixture._install(prefix=py_prefix, pin=py_pin, bundle=fixture.bundle)
            py_json = py_call(label + '-setup-install', py_install)
            if py_install.returncode != 0 or not py_json or py_json.get('status') != 'installed':
                raise AssertionError(f'{label}: legacy setup install failed {py_json!r}')
            rust_install = rust_call(label + '-setup-install', create_install_plan(
                rs_prefix, rs_pin, fixture.bundle, receipt_source, files))
            if rust_install.get('status') != 'ok':
                raise AssertionError(f'{label}: Rust setup install failed {rust_install!r}')
            assert_equal(label + ' setup tree', snapshot(py_home), snapshot(rs_home))
            return py_home, rs_home, py_prefix, rs_prefix, py_json['receipt_sha256']

        # Tampered installed content is refused before tombstoning by both.
        py_home, rs_home, py_prefix, rs_prefix, digest = installed_pair('tampered-uninstall')
        for prefix in (py_prefix, rs_prefix):
            (prefix / 'sdk' / 'fixture' / 'marker.txt').write_bytes(b'tampered marker\n')
        before_py, before_rs = snapshot(py_home), snapshot(rs_home)
        py_result = fixture._uninstall(prefix=py_prefix, receipt_sha256=digest)
        py_output = py_call('tampered-uninstall', py_result)
        rust_result = rust_call('tampered-uninstall', {
            'operation':'remove', 'prefix':str(rs_prefix), 'inventory':inventory,
            'receipt_digest':digest})
        assert_refusal('tampered uninstall', py_result, rust_result)
        assert_equal('tampered refusal effects', snapshot(py_home), snapshot(rs_home))
        assert_equal('tampered Python unchanged', before_py, snapshot(py_home))
        assert_equal('tampered Rust unchanged', before_rs, snapshot(rs_home))
        RESULTS.append({'case':'tampered-uninstall', 'decision':'both refused',
                        'legacy_exit':py_result.returncode, 'filesystem_unchanged':True})

        # An unlisted empty directory is also a refusal, not recursively deleted.
        py_home, rs_home, py_prefix, rs_prefix, digest = installed_pair('extra-directory-uninstall')
        for prefix in (py_prefix, rs_prefix):
            (prefix / 'unexpected-empty').mkdir(mode=0o700)
        before_py, before_rs = snapshot(py_home), snapshot(rs_home)
        py_result = fixture._uninstall(prefix=py_prefix, receipt_sha256=digest)
        py_output = py_call('extra-directory-uninstall', py_result)
        rust_result = rust_call('extra-directory-uninstall', {
            'operation':'remove', 'prefix':str(rs_prefix), 'inventory':inventory,
            'receipt_digest':digest})
        assert_refusal('extra directory uninstall', py_result, rust_result)
        assert_equal('extra directory refusal effects', snapshot(py_home), snapshot(rs_home))
        assert_equal('extra dir Python unchanged', before_py, snapshot(py_home))
        assert_equal('extra dir Rust unchanged', before_rs, snapshot(rs_home))
        RESULTS.append({'case':'extra-empty-directory-uninstall', 'decision':'both refused',
                        'legacy_exit':py_result.returncode, 'filesystem_unchanged':True})

        # Additional matched refusal effects on current transaction bytes.
        for label in ('stale-receipt', 'extra-user-file', 'missing-owned-file'):
            py_home, rs_home, py_prefix, rs_prefix, digest = installed_pair(label)
            if label == 'stale-receipt':
                supplied = '0' * 64
                assert digest != supplied
            else:
                supplied = digest
                for prefix in (py_prefix, rs_prefix):
                    if label == 'extra-user-file':
                        (prefix / 'user-notes.txt').write_bytes(b'preserve these user notes\n')
                        (prefix / 'user-notes.txt').chmod(0o600)
                    else:
                        (prefix / 'sdk' / 'fixture' / 'marker.txt').unlink()
            before_py, before_rs = snapshot(py_home), snapshot(rs_home)
            py_result = fixture._uninstall(prefix=py_prefix, receipt_sha256=supplied)
            py_call(label, py_result)
            rust_result = rust_call(label, {'operation':'remove', 'prefix':str(rs_prefix), 'inventory':inventory, 'receipt_digest':supplied})
            assert_refusal(label, py_result, rust_result)
            assert_equal(label + ' paired effects', snapshot(py_home), snapshot(rs_home))
            assert_equal(label + ' Python preserved', before_py, snapshot(py_home))
            assert_equal(label + ' Rust preserved', before_rs, snapshot(rs_home))
            RESULTS.append({'case':label, 'decision':'both refused', 'legacy_exit':py_result.returncode,
                            'rust_wrapper_exit':2, 'filesystem_unchanged':True, 'before_python':before_py,
                            'after_python':snapshot(py_home), 'before_rust':before_rs, 'after_rust':snapshot(rs_home)})

        if source_hashes() != sources_at_start:
            raise AssertionError('public core source changed during differential proof; rebuild and rerun against the final source bytes')
        if snapshot(fixture.bundle) != source_bundle_before:
            raise AssertionError('release bundle changed during filesystem proof')
        report = {
            'status':'pass', 'historical_source_sha256': {'release/install.py':sha256(INSTALLER_PATH.read_bytes()), 'release/test_install.py':sha256(TEST_PATH.read_bytes())}, 'case_count':len(RESULTS), 'ownership_scope':'same OS account, actual uid/gid and mode plus full tree/pins; not privileged cross-account mutation',
            'scope':'host filesystem transaction effects only; no Rust receipt/authentication/CLI capability claim',
            'host':host, 'python':{'path':str(PYTHON),'version':'3.12.15','sha256':actual_hash,'invocation':'-I -B'},
            'rust':{'toolchain':'1.98.1','crate':'ami-rust-core transaction API','binary':str(BINARY)},
            'source_sha256':sources_at_start,
            'source_unchanged_during_run':True,
            'cases':RESULTS,
            'limitations':['No injected post-publication partial failure; public API exposes no fault-injection hook.',
                           'The Rust bridge intentionally uses the receipt bytes from the legacy disposable-signature install; authentication and receipt parsing remain outside this filesystem-layer comparison.',
                           'This report covers only the host recorded by the current execution.'],
            'logs':LOGS,
        }
        (EVIDENCE / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True, indent=2))
    finally:
        fixture.tearDown()
        tests.InstallerFixture.tearDownClass()


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        failure = {'status':'fail','error':repr(error),'traceback':traceback.format_exc(),
                   'source_sha256_at_failure':source_hashes(),'cases_completed':RESULTS,'logs':LOGS}
        report_path = EVIDENCE / 'failure-report.json'
        suffix = 1
        while report_path.exists():
            suffix += 1
            report_path = EVIDENCE / f'failure-report-{suffix:02d}.json'
        report_path.write_text(json.dumps(failure, sort_keys=True, indent=2) + '\n')
        print(json.dumps(failure, sort_keys=True, indent=2), file=sys.stderr)
        raise
