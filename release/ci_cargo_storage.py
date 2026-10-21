"""Internal RC2 original/derived Cargo component qualification, never SDK publication."""
from __future__ import annotations
import argparse
import datetime
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from release import ci_cargo as c

MIB = 1024**2
WORK_NAME = 'ami-rust-cargo-storage-work'
BOOTSTRAP_NAME = 'ami-rust-python-bootstrap'
OWNER_NAME = '.ami-rust-cargo-storage-owner.json'
SCHEMA = 'ami-rust-cargo-storage-component-v1'
RETAINED_BYTES = 31 * MIB


def own_rss():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == 'darwin' else value * 1024


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * MIB:
        raise ValueError('missing, linked or oversized component input')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate component JSON key')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def fresh(path):
    if not path.is_absolute() or path.is_symlink() or path.exists():
        raise ValueError('component output must be a fresh absolute path')
    parent = path.parent.resolve(strict=True)
    return parent / path.name


def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    if len(raw) > 4 * MIB:
        raise ValueError('component record exceeds its bound')
    with path.open('xb') as stream:
        stream.write(raw)


def tree_files(root):
    """Walk readable owned fixtures; propagate enumeration errors, skip vanished entries."""
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError('managed root is not a real directory')
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            iterator = os.scandir(directory)
        except FileNotFoundError:
            if directory == root:
                raise
            continue
        with iterator:
            for entry in iterator:
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    # Compiler-owned transient children can disappear during a sample.
                    continue
                path = Path(entry.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    yield path, info
                else:
                    raise ValueError('unsupported entry in managed component tree')


def managed_bytes(roots):
    selected = []
    for root in sorted(set(roots), key=lambda p: len(p.parts)):
        if not any(root.is_relative_to(parent) for parent in selected):
            selected.append(root)
    return sum(info.st_size for root in selected for _, info in tree_files(root))


def log_bytes(roots):
    return sum(info.st_size for root in roots for path, info in tree_files(root)
               if stat.S_ISREG(info.st_mode) and path.name.endswith(('.log', '.stdout', '.stderr')))


def source_symlinks(source):
    return {path.relative_to(source).as_posix():os.readlink(path)
            for path, info in tree_files(source)
            if path.relative_to(source).parts[0] != '.git' and stat.S_ISLNK(info.st_mode)}


def verify_derived_source(source, descriptor, supervisor, work, expected_symlinks):
    paths = supervisor.run_text(['/usr/bin/git', '-C', str(source), 'ls-files', '--cached', '--others', '-z'],
                                cwd=work, label='derived-tracked-source-files', timeout=30).split('\0')
    paths = [path for path in paths if path]
    actual_symlinks = {path:os.readlink(source/path) for path in paths if (source/path).is_symlink()}
    if actual_symlinks != expected_symlinks:
        raise ValueError('derived Cargo source changed the original pinned symlink targets')
    files = {path: c.sha256(source / path) for path in paths
             if (source / path).is_file() and not (source / path).is_symlink()}
    expected = descriptor['effective_source']
    if len(files) != expected['file_count'] or c.canonical_sha256(files) != expected['sha256']:
        raise ValueError('derived Cargo complete source identity differs from its descriptor')
    return files


def validate_runtime(runtime, runtime_root, profile, expected_tools):
    contract_path = ROOT/'host/cargo-storage/runtime-checks.json'
    contract = read_json(contract_path)
    if contract.get('schema') != 'ami-rust-cargo-storage-runtime-checks-v1':
        raise ValueError('unknown storage fixture contract')
    required = contract['common'] + contract['profiles'][profile]
    if len(required) != len(set(required)):
        raise ValueError('duplicate required storage fixture check')
    if (not isinstance(runtime, dict)
            or runtime.get('schema') != 'ami-rust-cargo-storage-runtime-rust-v1'
            or runtime.get('status') != 'PASS_HOST_CARGO_STORAGE_FIXTURES_ONLY'
            or runtime.get('rc2_accepted') is not False
            or runtime.get('driver_source_sha256') != c.sha256(ROOT/'tooling/crates/xtask/src/cargo_storage_probe.rs')):
        raise ValueError('Rust storage fixture has an invalid identity or status')
    checks, commands = runtime.get('checks'), runtime.get('commands')
    if (not isinstance(checks, list) or not checks or not isinstance(commands, list) or not commands
            or runtime.get('check_count') != len(checks) or runtime.get('command_count') != len(commands)
            or any(not isinstance(row, dict) or row.get('passed') is not True for row in checks)):
        raise ValueError('incomplete or failed storage fixture observations')
    names = [row.get('name') for row in checks]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)) or set(names) != set(required):
        raise ValueError('storage fixture does not cover the exact required host checks')
    labels = set()
    for command in commands:
        label, expected = command.get('label'), command.get('expected_exit_code')
        if (not isinstance(label, str) or label in labels or type(expected) is not int or expected not in (0, 101)
                or command.get('exit_code') != expected or command.get('stop_reason') is not None
                or command.get('capture_error') is not None
                or command.get('status') != {'exit_code':expected, 'signal':None, 'success':expected == 0}
                or not command.get('argv') or not command.get('environment') or not command.get('cwd')):
            raise ValueError('storage command observation is contradictory or incomplete')
        labels.add(label)
        for stream in ('stdout', 'stderr'):
            identity = command[stream]
            relative = Path(identity['path'])
            if (relative.is_absolute() or len(relative.parts) != 2 or relative.parts[0] != 'logs'
                    or relative.parts[1] in ('.', '..')):
                raise ValueError('storage fixture log path escapes its log directory')
            path = runtime_root/relative
            if ((runtime_root/'logs').is_symlink() or path.is_symlink() or not path.is_file()
                    or path.stat().st_size > 8*MIB or path.stat().st_size != identity['bytes']
                    or c.sha256(path) != identity['sha256']):
                raise ValueError('storage fixture raw log identity mismatch')
    tools = runtime.get('tools')
    if not isinstance(tools, list) or len(tools) != 5 or len({row['name'] for row in tools}) != 5:
        raise ValueError('storage fixture tool inventory is incomplete')
    actual = {row['name']:row for row in tools}
    expected_names = {'control-cargo':'control', 'derived-cargo':'derived', 'rustc':'rustc', 'rustdoc':'rustdoc'}
    for runtime_name, report_name in expected_names.items():
        tool, expected = actual[runtime_name], expected_tools[report_name]
        if (tool['sha256'] != expected['sha256']
                or tool['path']['unix_bytes_hex'] != os.fsencode(expected['path']).hex()):
            raise ValueError('storage fixture executed a different selected tool')
    git = Path('/usr/bin/git').resolve(strict=True)
    if actual['git']['sha256'] != c.sha256(git) or actual['git']['path']['unix_bytes_hex'] != os.fsencode(git).hex():
        raise ValueError('storage fixture Git identity differs')
    return {'contract_sha256':c.sha256(contract_path), 'checked_logs':2*len(commands),
            'checked_commands':len(commands), 'checked_fixture_outcomes':len(checks)}


def run(args):
    temporary = args.temporary.resolve(strict=True)
    output = fresh(args.output)
    work = temporary / WORK_NAME
    bootstrap = temporary / BOOTSTRAP_NAME
    owner = temporary / OWNER_NAME
    if output.parent != temporary or output.name in (WORK_NAME, BOOTSTRAP_NAME, OWNER_NAME):
        raise ValueError('component output must be a distinct temporary sibling')
    if work.exists() or work.is_symlink() or owner.exists() or owner.is_symlink():
        raise ValueError('component work/owner must be fresh')
    if args.python_bootstrap_root.resolve(strict=True) != bootstrap or bootstrap.is_symlink():
        raise ValueError('select the fixed sibling pinned CI Python bootstrap')
    output.mkdir(mode=0o700)
    write_json(owner, {'schema': SCHEMA, 'work': str(work), 'output': str(output),
                       'temporary': str(temporary), 'bootstrap': str(bootstrap), 'pid': os.getpid()})
    start = time.monotonic()
    stage = 'original-source-control'
    report = {'schema': SCHEMA, 'status': 'RUNNING', 'rc2_accepted': False,
              'scope': 'Original/derived host Cargo storage component; no SDK, AROS or release acceptance',
              'source_commit': os.environ.get('GITHUB_SHA'),
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'driver_sha256': c.sha256(Path(__file__)), 'commands': []}
    roots = (ROOT, work, output, bootstrap)
    supervisors = []
    original_supervisor = c.Supervisor
    original_rss_limit = c.MAX_RSS_BYTES
    class CampaignSupervisor(original_supervisor):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            supervisors.append(self)
        def managed_bytes(self):
            return managed_bytes(roots)
        def logs_bytes(self):
            return log_bytes((work, output))
        def run(self, command, *, timeout=1200, **kw):
            remaining = 5400 - (time.monotonic() - start)
            if remaining <= 0:
                raise ValueError('component campaign deadline reached')
            previous_limit = c.MAX_RSS_BYTES
            prior_count = len(self.commands)
            environment_digest = c.canonical_sha256(self.env)
            try:
                # validate_pins sees the immutable 4GiB normative policy. Reserve
                # driver headroom only while the subprocess sampler is active.
                c.MAX_RSS_BYTES = 4 * 1024**3 - 512 * MIB
                result = super().run(command, timeout=min(timeout, remaining), **kw)
            finally:
                c.MAX_RSS_BYTES = previous_limit
                if len(self.commands) > prior_count:
                    row = self.commands[-1]
                    row['argv'] = [os.fsdecode(value) for value in command]
                    row['environment_sha256'] = environment_digest
                    row['cwd'] = str(kw['cwd'])
                    row['timeout_seconds'] = min(timeout, remaining)
                    for stream in ('stdout', 'stderr'):
                        path = self.work / row[stream + '_log']
                        row[stream] = {'bytes': path.stat().st_size, 'sha256': c.sha256(path)}
            if own_rss() + max(s.peak_rss for s in supervisors) > 4 * 1024**3:
                raise ValueError('driver plus command-tree RSS ceiling exceeded')
            return result
    c.Supervisor = CampaignSupervisor
    try:
        inputs_path, resources_path = ROOT/'release/ci-bootstrap-inputs.json', ROOT/'release/ci-resources.json'
        control = c.produce(argparse.Namespace(work=work, output=output/'original-control',
                        inputs=inputs_path, resources=resources_path,
                        python_bootstrap_root=bootstrap))
        report['original_source_control'] = control
        report['original_source_control_limit'] = 'Freshly produced original patched-source control, not a claimed byte-identical old RC1 binary'
        source = work/'cargo-source'
        host = work/'bootstrap'
        vendor = work/'vendor-overlay'
        source_before = c.tree_inventory(source, exclude_git=True)
        symlinks_before = source_symlinks(source)
        vendor_before = c.tree_inventory(vendor)
        compiler_before = c.tree_inventory(host)
        original_binary = work/'build-work/target/release/cargo'
        control_digest = c.sha256(original_binary)
        if control_digest != control['custom_cargo_artifact']['sha256']:
            raise ValueError('original Cargo control changed before derivation')
        descriptor = read_json(ROOT/'host/cargo-storage/source.json')
        patch = ROOT/descriptor['additional_patch']['repository_path']
        if descriptor['upstream_commit'] != control['input_materials']['cargo_upstream']['commit']:
            raise ValueError('derived Cargo has a different upstream source')
        if descriptor['base_patch']['sha256'] != control['input_materials']['cargo_patch']['sha256']:
            raise ValueError('derived Cargo original metadata patch mismatch')
        if c.sha256(patch) != descriptor['additional_patch']['sha256']:
            raise ValueError('derived Cargo storage patch digest mismatch')
        report['storage_source_descriptor'] = descriptor
        report['original_source_inventory_before_derivation'] = source_before
        stage = 'derive-and-build-Cargo'
        build = work/'storage-build'
        build.mkdir()
        env = c.safe_run_env(build, host/'bin')
        env.update(RUSTC=str(host/'bin/rustc'), RUSTDOC=str(host/'bin/rustdoc'),
                   CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
                   CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_DEV_INCREMENTAL='false',
                   CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_INCREMENTAL='false',
                   CARGO_PROFILE_RELEASE_OPT_LEVEL='2', CARGO_PROFILE_RELEASE_CODEGEN_UNITS='16',
                   CARGO_PROFILE_RELEASE_LTO='false', SOURCE_DATE_EPOCH='1791936000',
                   CARGO_TARGET_DIR=str(build/'target'))
        flags = [f'--remap-path-prefix={source}=/cargo-source',
                 f'--remap-path-prefix={build}=/cargo-build',
                 f'--remap-path-prefix={vendor}=/cargo-vendor']
        if sys.platform == 'darwin':
            flags += ['-C', f'link-arg=-Wl,-oso_prefix,{host}/']
        env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
        (build/'cargo-home/config.toml').write_text('[source.crates-io]\nreplace-with="vendored"\n[source.vendored]\ndirectory='+json.dumps(str(vendor))+'\n')
        logs = build/'logs'; logs.mkdir()
        sup = CampaignSupervisor(work, output, env, logs)
        sup.run(['/usr/bin/git', '-C', str(source), 'apply', '--check', str(patch)],
                cwd=work, label='check-storage-patch', timeout=30)
        sup.run(['/usr/bin/git', '-C', str(source), 'apply', str(patch)],
                cwd=work, label='apply-storage-patch', timeout=30)
        source_files = verify_derived_source(source, descriptor, sup, work, symlinks_before)
        report['original_source_symlink_targets'] = symlinks_before
        write_json(output/'effective-source-files.json', source_files)
        snapshot = output/'executed-source'; snapshot.mkdir()
        for name in descriptor['changed_storage_files']:
            out = snapshot/name; out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source/name, out)
        shutil.copy2(patch, output/'cargo-storage.patch')
        sup.run([str(host/'bin/cargo'), 'build', '--locked', '--offline', '-j', '2',
                 '--bin', 'cargo', '--features', 'all-static', '--release'],
                cwd=source, label='build-storage-Cargo')
        derived = build/'target/release/cargo'
        report['tools'] = {key: {'path': str(path), 'bytes': path.stat().st_size, 'sha256': c.sha256(path)}
                           for key, path in [('control', original_binary), ('derived', derived),
                                             ('rustc', host/'bin/rustc'), ('rustdoc', host/'bin/rustdoc')]}
        stage = 'Rust-component-fixtures'
        # Fetch only the unchanged checksum-pinned tooling registry closure, then run offline.
        toolenv = dict(env, CARGO_TARGET_DIR=str(work/'fixture-target'))
        toolenv.pop('CARGO_NET_OFFLINE')
        toolenv.pop('CARGO_ENCODED_RUSTFLAGS')
        toolenv['CARGO_HOME'] = str(work/'fixture-cargo-home')
        Path(toolenv['CARGO_HOME']).mkdir()
        sup.env = toolenv
        sup.run([str(host/'bin/cargo'), 'fetch', '--locked', '--manifest-path', str(ROOT/'tooling/Cargo.toml')],
                cwd=work, label='fetch-locked-Rust-fixture-inputs', timeout=600)
        sup.run([str(host/'bin/cargo'), 'build', '--locked', '--offline', '-j', '2',
                 '--manifest-path', str(ROOT/'tooling/Cargo.toml'), '-p', 'ami-rust-xtask'],
                cwd=work, label='build-Rust-storage-fixtures')
        fixture = work/'fixture-target/debug/ami-rust-xtask'
        report['fixture_executable'] = {'bytes': fixture.stat().st_size, 'sha256': c.sha256(fixture)}
        sup.run([str(fixture), 'cargo-storage-probe', '--control', str(original_binary), '--derived', str(derived),
                 '--rustc', str(host/'bin/rustc'), '--rustdoc', str(host/'bin/rustdoc'),
                 '--work', str(work/'runtime with spaces'), '--output', str(output/'runtime')],
                cwd=work, label='actual-Rust-storage-fixtures')
        report['runtime_result'] = read_json(output/'runtime/result.json')
        report['runtime_readback'] = validate_runtime(report['runtime_result'], output/'runtime', control['host'], report['tools'])
        if c.sha256(original_binary) != control_digest:
            raise ValueError('original Cargo control binary changed')
        if c.tree_inventory(vendor) != vendor_before or c.tree_inventory(host) != compiler_before:
            raise ValueError('immutable compiler/vendor changed')
        if (source_symlinks(source) != symlinks_before
                or any(c.sha256(source/path) != digest for path, digest in source_files.items())):
            raise ValueError('executed derived source changed')
        report['immutable_inputs_unchanged_after'] = True
        if (own_rss() + max(s.peak_rss for s in supervisors) > 4 * 1024**3
                or managed_bytes(roots) > 12 * 1024**3
                or log_bytes((work, output)) > 16*MIB
                or time.monotonic() - start > 5400):
            raise ValueError('final component resource accounting exceeded its policy')
        report['status'] = 'PASS_HOST_CARGO_STORAGE_COMPONENT_ONLY'
    except BaseException as error:
        report.update(status='FAILED', failed_stage=stage, error=repr(error))
        raise
    finally:
        c.Supervisor, c.MAX_RSS_BYTES = original_supervisor, original_rss_limit
        # Preserve exact selected logs; no compiler/cache/binary payload upload.
        retained = output/'logs'; retained.mkdir(exist_ok=True)
        if work.exists():
            for name in ('logs', 'records', 'storage-build/logs'):
                origin = work/name
                if origin.is_dir():
                    for path in origin.rglob('*'):
                        if path.is_file() and not path.is_symlink():
                            dest = retained/path.relative_to(work)
                            dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, dest)
        report.update(completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      elapsed_seconds=time.monotonic()-start,
                      supervision={'driver_peak_rss_bytes': own_rss(),
                                   'command_tree_peak_rss_bytes': max((s.peak_rss for s in supervisors), default=0),
                                   'conservative_driver_plus_child_peak_rss_bytes': own_rss()+max((s.peak_rss for s in supervisors), default=0),
                                   'workspace_peak_bytes': max([s.peak_workspace for s in supervisors] + ([managed_bytes(roots)] if work.exists() else [0])),
                                   'logs_bytes': log_bytes((work, output)) if work.exists() else 0,
                                   'commands': [row for s in supervisors for row in s.commands],
                                   'limits': {'rss_bytes':4*1024**3, 'workspace_bytes':12*1024**3,
                                              'logs_bytes':16*MIB, 'command_seconds':1200, 'campaign_seconds':5400}})
        violations = []
        measured = report['supervision']
        encoded_bytes = len((json.dumps(report, indent=2, sort_keys=True)+'\n').encode())
        measured['workspace_peak_bytes'] = max(measured['workspace_peak_bytes'], managed_bytes(roots)+encoded_bytes)
        if measured['conservative_driver_plus_child_peak_rss_bytes'] > 4*1024**3:
            violations.append('aggregate driver plus command RSS')
        if measured['workspace_peak_bytes'] > 12*1024**3:
            violations.append('managed workspace')
        if measured['logs_bytes'] > 16*MIB:
            violations.append('aggregate logs including retained copies')
        if report['elapsed_seconds'] > 5400:
            violations.append('campaign deadline including evidence finalization')
        # Include the final record in admission before it can contain a PASS.
        encoded_bytes = len((json.dumps(report, indent=2, sort_keys=True)+'\n').encode())
        if managed_bytes((output,)) + encoded_bytes > RETAINED_BYTES:
            violations.append('retained component evidence capacity')
        if violations:
            report.update(status='FAILED', finalization_errors=violations)
        write_json(output/'component.json', report)
        if violations:
            raise ValueError('component finalization failed: ' + ', '.join(violations))
    print(json.dumps({'status': report['status'], 'output': str(output)}))


def cleanup(args):
    temporary = args.temporary.resolve(strict=True)
    owner = temporary/OWNER_NAME
    value = read_json(owner)
    work = temporary/WORK_NAME
    bootstrap = temporary/BOOTSTRAP_NAME
    output = args.output.resolve(strict=True)
    if (value.get('schema') != SCHEMA or value.get('work') != str(work)
            or value.get('output') != str(output) or value.get('temporary') != str(temporary)
            or value.get('bootstrap') != str(bootstrap) or output.parent != temporary):
        raise ValueError('component cleanup ownership mismatch')
    final = read_json(output/'component.json')
    if (final.get('schema') != SCHEMA
            or final.get('status') not in ('FAILED', 'PASS_HOST_CARGO_STORAGE_COMPONENT_ONLY')
            or final.get('rc2_accepted') is not False):
        raise ValueError('no finalized component receipt; preserve work after interrupted coordinator')
    pid = value.get('pid')
    if type(pid) is not int or pid <= 0:
        raise ValueError('component owner PID is invalid')
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise ValueError('component coordinator may still be live')
    if work.is_symlink() or (work.exists() and not work.is_dir()):
        raise ValueError('refuse linked/invalid component work')
    if bootstrap.is_symlink() or (bootstrap.exists() and not bootstrap.is_dir()):
        raise ValueError('refuse linked/invalid internal Python bootstrap')
    receipt_bytes = 0
    if bootstrap.exists():
        read_json(bootstrap/'bootstrap.json')
        receipt_bytes = (bootstrap/'bootstrap.json').stat().st_size
    if managed_bytes((output,)) + receipt_bytes + MIB > 32*MIB:
        raise ValueError('retained evidence exceeds capacity before cleanup receipt/framing')
    # Validate every owned root and the retained envelope before retiring any work.
    if work.exists():
        shutil.rmtree(work)
    if bootstrap.exists():
        shutil.copy2(bootstrap/'bootstrap.json', output/'python-bootstrap.json')
        shutil.rmtree(bootstrap)
    write_json(output/'cleanup.json', {'schema':SCHEMA, 'status':'OWNED_WORK_RETIRED',
                'work_remaining_bytes': c.directory_bytes(work), 'internal_python_remaining_bytes': c.directory_bytes(bootstrap), 'retained_bytes': c.directory_bytes(output),
                'source_commit': os.environ.get('GITHUB_SHA'), 'sdk_publication':False})
    owner.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--temporary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--python-bootstrap-root', type=Path)
    parser.add_argument('--cleanup', action='store_true')
    args = parser.parse_args()
    if args.cleanup:
        cleanup(args)
    elif args.python_bootstrap_root is None:
        parser.error('select the pinned internal CI Python bootstrap')
    else:
        def interrupted(signum, frame):
            raise InterruptedError('component coordinator received SIGTERM')
        prior = signal.signal(signal.SIGTERM, interrupted)
        try:
            run(args)
        finally:
            signal.signal(signal.SIGTERM, prior)

if __name__ == '__main__':
    main()
