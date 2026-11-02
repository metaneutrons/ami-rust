// SPDX-License-Identifier: MIT OR Apache-2.0
// Tests of the registry tool: each gate has a positive and a counter-probe.
// Run with: node --test tools/registry/

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';
import * as registry from './registry.mjs';
import { TomlError, parseToml } from './toml.mjs';

const OWN_URL = 'https://crates.example.org/';
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const silently = async (action) => {
  const log = console.log;
  console.log = () => {};
  try {
    return await action();
  } finally {
    console.log = log;
  }
};

function tarHeader(name, size, flag = '0') {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${size.toString(8).padStart(11, '0')}\0`, 124);
  header.write('00000000000\0', 136);
  header.write('        ', 148);
  header.write(flag, 156);
  header.write('ustar\0', 257);
  header.write('00', 263);
  const sum = [...header].reduce((a, b) => a + b, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return header;
}

function tarGz(members) {
  const blocks = [];
  for (const [name, content, flag] of members) {
    const data = Buffer.from(content);
    blocks.push(tarHeader(name, data.length, flag), data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

const crateBytes = (name, version, text, member) => tarGz([[member ?? `${name}-${version}/Cargo.toml`, text]]);
const manifest = (name, version, extra = '') => `[package]\nname = "${name}"\nversion = "${version}"\nrust-version = "1.98"\n${extra}`;
const entryOf = (text, name = 'aros', version = '0.2.0', own = ['aros', 'aros-sys']) =>
  JSON.parse(registry.indexLine(crateBytes(name, version, text), name, version, new Set(own), OWN_URL));

class FakeBucket {
  constructor() {
    this.store = new Map();
    this.writes = [];
  }
  async get(key) {
    return this.store.get(key) ?? null;
  }
  async put(key, data) {
    this.store.set(key, Buffer.from(data));
    this.writes.push(key);
  }
  async headBucket() {
    return true;
  }
}

test('index paths follow the length of the name', () => {
  assert.equal(registry.indexPath('a'), '1/a');
  assert.equal(registry.indexPath('ab'), '2/ab');
  assert.equal(registry.indexPath('abc'), '3/a/abc');
  assert.equal(registry.indexPath('aros'), 'ar/os/aros');
  assert.equal(registry.indexPath('Aros-Sys'), 'ar/os/aros-sys');
});

test('malformed crate names are refused', () => {
  for (const name of ['', '../x', 'a/b', '1abc', 'a b']) assert.throws(() => registry.indexPath(name), registry.Refusal);
});

test('archive names split into name and version', () => {
  assert.deepEqual(registry.splitArchiveName('aros-sys-0.2.0.crate'), ['aros-sys', '0.2.0']);
  assert.deepEqual(registry.splitArchiveName('aros-1.0.0-rc.1.crate'), ['aros', '1.0.0-rc.1']);
  for (const name of ['aros.crate', 'aros-0.2.crate', '../aros-0.2.0.crate', 'aros-0.2.0.tar']) {
    assert.throws(() => registry.splitArchiveName(name), registry.Refusal, name);
  }
});

test('an index line carries the checksum, version and rust version', () => {
  const data = crateBytes('aros', '0.2.0', manifest('aros', '0.2.0'));
  const entry = JSON.parse(registry.indexLine(data, 'aros', '0.2.0', new Set(['aros']), OWN_URL));
  assert.equal(entry.cksum, sha256(data));
  assert.deepEqual([entry.name, entry.vers, entry.yanked, entry.links], ['aros', '0.2.0', false, null]);
  assert.equal(entry.rust_version, '1.98');
  assert.equal(entry.v, 1);
});

test('the keys of an index line are sorted and compact', () => {
  const line = registry.indexLine(crateBytes('aros', '0.2.0', manifest('aros', '0.2.0')), 'aros', '0.2.0', new Set(['aros']), OWN_URL);
  assert.equal(line, registry.canonicalJson(JSON.parse(line)));
  assert.ok(line.startsWith('{"cksum":'));
  assert.ok(!line.includes(' '));
});

test('dependencies: own crates are the same registry, others come from crates.io', () => {
  const entry = entryOf(
    manifest(
      'aros',
      '0.2.0',
      '[dependencies]\naros-sys = "=0.2.0"\nserde = { version = "1", features = ["derive"], optional = true }\n' +
        '[dev-dependencies]\ntempfile = "3"\n' +
        '[build-dependencies]\ncc = "1"\n' +
        "[target.'cfg(unix)'.dependencies]\nlibc = { version = \"0.2\", default-features = false }\n" +
        '[dependencies.renamed]\nversion = "2"\npackage = "real-name"\n',
    ),
  );
  const deps = new Map(entry.deps.map((d) => [`${d.name}/${d.kind}/${d.target}`, d]));
  assert.equal(deps.get('aros-sys/normal/null').registry, null);
  assert.equal(deps.get('serde/normal/null').registry, registry.CRATES_IO_INDEX);
  assert.equal(deps.get('serde/normal/null').optional, true);
  assert.deepEqual(deps.get('serde/normal/null').features, ['derive']);
  assert.ok(deps.has('cc/build/null'));
  assert.equal(deps.get('libc/normal/cfg(unix)').default_features, false);
  assert.equal(deps.get('renamed/normal/null').package, 'real-name');
  assert.ok(!entry.deps.some((d) => d.name === 'tempfile'));
});

test('a dependency on this registry by URL is the same registry, with or without sparse+', () => {
  for (const url of [OWN_URL, `sparse+${OWN_URL}`]) {
    const entry = entryOf(manifest('aros', '0.2.0', `[dependencies]\nother = { version = "1", registry-index = "${url}" }\n`), 'aros', '0.2.0', ['aros']);
    assert.equal(entry.deps[0].registry, null);
  }
});

test('crates packaged together are the same registry whatever URL they were staged with', () => {
  const entry = entryOf(manifest('aros', '0.2.0', '[dependencies]\naros-sys = { version = "=0.2.0", registry-index = "sparse+https://staging.example/" }\n'));
  assert.equal(entry.deps[0].registry, null);
});

test('counter-probe: a foreign registry for an unknown crate is kept', () => {
  const entry = entryOf(manifest('aros', '0.2.0', '[dependencies]\nother = { version = "1", registry-index = "sparse+https://elsewhere.example/" }\n'), 'aros', '0.2.0', ['aros']);
  assert.equal(entry.deps[0].registry, 'sparse+https://elsewhere.example/');
});

test('features with the newer syntax move to features2', () => {
  const entry = entryOf(manifest('aros', '0.2.0', '[features]\nalloc = []\nserde = ["dep:serde"]\nweak = ["serde?/derive"]\n'));
  assert.deepEqual(entry.features, { alloc: [] });
  assert.deepEqual(entry.features2, { serde: ['dep:serde'], weak: ['serde?/derive'] });
  assert.equal(entry.v, 2);
});

test('counter-probes: a wrong or missing manifest is refused', () => {
  const index = (data, name = 'aros') => registry.indexLine(data, name, '0.2.0', new Set(['aros']), OWN_URL);
  assert.throws(() => index(crateBytes('aros', '0.2.0', manifest('other', '0.2.0'))), registry.Refusal);
  assert.throws(() => index(crateBytes('aros', '0.2.0', manifest('aros', '0.2.0'), '../Cargo.toml')), registry.Refusal);
  assert.throws(() => index(crateBytes('aros', '0.2.0', manifest('aros', '0.2.0'), 'aros-0.2.0/Cargo.toml/')), registry.Refusal);
});

test('tar members: a long name in a pax header is honoured', () => {
  const long = `aros-0.2.0/${'d/'.repeat(80)}Cargo.toml`;
  const record = ` path=${long}\n`;
  const pax = `${record.length + String(record.length).length}${record}`;
  const data = tarGz([['PaxHeader', pax, 'x'], ['short', 'x = 1\n', '0']]);
  const names = [...registry.tarMembers(gunzipSync(data))].map((member) => member.name);
  assert.deepEqual(names, [long]);
});

test('merging appends, is idempotent, and refuses to change a published version', () => {
  const line = (version, { yanked = false, cksum = 'a' } = {}) => registry.canonicalJson({ name: 'aros', vers: version, cksum, yanked });
  const first = registry.mergeIndex('', [line('0.1.0')]);
  const second = registry.mergeIndex(first, [line('0.2.0')]);
  assert.equal(second, `${first}${line('0.2.0')}\n`);
  assert.equal(registry.mergeIndex(second, [line('0.1.0'), line('0.2.0')]), second);
  assert.throws(() => registry.mergeIndex(first, [line('0.1.0', { cksum: 'b' })]), registry.Refusal);
  const yanked = registry.mergeIndex('', [line('0.1.0', { yanked: true })]);
  assert.equal(registry.mergeIndex(yanked, [line('0.1.0')]), yanked, 'a yanked flag is not a content change');
});

function tree(entries) {
  const root = mkdtempSync(join(tmpdir(), 'registry-'));
  for (const [path, text] of entries) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

test('the publish list selects crates in crates/ and tooling/crates/', () => {
  const pkg = (name, publish) => `[package]\nname = "${name}"\nversion = "0.1.0"\npublish = ${publish}\n`;
  const root = tree([
    ['crates/one/Cargo.toml', pkg('aros-one', '["reg"]')],
    ['crates/two/Cargo.toml', pkg('aros-two', 'false')],
    ['crates/three/Cargo.toml', pkg('aros-three', '["other"]')],
    ['crates/four/Cargo.toml', pkg('aros-four', '["x", "reg"]')],
    ['tooling/crates/build/Cargo.toml', pkg('aros-build', '["reg"]')],
  ]);
  assert.deepEqual(registry.publishableCrates(root, 'reg'), ['aros-build', 'aros-four', 'aros-one']);
});

function stageTree(arosDeps) {
  const pkg = (name, publish, deps) => `[package]\nname = "${name}"\nversion = "0.1.0"\npublish = ${publish}\n${deps}`;
  return tree([
    ['crates/aros-sys/Cargo.toml', pkg('aros-sys', '["reg"]', '')],
    ['crates/aros/Cargo.toml', pkg('aros', '["reg"]', arosDeps)],
    ['crates/plain/Cargo.toml', pkg('plain', 'false', '[dependencies]\naros-sys = { version = "=0.1.0", path = "../aros-sys" }\n')],
  ]);
}

test('staging: inline path dependencies gain the registry and nothing else changes', () => {
  const root = stageTree('[dependencies]\naros-sys = { version = "=0.1.0", path = "../aros-sys", default-features = false }\nserde = "1"\n');
  assert.equal(registry.stageManifests(root, 'reg'), 1);
  const deps = parseToml(readFileSync(join(root, 'crates/aros/Cargo.toml'), 'utf8')).dependencies;
  assert.equal(deps['aros-sys'].registry, 'reg');
  assert.equal(deps['aros-sys']['default-features'], false);
  assert.equal(deps.serde, '1');
  assert.ok(!readFileSync(join(root, 'crates/plain/Cargo.toml'), 'utf8').includes('registry'), 'a crate that is not published is left alone');
});

test('counter-probes: forms that cannot be staged are refused, not skipped', () => {
  for (const deps of ['[dependencies.aros-sys]\nversion = "=0.1.0"\npath = "../aros-sys"\n', '[dependencies]\naros-sys = "=0.1.0"\n']) {
    assert.throws(() => registry.stageManifests(stageTree(deps), 'reg'), registry.Refusal);
  }
});

test('signing reproduces the AWS documented GET Object example', () => {
  const { authorization } = registry.sigv4({
    method: 'GET', host: 'examplebucket.s3.amazonaws.com', path: '/test.txt', headers: { range: 'bytes=0-9' },
    payloadHash: sha256(''), amzDate: '20130524T000000Z', region: 'us-east-1', service: 's3',
    accessKey: 'AKIAIOSFODNN7EXAMPLE', secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  });
  assert.ok(authorization.endsWith('Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'), authorization);
});

test('counter-probe: a changed input changes the signature', () => {
  const base = { method: 'GET', host: 'h', path: '/k', payloadHash: sha256(''), amzDate: '20130524T000000Z', region: 'auto', service: 's3', accessKey: 'id', secretKey: 'secret' };
  assert.notEqual(registry.sigv4(base).authorization, registry.sigv4({ ...base, path: '/k2' }).authorization);
});

function build(root, version = '0.2.0', sysExtra = '') {
  const crates = join(root, 'crates-in');
  const stat = join(root, 'static');
  mkdirSync(crates, { recursive: true });
  mkdirSync(stat, { recursive: true });
  writeFileSync(join(stat, 'config.json'), '{"dl":"https://crates.example.org/crates/{crate}/{crate}-{version}.crate"}');
  writeFileSync(join(stat, 'index.html'), '<p>x</p>');
  writeFileSync(join(crates, `aros-sys-${version}.crate`), crateBytes('aros-sys', version, manifest('aros-sys', version, sysExtra)));
  writeFileSync(join(crates, `aros-${version}.crate`), crateBytes('aros', version, manifest('aros', version, `[dependencies]\naros-sys = "=${version}"\n`)));
  const out = join(root, `out-${version}-${sysExtra.length}`);
  mkdirSync(out);
  registry.buildIndex(crates, out, OWN_URL, stat);
  return out;
}

const publicFrom = (bucket, transform = (key, data) => data) => async (host, key) => {
  const data = bucket.store.get(key);
  if (!data) throw new registry.Refusal(`${key}: HTTP 404`);
  return transform(key, data);
};

test('publication is complete, writes crates before indexes, and is idempotent', async () => {
  const root = mkdtempSync(join(tmpdir(), 'registry-'));
  const out = build(root);
  const bucket = new FakeBucket();
  await silently(() => registry.publish(out, bucket, 'crates.example.org', publicFrom(bucket)));
  assert.deepEqual([...bucket.store.keys()].sort(), ['ar/os/aros', 'ar/os/aros-sys', 'config.json', 'crates/aros-sys/aros-sys-0.2.0.crate', 'crates/aros/aros-0.2.0.crate', 'index.html']);
  const lastCrate = Math.max(...bucket.writes.map((k, i) => (k.endsWith('.crate') ? i : -1)));
  const firstIndex = Math.min(...bucket.writes.map((k, i) => (k.startsWith('ar/') ? i : Infinity)));
  assert.ok(lastCrate < firstIndex);
  bucket.writes.length = 0;
  await silently(() => registry.publish(out, bucket, 'crates.example.org', publicFrom(bucket)));
  assert.deepEqual(bucket.writes, [], 'a second publication writes nothing');
});

test('a later version is appended to the index', async () => {
  const root = mkdtempSync(join(tmpdir(), 'registry-'));
  const bucket = new FakeBucket();
  await silently(() => registry.publish(build(root, '0.2.0'), bucket, 'h', publicFrom(bucket)));
  await silently(() => registry.publish(build(root, '0.2.1'), bucket, 'h', publicFrom(bucket)));
  const versions = bucket.store.get('ar/os/aros').toString().trim().split('\n').map((line) => JSON.parse(line).vers);
  assert.deepEqual(versions, ['0.2.0', '0.2.1']);
});

test('counter-probe: a published archive with other bytes is refused', async () => {
  const root = mkdtempSync(join(tmpdir(), 'registry-'));
  const bucket = new FakeBucket();
  await silently(() => registry.publish(build(root), bucket, 'h', publicFrom(bucket)));
  const changed = build(root, '0.2.0', 'description = "changed"\n');
  await assert.rejects(() => silently(() => registry.publish(changed, bucket, 'h', publicFrom(bucket))), registry.Refusal);
});

test('counter-probe: a tampered output file is refused', async () => {
  const out = build(mkdtempSync(join(tmpdir(), 'registry-')));
  writeFileSync(join(out, 'crates/aros/aros-0.2.0.crate'), Buffer.concat([readFileSync(join(out, 'crates/aros/aros-0.2.0.crate')), Buffer.from('x')]));
  const bucket = new FakeBucket();
  await assert.rejects(() => silently(() => registry.publish(out, bucket, 'h', publicFrom(bucket))), registry.Refusal);
});

test('counter-probe: a manifest key cannot escape the output directory', async () => {
  const out = build(mkdtempSync(join(tmpdir(), 'registry-')));
  const path = join(out, 'registry-manifest.json');
  const data = JSON.parse(readFileSync(path, 'utf8'));
  data.files[0].key = '../x';
  writeFileSync(path, JSON.stringify(data));
  await assert.rejects(() => silently(() => registry.publish(out, new FakeBucket(), 'h', async () => Buffer.alloc(0))));
});

test('counter-probe: the public copy must match what was built', async () => {
  const out = build(mkdtempSync(join(tmpdir(), 'registry-')));
  const bucket = new FakeBucket();
  const lying = publicFrom(bucket, (key, data) => (key.endsWith('.crate') ? Buffer.concat([data, Buffer.from('x')]) : data));
  await assert.rejects(() => silently(() => registry.publish(out, bucket, 'h', lying)), registry.Refusal);
});

test('public fetches carry an explicit user agent and retry a refusal', async () => {
  const seen = [];
  const answers = [403, 200];
  const fetcher = async (url, init) => {
    seen.push(init.headers['User-Agent']);
    const status = answers.shift();
    return { status, arrayBuffer: async () => Buffer.from('ok') };
  };
  const data = await registry.fetchPublic('crates.example.org', 'config.json', { fetcher, delay: 0 });
  assert.equal(data.toString(), 'ok');
  assert.deepEqual(seen, [registry.USER_AGENT, registry.USER_AGENT]);
  assert.ok(!seen[0].includes('node'));
  await assert.rejects(() => registry.fetchPublic('h', 'k', { fetcher: async () => ({ status: 404, arrayBuffer: async () => Buffer.alloc(0) }), retries: 2, delay: 0 }), registry.Refusal);
});

test('configuration: complete values pass and every missing or malformed value is refused', () => {
  const good = { R2_ENDPOINT: 'https://acc.r2.cloudflarestorage.com', R2_BUCKET: 'b', R2_ACCESS_KEY_ID: 'id', R2_SECRET_ACCESS_KEY: 'secret', REGISTRY_HOSTNAME: 'crates.example.org' };
  const [, bucket] = registry.environmentBucket(good);
  assert.equal(bucket.bucket, 'b');
  for (const name of Object.keys(good)) assert.throws(() => registry.environmentBucket({ ...good, [name]: '' }), registry.Refusal, name);
  assert.throws(() => registry.environmentBucket({ ...good, R2_ENDPOINT: 'http://insecure.example' }), registry.Refusal);
  assert.throws(() => registry.environmentBucket({ ...good, REGISTRY_HOSTNAME: 'a b' }), registry.Refusal);
});

test('TOML: the constructs of a normalised Cargo manifest', () => {
  const parsed = parseToml(`# comment
[package]
name = "x"   # trailing
description = """
two
lines \\
joined"""
publish = ["a", 'b']
[dependencies.dep]
version = "1"
features = [
    "one",
    "two", # note
]
[target.'cfg(any(unix, windows))'.dependencies]
libc = { version = "0.2", default-features = false }
[[bin]]
name = "one"
[[bin]]
name = "two"
`);
  assert.equal(parsed.package.description, 'two\nlines joined');
  assert.deepEqual(parsed.package.publish, ['a', 'b']);
  assert.deepEqual(parsed.dependencies.dep.features, ['one', 'two']);
  assert.equal(parsed.target['cfg(any(unix, windows))'].dependencies.libc['default-features'], false);
  assert.deepEqual(parsed.bin.map((b) => b.name), ['one', 'two']);
});

test('TOML: counter-probes fail loudly', () => {
  for (const text of ['a = ', 'a = 1\na = 2', '[t]\n[t.x]\nx = 1\n[t]\ny', 'when = 1979-05-27', 'a = "unterminated', 'a = [1, 2', 'a = 1 b = 2']) {
    assert.throws(() => parseToml(text), TomlError, text);
  }
});

test('TOML: every manifest in this repository parses', () => {
  const root = new URL('../../', import.meta.url).pathname;
  const publishable = registry.publishableCrates(root, 'metaneutrons');
  assert.ok(publishable.length >= 11, `found ${publishable.length}`);
});
