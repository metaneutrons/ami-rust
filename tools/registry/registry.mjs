#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// A static Cargo sparse registry for the ami-rust crates.
//
// The registry is a set of files in an object bucket behind a hostname:
//
//   config.json                       the registry configuration (download URL)
//   index.html                        a human-readable landing page
//   <index path>                      one JSON line per published version
//   crates/<name>/<name>-<ver>.crate  the package archives
//
// Published files are append-only. A crate archive is written once and never
// changes; an index file only ever gains lines. A version that is already
// published must come out byte for byte the same, or publication stops.
//
// Subcommands:
//   crates     list the crates whose manifests name the registry in `publish`
//   stage      in a throwaway copy, point dependencies between those crates at the registry
//   index      turn packaged .crate files into index lines and an upload manifest
//   preflight  check the configuration and the bucket without changing anything
//   publish    upload what `index` produced, append-only, then verify it publicly
//   verify     compare the public registry with what `index` produced
//
// Only Node's own modules are used.

import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { TomlError, parseToml } from './toml.mjs';

export const CRATES_IO_INDEX = 'https://github.com/rust-lang/crates.io-index';
export const USER_AGENT = 'ami-rust-registry/1';
export const SCHEMA = 'ami-rust-registry-manifest-v1';
const NAME = /^[A-Za-z][A-Za-z0-9_-]*$/;
const VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
const MAX_MANIFEST_BYTES = 1 << 20;
const GROUPS = ['crates', 'tooling/crates'];

/** A condition that must stop publication. */
export class Refusal extends Error {}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

/** JSON with sorted object keys and no whitespace, as the index lines are written. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// ---------------------------------------------------------------------------
// Which crates

function manifestsIn(source) {
  const found = [];
  for (const group of GROUPS) {
    const base = join(source, group);
    let entries;
    try {
      entries = readdirSync(base).sort();
    } catch {
      continue;
    }
    for (const entry of entries) {
      const path = join(base, entry, 'Cargo.toml');
      try {
        if (statSync(path).isFile()) found.push(path);
      } catch {
        // not a crate directory
      }
    }
  }
  return found;
}

export function publishableCrates(source, registry) {
  const names = [];
  for (const path of manifestsIn(source)) {
    const pkg = parseToml(readFileSync(path, 'utf8')).package ?? {};
    if (Array.isArray(pkg.publish) && pkg.publish.includes(registry)) names.push(pkg.name);
  }
  return names.sort();
}

/**
 * Point the dependencies between publishable crates at the registry.
 *
 * The repository's manifests name those dependencies by path and version only,
 * which Cargo reads as crates.io. For packaging, in a throwaway copy, each such
 * dependency also gets `registry = "<name>"`, so that Cargo resolves it against
 * the packages it is producing together. The repository is not changed.
 */
export function stageManifests(source, registry) {
  const names = new Set(publishableCrates(source, registry));
  let changed = 0;
  for (const path of manifestsIn(source)) {
    const text = readFileSync(path, 'utf8');
    if (!names.has(parseToml(text).package.name)) continue;
    const lines = text.split('\n');
    lines.forEach((line, number) => {
      const section = /^\[(?:[^\]]*\.)?(?:dependencies|build-dependencies)\.([A-Za-z0-9_-]+)\]\s*$/.exec(line);
      if (section && names.has(section[1])) {
        throw new Refusal(`${path}: the dependency on ${section[1]} must be written as an inline table`);
      }
      const inline = /^([A-Za-z0-9_-]+)\s*=\s*\{(.*)\}\s*$/.exec(line);
      if (!inline || !names.has(inline[1]) || !inline[2].includes('path') || inline[2].includes('registry')) return;
      lines[number] = `${inline[1]} = {${inline[2].trimEnd()}, registry = "${registry}" }`;
      changed++;
    });
    const staged = lines.join('\n');
    if (staged !== text) writeFileSync(path, staged);
    // Every dependency on a publishable crate must now name the registry.
    const manifest = parseToml(staged);
    for (const table of ['dependencies', 'build-dependencies']) {
      for (const [dependency, spec] of Object.entries(manifest[table] ?? {})) {
        if (names.has(dependency) && !(typeof spec === 'object' && spec.registry === registry)) {
          throw new Refusal(`${path}: the dependency on ${dependency} could not be pointed at the registry`);
        }
      }
    }
  }
  return changed;
}

// ---------------------------------------------------------------------------
// Index entries

/** The path of a crate's index file, as the sparse protocol lays it out. */
export function indexPath(name) {
  if (!NAME.test(name)) throw new Refusal(`malformed crate name: ${JSON.stringify(name)}`);
  const lower = name.toLowerCase();
  if (lower.length === 1) return `1/${lower}`;
  if (lower.length === 2) return `2/${lower}`;
  if (lower.length === 3) return `3/${lower[0]}/${lower}`;
  return `${lower.slice(0, 2)}/${lower.slice(2, 4)}/${lower}`;
}

const octal = (field) => parseInt(field.toString('latin1').replace(/\0.*$/s, '').trim() || '0', 8);
const cString = (field) => field.toString('utf8').replace(/\0.*$/s, '');

/** The members of a tar archive: name, type flag and data. Pax and GNU long names are honoured. */
export function* tarMembers(tar) {
  let offset = 0;
  let longName = null;
  let pax = {};
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) return;
    const size = octal(header.subarray(124, 136));
    const flag = String.fromCharCode(header[156] || 0x30);
    let name = cString(header.subarray(0, 100));
    if (header.subarray(257, 262).toString('latin1') === 'ustar') {
      const prefix = cString(header.subarray(345, 500));
      if (prefix) name = `${prefix}/${name}`;
    }
    const start = offset + 512;
    const data = tar.subarray(start, start + size);
    offset = start + Math.ceil(size / 512) * 512;
    if (flag === 'L') {
      longName = cString(data);
    } else if (flag === 'x') {
      pax = {};
      let rest = data.toString('utf8');
      while (rest) {
        const space = rest.indexOf(' ');
        const length = Number(rest.slice(0, space));
        const record = rest.slice(space + 1, length - 1);
        const equals = record.indexOf('=');
        pax[record.slice(0, equals)] = record.slice(equals + 1);
        rest = rest.slice(length);
      }
    } else if (flag === 'g' || flag === 'K') {
      // global pax data and GNU long link names do not matter here
    } else {
      yield { name: pax.path ?? longName ?? name, flag, data };
      longName = null;
      pax = {};
    }
  }
}

/** The normalised Cargo.toml inside a .crate, and nothing else of it. */
export function readManifest(archive, name, version) {
  const member = `${name}-${version}/Cargo.toml`;
  const tar = gunzipSync(archive, { maxOutputLength: 1 << 30 });
  for (const entry of tarMembers(tar)) {
    if (entry.name !== member) continue;
    if (!(entry.flag === '0') || entry.data.length > MAX_MANIFEST_BYTES) {
      throw new Refusal(`${member} is not a regular file of reasonable size`);
    }
    return parseToml(entry.data.toString('utf8'));
  }
  throw new Refusal(`${name}-${version}.crate has no ${member}`);
}

export function splitFeatures(features) {
  const plain = {};
  const extended = {};
  for (const [name, values] of Object.entries(features)) {
    const usesNew = values.some((value) => value.startsWith('dep:') || value.includes('?/'));
    (usesNew ? extended : plain)[name] = values;
  }
  return [plain, extended];
}

const bare = (url) => url.replace(/^sparse\+/, '').replace(/\/+$/, '');

export function dependencyEntries(manifest, ownNames, ownIndexUrl) {
  const entries = [];
  const one = (name, spec, kind, target) => {
    const dependency = typeof spec === 'string' ? { version: spec } : spec;
    const pkg = dependency.package ?? null;
    const realName = pkg ?? name;
    const registryIndex = dependency['registry-index'];
    let registry;
    if (ownNames.has(realName) || (registryIndex !== undefined && bare(registryIndex) === bare(ownIndexUrl))) {
      registry = null;
    } else if (registryIndex !== undefined) {
      registry = registryIndex;
    } else {
      registry = CRATES_IO_INDEX;
    }
    entries.push({
      name,
      req: dependency.version ?? '*',
      features: [...(dependency.features ?? [])].sort(),
      optional: Boolean(dependency.optional ?? false),
      default_features: Boolean(dependency['default-features'] ?? dependency.default_features ?? true),
      target,
      kind,
      registry,
      package: pkg,
    });
  };
  for (const [table, kind] of [['dependencies', 'normal'], ['build-dependencies', 'build']]) {
    for (const [name, spec] of Object.entries(manifest[table] ?? {})) one(name, spec, kind, null);
  }
  for (const [target, tables] of Object.entries(manifest.target ?? {})) {
    for (const [table, kind] of [['dependencies', 'normal'], ['build-dependencies', 'build']]) {
      for (const [name, spec] of Object.entries(tables[table] ?? {})) one(name, spec, kind, target);
    }
  }
  const key = (entry) => `${entry.name}\0${entry.kind}\0${entry.target ?? ''}`;
  entries.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
  return entries;
}

export function indexLine(archive, name, version, ownNames, ownIndexUrl) {
  const manifest = readManifest(archive, name, version);
  const pkg = manifest.package;
  if (pkg.name !== name || pkg.version !== version) {
    throw new Refusal(`${name}-${version}.crate carries a manifest of ${pkg.name} ${pkg.version}`);
  }
  const [plain, extended] = splitFeatures(manifest.features ?? {});
  const entry = {
    name,
    vers: version,
    deps: dependencyEntries(manifest, ownNames, ownIndexUrl),
    cksum: sha256(archive),
    features: plain,
    yanked: false,
    links: pkg.links ?? null,
  };
  if (Object.keys(extended).length > 0) {
    entry.features2 = extended;
    entry.v = 2;
  } else {
    entry.v = 1;
  }
  if (pkg['rust-version'] !== undefined) entry.rust_version = pkg['rust-version'];
  return canonicalJson(entry);
}

export function splitArchiveName(filename) {
  const match = /^(.+?)-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\.crate$/.exec(filename);
  if (!match) throw new Refusal(`not a crate archive name: ${JSON.stringify(filename)}`);
  const [, name, version] = match;
  if (!NAME.test(name) || !VERSION.test(version)) throw new Refusal(`malformed crate archive name: ${JSON.stringify(filename)}`);
  return [name, version];
}

/** Append new versions to an index file text; refuse to change a published one. */
export function mergeIndex(existing, newLines) {
  const lines = existing.split('\n').filter(Boolean);
  const seen = new Map();
  for (const line of lines) seen.set(JSON.parse(line).vers, line);
  for (const line of newLines) {
    const version = JSON.parse(line).vers;
    if (seen.has(version)) {
      const old = JSON.parse(seen.get(version));
      const added = JSON.parse(line);
      // Only the yanked flag may differ, and publication never sets it.
      old.yanked = added.yanked = false;
      if (canonicalJson(old) !== canonicalJson(added)) {
        throw new Refusal(`version ${version} is already published with different content`);
      }
      continue;
    }
    seen.set(version, line);
    lines.push(line);
  }
  return lines.map((line) => `${line}\n`).join('');
}

export function buildIndex(cratesDir, outDir, indexUrl, staticDir) {
  const archives = readdirSync(cratesDir).filter((file) => file.endsWith('.crate')).sort();
  if (archives.length === 0) throw new Refusal('no .crate archives to index');
  const parsed = archives.map((file) => [file, ...splitArchiveName(file)]);
  const ownNames = new Set(parsed.map(([, name]) => name));
  const files = [];
  const add = (key, data, contentType, cacheControl, kind) => {
    const target = join(outDir, key);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, data);
    files.push({ key, kind, bytes: data.length, sha256: sha256(data), content_type: contentType, cache_control: cacheControl });
  };
  const perCrate = new Map();
  for (const [file, name, version] of parsed) {
    const data = readFileSync(join(cratesDir, file));
    add(`crates/${name}/${file}`, data, 'application/gzip', 'public, max-age=31536000, immutable', 'crate');
    if (!perCrate.has(name)) perCrate.set(name, []);
    perCrate.get(name).push(indexLine(data, name, version, ownNames, indexUrl));
  }
  for (const name of [...perCrate.keys()].sort()) {
    const text = Buffer.from(perCrate.get(name).map((line) => `${line}\n`).join(''));
    add(indexPath(name), text, 'text/plain; charset=utf-8', 'public, max-age=60', 'index');
  }
  for (const [key, contentType] of [['config.json', 'application/json'], ['index.html', 'text/html; charset=utf-8']]) {
    add(key, readFileSync(join(staticDir, key)), contentType, 'public, max-age=300', 'static');
  }
  files.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const manifest = { schema: SCHEMA, index_url: indexUrl, files };
  writeFileSync(join(outDir, 'registry-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

// ---------------------------------------------------------------------------
// S3 access (Signature Version 4), for R2

const hmac = (key, message) => createHmac('sha256', key).update(message).digest();
const encodeSegment = (segment) =>
  encodeURIComponent(segment).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const encodePath = (path) => path.split('/').map(encodeSegment).join('/');

/**
 * The Authorization header of an AWS Signature Version 4 request. `headers` are
 * the extra headers to sign (lower-case names); host and the x-amz date and
 * content hash headers are added here.
 */
export function sigv4({ method, host, path, query = {}, headers = {}, payloadHash, amzDate, region, service, accessKey, secretKey }) {
  const signed = { ...headers, host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  const names = Object.keys(signed).sort();
  const canonicalHeaders = names.map((name) => `${name}:${String(signed[name]).trim().replace(/\s+/g, ' ')}\n`).join('');
  const canonicalQuery = Object.keys(query).sort().map((k) => `${encodeSegment(k)}=${encodeSegment(query[k])}`).join('&');
  const canonical = [method, encodePath(path), canonicalQuery, canonicalHeaders, names.join(';'), payloadHash].join('\n');
  const date = amzDate.slice(0, 8);
  const scope = `${date}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const key = hmac(hmac(hmac(hmac(`AWS4${secretKey}`, date), region), service), 'aws4_request');
  const signature = createHmac('sha256', key).update(toSign).digest('hex');
  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`,
    signed,
  };
}

/** Object access to one bucket on an S3-compatible endpoint. */
export class Bucket {
  constructor(endpoint, bucket, accessKey, secretKey, { region = 'auto', fetcher = fetch } = {}) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || !url.hostname) throw new Refusal('the endpoint must be an https URL');
    this.host = url.host;
    this.bucket = bucket;
    this.accessKey = accessKey;
    this.secretKey = secretKey;
    this.region = region;
    this.fetcher = fetcher;
  }

  async request(method, key, data = Buffer.alloc(0), extra = {}, retries = 1) {
    const path = `/${this.bucket}${key ? `/${key}` : ''}`;
    const payloadHash = sha256(data);
    let last;
    for (let attempt = 0; attempt < retries; attempt++) {
      const amzDate = new Date().toISOString().replace(/[-:]|\.\d{3}/g, '');
      const { authorization, signed } = sigv4({
        method, host: this.host, path, payloadHash, amzDate, region: this.region, service: 's3',
        accessKey: this.accessKey, secretKey: this.secretKey,
      });
      const headers = { ...signed, Authorization: authorization, 'User-Agent': USER_AGENT, ...extra };
      delete headers.host;
      const response = await this.fetcher(`https://${this.host}${encodePath(path)}`, {
        method,
        headers,
        body: method === 'PUT' || method === 'POST' ? data : undefined,
      });
      const body = Buffer.from(await response.arrayBuffer());
      if ((response.status === 401 || response.status === 403) && attempt + 1 < retries) {
        last = { status: response.status, body };
        await sleep(6000);
        continue;
      }
      return { status: response.status, body };
    }
    return last;
  }

  async get(key) {
    const { status, body } = await this.request('GET', key);
    if (status === 404) return null;
    if (status !== 200) throw new Refusal(`GET ${key}: HTTP ${status}`);
    return body;
  }

  async put(key, data, contentType, cacheControl) {
    const { status } = await this.request('PUT', key, data, { 'Content-Type': contentType, 'Cache-Control': cacheControl });
    if (status !== 200 && status !== 201) throw new Refusal(`PUT ${key}: HTTP ${status}`);
  }

  async headBucket(retries = 8) {
    const { status } = await this.request('HEAD', '', Buffer.alloc(0), {}, retries);
    return status === 200;
  }
}

// ---------------------------------------------------------------------------
// Publication

export function loadManifest(outDir) {
  const manifest = JSON.parse(readFileSync(join(outDir, 'registry-manifest.json'), 'utf8'));
  if (manifest.schema !== SCHEMA) throw new Refusal('unknown registry manifest schema');
  return manifest;
}

export function fileBytes(outDir, entry) {
  const path = join(outDir, entry.key);
  const inside = relative(realpathSync(outDir), realpathSync(path));
  if (inside.startsWith('..') || inside.startsWith(sep)) {
    throw new Refusal(`manifest key escapes the output directory: ${JSON.stringify(entry.key)}`);
  }
  const data = readFileSync(path);
  if (sha256(data) !== entry.sha256 || data.length !== entry.bytes) throw new Refusal(`${entry.key} differs from its manifest entry`);
  return data;
}

export function environmentBucket(environment = process.env) {
  const values = {};
  for (const name of ['R2_ENDPOINT', 'R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'REGISTRY_HOSTNAME']) {
    const value = environment[name] ?? '';
    if (!value || value !== value.trim() || /\s/.test(value)) throw new Refusal(`${name} is missing or malformed`);
    values[name] = value;
  }
  if (!/^[a-z0-9][a-z0-9.-]*$/.test(values.REGISTRY_HOSTNAME)) throw new Refusal('REGISTRY_HOSTNAME is malformed');
  return [values, new Bucket(values.R2_ENDPOINT, values.R2_BUCKET, values.R2_ACCESS_KEY_ID, values.R2_SECRET_ACCESS_KEY)];
}

export async function fetchPublic(hostname, key, { retries = 10, fetcher = fetch, delay = 5000 } = {}) {
  const url = `https://${hostname}/${encodePath(key)}`;
  let last;
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      // Cloudflare refuses some default client identities with HTTP 403.
      const response = await fetcher(url, { headers: { 'User-Agent': USER_AGENT } });
      if (response.status === 200) return Buffer.from(await response.arrayBuffer());
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = String(error.cause?.message ?? error.message);
    }
    if (attempt + 1 < retries) await sleep(delay);
  }
  throw new Refusal(`${url}: ${last}`);
}

export async function verifyPublic(outDir, manifest, hostname, fetchOne = fetchPublic) {
  for (const entry of manifest.files) {
    const expected = fileBytes(outDir, entry);
    const actual = await fetchOne(hostname, entry.key);
    if (entry.kind === 'index') {
      // The public file may hold other versions too; it must carry ours.
      const present = new Set(actual.toString().split('\n'));
      if (!expected.toString().split('\n').filter(Boolean).every((line) => present.has(line))) {
        throw new Refusal(`public ${entry.key} does not carry the published lines`);
      }
    } else if (!actual.equals(expected)) {
      throw new Refusal(`public ${entry.key} differs from what was built`);
    }
    console.log(`verified ${entry.key}`);
  }
}

const ORDER = { crate: 0, index: 1, static: 2 };
const lines = (data) => data.toString().split('\n').filter(Boolean);

export async function publish(outDir, bucket, hostname, fetchOne = fetchPublic) {
  const manifest = loadManifest(outDir);
  const ordered = [...manifest.files].sort((a, b) => ORDER[a.kind] - ORDER[b.kind]);
  for (const entry of ordered) {
    const data = fileBytes(outDir, entry);
    const existing = await bucket.get(entry.key);
    if (entry.kind === 'crate') {
      if (existing !== null && !existing.equals(data)) throw new Refusal(`${entry.key} is already published with different bytes`);
      if (existing === null) {
        await bucket.put(entry.key, data, entry.content_type, entry.cache_control);
        console.log(`uploaded ${entry.key}`);
      }
    } else if (entry.kind === 'index') {
      const merged = Buffer.from(mergeIndex((existing ?? Buffer.alloc(0)).toString(), lines(data)));
      if (existing === null || !existing.equals(merged)) {
        await bucket.put(entry.key, merged, entry.content_type, entry.cache_control);
        console.log(`updated ${entry.key}`);
      }
    } else if (existing === null || !existing.equals(data)) {
      await bucket.put(entry.key, data, entry.content_type, entry.cache_control);
      console.log(`updated ${entry.key}`);
    }
  }
  await verifyPublic(outDir, manifest, hostname, fetchOne);
}

export async function preflight(outDir, environment = process.env, fetchOne = fetchPublic) {
  const [values, bucket] = environmentBucket(environment);
  const manifest = loadManifest(outDir);
  for (const entry of manifest.files) fileBytes(outDir, entry);
  if (!(await bucket.headBucket())) throw new Refusal('the bucket is not reachable with the configured credentials');
  // Everything that exists must be consistent with what would be written.
  for (const entry of manifest.files) {
    const existing = await bucket.get(entry.key);
    const data = fileBytes(outDir, entry);
    if (entry.kind === 'crate' && existing !== null && !existing.equals(data)) {
      throw new Refusal(`${entry.key} is already published with different bytes`);
    }
    if (entry.kind === 'index') mergeIndex((existing ?? Buffer.alloc(0)).toString(), lines(data));
  }
  const config = JSON.parse((await fetchOne(values.REGISTRY_HOSTNAME, 'config.json')).toString());
  if (String(config.dl ?? '').split('/')[2] !== values.REGISTRY_HOSTNAME) {
    throw new Refusal('config.json does not point at the registry hostname');
  }
  console.log('preflight ok');
}

// ---------------------------------------------------------------------------

function options(argv, required) {
  const values = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i];
    if (!name.startsWith('--') || i + 1 >= argv.length) throw new Refusal(`unexpected argument ${name}`);
    values[name.slice(2)] = argv[i + 1];
  }
  for (const name of required) if (!values[name]) throw new Refusal(`missing --${name}`);
  return values;
}

export async function main(argv) {
  const [command, ...rest] = argv;
  try {
    if (command === 'crates') {
      const o = options(rest, ['source', 'registry']);
      console.log(publishableCrates(o.source, o.registry).join('\n'));
    } else if (command === 'stage') {
      const o = options(rest, ['source', 'registry']);
      console.log(`pointed ${stageManifests(o.source, o.registry)} dependencies at the registry`);
    } else if (command === 'index') {
      const o = options(rest, ['crates', 'out', 'index-url', 'static']);
      try {
        if (readdirSync(o.out).length > 0) throw new Refusal('the output directory must be empty');
      } catch (error) {
        if (error instanceof Refusal || error.code !== 'ENOENT') throw error;
      }
      mkdirSync(o.out, { recursive: true });
      const manifest = buildIndex(o.crates, o.out, o['index-url'], o.static);
      console.log(`indexed ${manifest.files.filter((f) => f.kind === 'crate').length} crates`);
    } else if (command === 'preflight') {
      await preflight(options(rest, ['out']).out);
    } else if (command === 'publish') {
      const o = options(rest, ['out']);
      const [values, bucket] = environmentBucket();
      await publish(o.out, bucket, values.REGISTRY_HOSTNAME);
    } else if (command === 'verify') {
      const o = options(rest, ['out']);
      const hostname = process.env.REGISTRY_HOSTNAME ?? '';
      if (!hostname) throw new Refusal('REGISTRY_HOSTNAME is missing');
      await verifyPublic(o.out, loadManifest(o.out), hostname);
    } else {
      throw new Refusal('usage: registry.mjs crates|stage|index|preflight|publish|verify ...');
    }
  } catch (error) {
    if (!(error instanceof Refusal) && !(error instanceof TomlError)) throw error;
    console.error(`registry: ${error.message}`);
    return 1;
  }
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
