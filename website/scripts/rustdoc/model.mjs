// Loads rustdoc JSON documents, merges the per-ABI builds into one registry of
// public items and resolves intra-doc links across crates.

import { innerKind, keyOf, scalar } from './types.mjs';

const ABI_PRIORITY = ['abi11', 'abi1'];
export const ABI_LABEL = { abi1: 'ABI-v1', abi11: 'ABI-v11' };
export const slug = (name) => scalar(name).toLowerCase();

const isHidden = (item) => (item?.attrs || []).some((attribute) => JSON.stringify(attribute).includes('doc(hidden)'));

export function memberIds(item) {
  const data = item.inner?.[innerKind(item)];
  if (!data) return [];
  if (data.kind?.plain?.fields) return data.kind.plain.fields;
  if (data.kind?.tuple) return data.kind.tuple.filter((id) => id !== null);
  return [];
}

export function inherentImpls(crate, item) {
  const data = item.inner?.[innerKind(item)];
  const result = [];
  for (const implId of data?.impls || []) {
    const implementation = crate.index[keyOf(implId)]?.inner?.impl;
    if (!implementation || implementation.trait || implementation.is_synthetic || implementation.blanket_impl) continue;
    result.push(implementation);
  }
  return result;
}

export function loadCrate(document, abi) {
  if (document.format_version !== 60) {
    throw new Error(`unsupported rustdoc JSON format ${document.format_version}`);
  }
  const index = document.index;
  const root = keyOf(document.root);
  const crateName = index[root].name;
  const exposed = new Map();
  const visited = new Set();
  const crate = {
    abi, document, index, root, crateName, exposed,
    paths: document.paths,
    externals: document.external_crates,
    anchors: new Map(),
    implementors: new Map(),
    kindByPath: new Map(),
  };

  const expose = (id, publicPath, name) => {
    const key = keyOf(id);
    const item = index[key];
    if (!item) return;
    const kind = innerKind(item);
    const existing = exposed.get(key);
    if (!existing || publicPath.length < existing.publicPath.length) {
      exposed.set(key, { id: key, item, kind, publicPath, name: name || item.name });
    }
    if (kind === 'module') walkModule(key, publicPath);
  };

  const walkModule = (id, publicPath) => {
    const visitKey = `${id}:${publicPath.join('::')}`;
    if (visited.has(visitKey)) return;
    visited.add(visitKey);
    for (const childId of index[keyOf(id)]?.inner?.module?.items || []) {
      const child = index[keyOf(childId)];
      if (!child || child.visibility !== 'public' || isHidden(child)) continue;
      const reexport = child.inner?.use;
      if (reexport) {
        if (reexport.id === null || reexport.id === undefined) continue;
        if (reexport.is_glob) walkModule(keyOf(reexport.id), publicPath);
        else expose(reexport.id, [...publicPath, reexport.name], reexport.name);
        continue;
      }
      if (!child.name) continue;
      expose(childId, [...publicPath, child.name], child.name);
    }
  };

  exposed.set(root, { id: root, item: index[root], kind: 'module', publicPath: [crateName], name: crateName });
  walkModule(root, [crateName]);

  for (const entry of exposed.values()) {
    const data = entry.item.inner?.[entry.kind];
    const owned = [
      ...memberIds(entry.item),
      ...(entry.item.inner?.enum?.variants || []),
      ...(entry.item.inner?.trait?.items || []),
    ];
    for (const implementation of inherentImpls(crate, entry.item)) owned.push(...(implementation.items || []));
    for (const memberId of owned) {
      const member = index[keyOf(memberId)];
      if (member?.name && !exposed.has(keyOf(memberId))) crate.anchors.set(keyOf(memberId), { owner: entry.id, name: member.name });
    }
    void data;
  }

  for (const item of Object.values(index)) {
    const implementation = item.inner?.impl;
    if (!implementation?.trait || implementation.trait.id === null || implementation.is_synthetic || implementation.blanket_impl) continue;
    const bucket = crate.implementors.get(keyOf(implementation.trait.id)) || [];
    bucket.push(implementation);
    crate.implementors.set(keyOf(implementation.trait.id), bucket);
  }
  for (const entry of Object.values(document.paths)) crate.kindByPath.set(entry.path.join('::'), entry.kind);
  return crate;
}

export function buildRegistry(crates) {
  const entries = new Map();
  for (const crate of crates) {
    for (const exposed of crate.exposed.values()) {
      const key = exposed.publicPath.join('::');
      let entry = entries.get(key);
      if (!entry) {
        entry = {
          key, crateName: crate.crateName, publicPath: exposed.publicPath, name: exposed.name,
          kind: exposed.kind, abis: new Map(),
        };
        entries.set(key, entry);
      }
      entry.abis.set(crate.abi, { crate, id: exposed.id, item: exposed.item });
    }
  }

  const claimed = new Set(['/reference/']);
  const ordered = [...entries.values()].sort((a, b) =>
    (a.kind === 'module' ? 0 : 1) - (b.kind === 'module' ? 0 : 1) || a.key.localeCompare(b.key));
  for (const entry of ordered) {
    const directory = entry.publicPath.slice(1, entry.kind === 'module' ? undefined : -1).map(slug);
    const leaf = entry.kind === 'module' ? [] : [slug(entry.name)];
    let parts = [slug(entry.crateName), ...directory, ...leaf];
    let route = `/reference/${parts.join('/')}/`;
    if (claimed.has(route)) {
      parts = [...parts.slice(0, -1), `${parts.at(-1)}-${entry.kind}`];
      route = `/reference/${parts.join('/')}/`;
    }
    claimed.add(route);
    entry.route = route;
    entry.file = entry.kind === 'module' ? [...parts, 'index.md'] : [...parts.slice(0, -1), `${parts.at(-1)}.md`];
  }

  const byDefinition = new Map();
  for (const entry of entries.values()) {
    for (const record of entry.abis.values()) {
      const definition = record.crate.paths[record.id];
      if (definition?.path) byDefinition.set(`${record.crate.crateName}|${definition.path.join('::')}`, entry);
    }
  }
  const primary = (entry) => {
    for (const abi of ABI_PRIORITY) if (entry.abis.has(abi)) return { abi, ...entry.abis.get(abi) };
    return null;
  };
  return { entries, byDefinition, primary, publishedCrates: new Set(crates.map((crate) => crate.crateName)) };
}

const STD_KIND = {
  struct: 'struct', enum: 'enum', trait: 'trait', union: 'union', type_alias: 'type',
  function: 'fn', macro: 'macro', constant: 'constant', static: 'static', primitive: 'primitive',
};
const MEMBER_ANCHOR = {
  variant: 'variant', assoc_const: 'associatedconstant', assoc_type: 'associatedtype',
  function: 'method', struct_field: 'structfield',
};

function standardUrl(crate, definition) {
  const [root, ...rest] = definition.path;
  const external = crate.externals[definition.crate_id];
  const base = (external?.html_root_url || 'https://doc.rust-lang.org/stable/').replace(/\/?$/, '/');
  const page = (path, kind) => {
    const [, ...tail] = path;
    const name = tail.at(-1);
    const modules = tail.slice(0, -1).map((segment) => `${segment}/`).join('');
    return `${base}${root}/${modules}${STD_KIND[kind]}.${name}.html`;
  };
  if (STD_KIND[definition.kind] && !/^[A-Z]/.test(rest.at(-2) || '') ) return page(definition.path, definition.kind);
  const ownerPath = definition.path.slice(0, -1);
  const ownerKind = crate.kindByPath.get(ownerPath.join('::'));
  if (!ownerKind || !STD_KIND[ownerKind]) return null;
  const anchor = MEMBER_ANCHOR[definition.kind];
  if (!anchor) return null;
  const prefix = ownerKind === 'trait' && anchor === 'method' ? 'tymethod' : anchor;
  return `${page(ownerPath, ownerKind)}#${prefix}.${definition.path.at(-1)}`;
}

/** Resolves an id from one crate's rustdoc document to a site URL, or null. */
export function routeForId(registry, crate, id) {
  const key = keyOf(id);
  const local = crate.exposed.get(key);
  if (local) return registry.entries.get(local.publicPath.join('::'))?.route ?? null;
  const anchor = crate.anchors.get(key);
  if (anchor) {
    const owner = crate.exposed.get(anchor.owner);
    const entry = registry.entries.get(owner.publicPath.join('::'));
    return entry ? `${entry.route}#${slug(anchor.name)}` : null;
  }
  const definition = crate.paths[key];
  if (!definition || definition.crate_id === 0) return null;
  const externalName = crate.externals[definition.crate_id]?.name;
  if (registry.publishedCrates.has(externalName)) {
    const exact = registry.byDefinition.get(`${externalName}|${definition.path.join('::')}`);
    if (exact) return exact.route;
    const owner = registry.byDefinition.get(`${externalName}|${definition.path.slice(0, -1).join('::')}`);
    return owner ? `${owner.route}#${slug(definition.path.at(-1))}` : null;
  }
  if (['core', 'alloc', 'std'].includes(externalName)) return standardUrl(crate, definition);
  return null;
}

/** Link resolver over an item's `links` table for the docs processor. */
export function itemResolver(registry, crate, item) {
  const links = item?.links || {};
  return {
    has: (key) => Object.hasOwn(links, key),
    url: (key) => routeForId(registry, crate, links[key]),
  };
}
