// Derives the MUI class hierarchy and the attribute, method and value
// relations from trait implementations in the rustdoc model. The `aros-mui`
// sources only record these as one-line generator comments; the type system
// is the authoritative record.

import { innerKind, keyOf, scalar, shortPath } from './types.mjs';

const DOC_HEADER = /^(MUI[CAMP]_\w+)(?: \(([^;)]*);\s*([^)]*)\))? from ([^\s:]+):(\d+)/;
const unquote = (value) => scalar(value).replace(/^c?"|"$/g, '');

function traitImpls(crate, item) {
  const data = item.inner?.[innerKind(item)];
  const result = new Map();
  for (const implId of data?.impls || []) {
    const implementation = crate.index[keyOf(implId)]?.inner?.impl;
    if (!implementation?.trait || implementation.is_synthetic || implementation.blanket_impl) continue;
    const bucket = result.get(implementation.trait.path) || [];
    bucket.push(implementation);
    result.set(implementation.trait.path, bucket);
  }
  return result;
}

function isaBound(implementation) {
  for (const predicate of implementation.generics?.where_predicates || []) {
    for (const bound of predicate.bound_predicate?.bounds || []) {
      const trait = bound.trait_bound?.trait;
      if (trait?.path !== 'IsA') continue;
      const target = trait.args?.angle_bracketed?.args?.[0]?.type?.resolved_path;
      if (target) return { name: shortPath(target.path), id: target.id };
    }
  }
  return null;
}

const associated = (crate, implementation, name) => {
  for (const id of implementation?.items || []) {
    const member = crate.index[keyOf(id)];
    if (member?.name === name) return member.inner[innerKind(member)];
  }
  return null;
};

export function parseHeaderDoc(docs) {
  const match = DOC_HEADER.exec(scalar(docs));
  if (!match) return null;
  return { native: match[1], type: match[2]?.trim() || null, flags: match[3]?.trim() || null, header: match[4], line: Number(match[5]) };
}

const ABI_SENTENCE = /\n*Available on (ABI-v1|ABI-v11) targets only\.\s*$/;

/** The ABI profile an item's own docs say it is restricted to, or null. */
export function declaredAbi(docs) {
  const match = ABI_SENTENCE.exec(scalar(docs));
  if (!match) return null;
  return match[1] === 'ABI-v1' ? 'abi1' : 'abi11';
}

export function isGeneratedStub(docs) {
  const text = scalar(docs).replace(ABI_SENTENCE, '').trim();
  return DOC_HEADER.test(text) && text.replace(DOC_HEADER, '').replace(/^[;.\s]*(typed unsafe message dispatch)?[.\s]*$/, '') === '';
}

export function buildMuiRelations(registry) {
  const under = (module) => [...registry.entries.values()]
    .filter((entry) => entry.crateName === 'aros_mui' && entry.publicPath[1] === module && entry.publicPath.length === 3);

  const classes = new Map();
  for (const entry of under('classes')) {
    const record = registry.primary(entry);
    const impls = traitImpls(record.crate, record.item);
    const ancestors = (impls.get('IsA') || [])
      .map((implementation) => implementation.trait.args?.angle_bracketed?.args?.[0]?.type?.resolved_path)
      .filter(Boolean)
      .map((target) => shortPath(target.path))
      .filter((name) => name !== entry.name);
    const classId = associated(record.crate, (impls.get('Class') || [])[0], 'ID')?.value;
    classes.set(entry.name, {
      entry, ancestors: new Set(ancestors), classId: classId ? unquote(classId) : null,
      header: parseHeaderDoc(record.item.docs), parent: null, children: [], attributes: [], methods: [],
    });
  }
  for (const info of classes.values()) {
    let best = null;
    for (const name of info.ancestors) {
      const candidate = classes.get(name);
      if (candidate && (!best || candidate.ancestors.size > best.ancestors.size)) best = candidate;
    }
    info.parent = best;
    best?.children.push(info);
  }
  for (const info of classes.values()) info.children.sort((a, b) => a.entry.name.localeCompare(b.entry.name));

  const attributes = new Map();
  for (const entry of under('attributes')) {
    const record = registry.primary(entry);
    const impls = traitImpls(record.crate, record.item);
    const typed = (impls.get('Attribute') || [])[0];
    const raw = (impls.get('RawAttribute') || [])[0];
    const owner = isaBound(typed || raw || { generics: {} });
    const valueType = associated(record.crate, typed, 'Value')?.type;
    const rawType = associated(record.crate, raw, 'C_TYPE')?.value;
    const tag = associated(record.crate, typed || raw, 'ID')?.value;
    const info = {
      entry, owner: owner && classes.get(owner.name) ? classes.get(owner.name) : null,
      ownerName: owner?.name || null,
      valueType, valueId: valueType?.resolved_path?.id ?? null,
      cType: rawType ? unquote(rawType).replace(/^\]\s*/, '') : null,
      tag: tag ? shortPath(tag) : null,
      header: parseHeaderDoc(record.item.docs),
      typed: Boolean(typed),
      build: impls.has('BuildAttribute'), set: impls.has('SetAttribute'), get: impls.has('GetAttribute'),
      rawBuild: impls.has('RawBuildAttribute'), rawSet: impls.has('RawSetAttribute'), rawGet: impls.has('RawGetAttribute'),
      crate: record.crate,
    };
    attributes.set(entry.key, info);
    info.owner?.attributes.push(info);
  }

  const methods = new Map();
  for (const entry of under('methods')) {
    const record = registry.primary(entry);
    const impls = traitImpls(record.crate, record.item);
    const rawMethod = (impls.get('RawMethod') || [])[0];
    const safeMethod = (impls.get('Method') || [])[0];
    const implementation = safeMethod || rawMethod;
    const owner = isaBound(implementation || { generics: {} });
    const message = associated(record.crate, rawMethod, 'Message')?.type;
    const tag = associated(record.crate, implementation, 'ID')?.value;
    const info = {
      entry, owner: owner && classes.get(owner.name) ? classes.get(owner.name) : null,
      ownerName: owner?.name || null, safe: Boolean(safeMethod),
      message: message?.resolved_path ? shortPath(message.resolved_path.path) : null,
      tag: tag ? shortPath(tag) : null, header: parseHeaderDoc(record.item.docs),
    };
    methods.set(entry.key, info);
    info.owner?.methods.push(info);
  }
  const byName = (a, b) => a.entry.name.localeCompare(b.entry.name);
  for (const info of classes.values()) { info.attributes.sort(byName); info.methods.sort(byName); }

  const valueUsers = new Map();
  for (const info of attributes.values()) {
    if (info.valueId === null) continue;
    const target = info.crate.exposed.get(keyOf(info.valueId));
    if (!target) continue;
    const key = target.publicPath.join('::');
    const bucket = valueUsers.get(key) || [];
    bucket.push(info);
    valueUsers.set(key, bucket);
  }
  for (const bucket of valueUsers.values()) bucket.sort(byName);

  return { classes, attributes, methods, valueUsers };
}
