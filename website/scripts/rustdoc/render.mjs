// Renders the merged registry as Starlight Markdown pages.

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { firstParagraph, plainText, processDocs, tableCell } from './docs.mjs';
import { ABI_LABEL, inherentImpls, itemResolver, memberIds, routeForId, slug } from './model.mjs';
import { declaredAbi, isGeneratedStub } from './relations.mjs';
import { createRenderer, innerKind, keyOf, scalar } from './types.mjs';

const KIND_LABEL = { function: 'fn', type_alias: 'type', constant: 'const', macro: 'macro' };
const ABI_ORDER = ['abi1', 'abi11'];
const MAX_LISTED_IMPLEMENTORS = 80;
const NO_TRAIT_LIST = new Set(['classes', 'attributes', 'methods']);

const frontmatter = (title, description) =>
  `---\ntitle: ${JSON.stringify(plainText(title))}\ndescription: ${JSON.stringify(plainText(description) || plainText(title))}\neditUrl: false\n---\n`;

const code = (text, language = 'rust') => `\`\`\`${language}\n${text}\n\`\`\``;

export function createPageWriter(options) {
  const { registry, relations, outputRoot, repository, revision } = options;
  const renderer = createRenderer();
  const written = [];

  const record = (entry) => registry.primary(entry);
  const abisOf = (entry) => ABI_ORDER.filter((abi) => entry.abis.has(abi));
  const allAbis = new Set(ABI_ORDER.filter((abi) => [...registry.entries.values()].some((entry) => entry.abis.has(abi))));
  const abiNote = (abis, noun = 'item') => {
    if (abis.length === allAbis.size) return '';
    const label = abis.map((abi) => ABI_LABEL[abi]).join(' and ');
    return `:::note[Availability]\nThis ${noun} is declared only for ${label} targets. It is not part of the other profile's public MUI headers, so code that uses it does not compile for the other target.\n:::\n\n`;
  };
  const abiSuffix = (entry) => (abisOf(entry).length === allAbis.size ? '' : ` *(${abisOf(entry).map((abi) => ABI_LABEL[abi]).join(', ')} only)*`);

  // The crate generator states ABI restrictions in each item's docs; the two
  // rustdoc builds show what is really declared. They must agree.
  const declarationErrors = [];
  const checkDeclaration = (label, present, docs, universe) => {
    const declared = declaredAbi(docs);
    const actual = present.size === universe.length || present.size === allAbis.size ? null : [...present][0];
    if (declared !== actual) {
      declarationErrors.push(`${label}: docs say ${declared ?? 'both ABIs'} but the builds declare it for ${actual ?? 'both ABIs'}`);
    }
  };

  const resolverFor = (rec) => itemResolver(registry, rec.crate, rec.item);
  const docsOf = (rec, shift = 1) => processDocs(rec.item.docs, resolverFor(rec), { shift });
  const memberDocs = (crate, item) => processDocs(item.docs, itemResolver(registry, crate, item), { shift: 3 });
  const linkTo = (entry, label = entry.name) => `[\`${label}\`](${entry.route})`;

  const sourceLine = (item) => {
    const span = item.span;
    if (!span?.filename) return '';
    const lines = span.begin[0] === span.end[0] ? `L${span.begin[0]}` : `L${span.begin[0]}-L${span.end[0]}`;
    return `[${span.filename}:${span.begin[0]}](${repository}/blob/${revision}/${span.filename}#${lines})`;
  };

  const breadcrumb = (entry) => {
    const trail = [`[Rust API](/reference/)`];
    for (let length = 1; length < entry.publicPath.length; length += 1) {
      const prefix = registry.entries.get(entry.publicPath.slice(0, length).join('::'));
      if (prefix) trail.push(`[${entry.publicPath[length - 1]}](${prefix.route})`);
    }
    return `${trail.join(' › ')}\n\n`;
  };

  const writePage = async (fileParts, contents) => {
    const destination = path.join(outputRoot, ...fileParts);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, contents.endsWith('\n') ? contents : `${contents}\n`, 'utf8');
    written.push(destination);
  };

  const accessText = (info) => {
    const parts = [];
    if (info.build) parts.push('construct');
    if (info.set) parts.push('set');
    if (info.get) parts.push('get');
    for (const [typed, raw, label] of [[info.build, info.rawBuild, 'construct'], [info.set, info.rawSet, 'set'], [info.get, info.rawGet, 'get']]) {
      if (!typed && raw) parts.push(`${label} (unsafe)`);
    }
    return parts.length ? parts.join(' · ') : 'none';
  };
  const valueText = (info) => (info.valueType ? renderer.type(info.valueType) : info.cType ? `raw ${info.cType}` : 'raw');
  const valueLink = (info) => {
    if (!info.valueType) return info.cType ? `\`${info.cType}\` (raw)` : '—';
    const url = info.valueId === null ? null : routeForId(registry, info.crate, info.valueId);
    const text = `\`${valueText(info)}\``;
    return url ? `[${text}](${url})` : text;
  };

  const generatedSummary = (entry) => {
    const module = entry.publicPath[1];
    if (entry.publicPath.length !== 3) return null;
    if (module === 'classes') {
      const info = relations.classes.get(entry.name);
      return info ? `MUI class ${info.header?.native ?? entry.name}${info.parent ? `, subclass of ${info.parent.entry.name}` : ', the root class'}.` : null;
    }
    if (module === 'attributes') {
      const info = relations.attributes.get(entry.key);
      return info ? `${info.tag ?? entry.name}: ${valueText(info)} attribute of ${info.ownerName ?? 'a MUI class'} (${accessText(info)}).` : null;
    }
    if (module === 'methods') {
      const info = relations.methods.get(entry.key);
      return info ? `${info.tag ?? entry.name}: method of ${info.ownerName ?? 'a MUI class'}${info.safe ? '' : ', raw dispatch (unsafe)'}.` : null;
    }
    return null;
  };

  const summaryOf = (entry) => {
    const rec = record(entry);
    if (isGeneratedStub(rec.item.docs)) return generatedSummary(entry) ?? '';
    return firstParagraph(docsOf(rec));
  };
  const plainSummaryOf = (entry) => plainText(summaryOf(entry));

  const titleOf = (entry) => {
    if (entry.publicPath.length === 3) {
      if (entry.publicPath[1] === 'classes') return `MUI class ${entry.name}`;
      if (entry.publicPath[1] === 'attributes') return `MUI attribute ${entry.name}`;
      if (entry.publicPath[1] === 'methods') return `MUI method ${entry.name}`;
    }
    if (entry.kind === 'module' && entry.publicPath.length === 1) return `Crate ${entry.name}`;
    return `${KIND_LABEL[entry.kind] ?? entry.kind} ${entry.publicPath.join('::')}`;
  };

  const childrenOf = (entry) => [...registry.entries.values()]
    .filter((child) => child.publicPath.length === entry.publicPath.length + 1
      && child.publicPath.slice(0, entry.publicPath.length).join('::') === entry.key)
    .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));

  const itemTable = (entries) => {
    const rows = entries.map((entry) =>
      `| ${linkTo(entry)} | ${KIND_LABEL[entry.kind] ?? entry.kind} | ${tableCell(`${summaryOf(entry)}${abiSuffix(entry)}`)} |`);
    return `| Item | Kind | Summary |\n| --- | --- | --- |\n${rows.join('\n')}`;
  };

  /* ---------- members, merged across ABI profiles ---------- */

  const mergeMembers = (entry, collect) => {
    const merged = new Map();
    for (const abi of ['abi11', 'abi1']) {
      const rec = entry.abis.get(abi);
      if (!rec) continue;
      for (const member of collect(rec)) {
        const identity = `${member.kind}:${member.item.name ?? member.index}`;
        const existing = merged.get(identity);
        if (existing) existing.abis.add(abi);
        else merged.set(identity, { ...member, abis: new Set([abi]), crate: rec.crate });
      }
    }
    const members = [...merged.values()];
    for (const member of members) checkDeclaration(`${entry.key}::${member.item.name ?? member.index}`, member.abis, member.item.docs, abisOf(entry));
    return members;
  };

  const genericForm = (item) => {
    const data = item.inner[innerKind(item)];
    const names = (data?.generics?.params || []).filter((entry) => !entry.kind?.type?.is_synthetic).map((entry) => entry.name);
    return `${item.name}${names.length ? `<${names.join(', ')}>` : ''}`;
  };
  const normalised = (text, names) => names.reduce((value, name) => value.split(name).join('_'), text);

  const implContext = (rec, implementation) => {
    const names = (implementation.generics?.params || []).map((entry) => entry.name);
    const target = renderer.type(implementation.for);
    const own = genericForm(rec.item);
    const { clauses } = renderer.generics(implementation.generics);
    const ownNames = (rec.item.inner[innerKind(rec.item)]?.generics?.params || []).map((entry) => entry.name);
    const sameShape = normalised(target, names) === normalised(own, ownNames) && clauses.length === 0;
    if (sameShape) return '';
    const where = clauses.length ? ` where ${clauses.join(', ')}` : '';
    return `Defined for \`${target}\`${where}.`;
  };

  const callableMembers = (entry) => mergeMembers(entry, (rec) => {
    const members = [];
    for (const implementation of inherentImpls(rec.crate, rec.item)) {
      const context = implContext(rec, implementation);
      for (const id of implementation.items || []) {
        const item = rec.crate.index[keyOf(id)];
        if (item?.visibility === 'public' && ['function', 'assoc_const'].includes(innerKind(item))) {
          members.push({ kind: innerKind(item), item, context });
        }
      }
    }
    return members;
  });

  const memberBlock = (entry, member, { inTrait = false } = {}) => {
    const availability = member.abis.size === abisOf(entry).length ? '' : `*Available on ${[...member.abis].sort().map((abi) => ABI_LABEL[abi]).join(' and ')} only.*\n\n`;
    const context = member.context ? `${member.context}\n\n` : '';
    const signature = renderer.associatedSignature(member.item, { inTrait });
    const body = memberDocs(member.crate, member.item);
    return `### \`${member.item.name}\`\n\n${availability}${code(signature)}\n\n${context}${body ? `${body}\n\n` : ''}`;
  };

  /* ---------- sections for ordinary items ---------- */

  const fieldsSection = (entry) => {
    const fields = mergeMembers(entry, (rec) => memberIds(rec.item)
      .map((id, index) => ({ kind: 'field', index, item: rec.crate.index[keyOf(id)] }))
      .filter((member) => member.item));
    if (!fields.length) return '';
    const blocks = fields.map((field) => {
      const title = field.item.name ?? String(field.index);
      const body = memberDocs(field.crate, field.item);
      return `### \`${title}\`\n\n${code(renderer.fieldSignature(field.item))}\n\n${body ? `${body}\n\n` : ''}`;
    });
    return `\n## Fields\n\n${blocks.join('')}`;
  };

  const variantShape = (crate, variant) => {
    const kind = variant.inner?.variant?.kind;
    if (kind === 'plain') return variant.name;
    if (kind?.tuple) {
      const parts = kind.tuple.map((id) => (id === null ? '_' : renderer.type(crate.index[keyOf(id)]?.inner?.struct_field)));
      return `${variant.name}(${parts.join(', ')})`;
    }
    if (kind?.struct) {
      const parts = kind.struct.fields.map((id) => renderer.fieldSignature(crate.index[keyOf(id)]));
      return `${variant.name} { ${parts.join(', ')} }`;
    }
    return variant.name;
  };

  const variantsSection = (entry) => {
    const variants = mergeMembers(entry, (rec) => (rec.item.inner?.enum?.variants || [])
      .map((id, index) => ({ kind: 'variant', index, item: rec.crate.index[keyOf(id)] })).filter((member) => member.item));
    if (!variants.length) return '';
    const generated = (variant) => /^Native `[^`]+`\.(\n\nAvailable on [^\n]+)?$/.test(scalar(variant.item.docs).trim());
    const undocumented = variants.every((variant) => (!variant.item.docs || generated(variant)) && variant.item.inner.variant.kind === 'plain');
    if (undocumented) {
      const rows = variants.map((variant) => {
        const only = variant.abis.size === abisOf(entry).length ? '' : [...variant.abis].sort().map((abi) => ABI_LABEL[abi]).join(', ');
        const native = /^Native `([^`]+)`/.exec(scalar(variant.item.docs))?.[1];
        return `| \`${variant.item.name}\` | ${native ? `\`${native}\`` : '—'} | ${only ? `${only} only` : '—'} |`;
      });
      return `\n## Variants\n\n| Variant | Native constant | Availability |\n| --- | --- | --- |\n${rows.join('\n')}\n`;
    }
    const blocks = variants.map((variant) => {
      const availability = variant.abis.size === abisOf(entry).length ? '' : `*Available on ${[...variant.abis].sort().map((abi) => ABI_LABEL[abi]).join(' and ')} only.*\n\n`;
      const body = memberDocs(variant.crate, variant.item);
      const shape = variantShape(variant.crate, variant.item);
      const signature = shape === variant.item.name ? '' : `${code(shape)}\n\n`;
      return `### \`${variant.item.name}\`\n\n${availability}${signature}${body ? `${body}\n\n` : ''}`;
    });
    return `\n## Variants\n\n${blocks.join('')}`;
  };

  const constantsSection = (entry) => {
    const members = callableMembers(entry).filter((member) => member.kind === 'assoc_const');
    if (!members.length) return '';
    return `\n## Associated constants\n\n${members.map((member) => memberBlock(entry, member)).join('')}`;
  };

  const methodsSection = (entry) => {
    const members = callableMembers(entry).filter((member) => member.kind === 'function');
    if (!members.length) return '';
    return `\n## Methods\n\n${members.map((member) => memberBlock(entry, member)).join('')}`;
  };

  const traitItemsSection = (entry) => {
    const members = mergeMembers(entry, (rec) => (rec.item.inner?.trait?.items || [])
      .map((id, index) => ({ kind: 'trait_item', index, item: rec.crate.index[keyOf(id)] })).filter((member) => member.item));
    if (!members.length) return '';
    const blocks = members.map((member) => memberBlock(entry, { ...member, context: '' }, { inTrait: true }));
    return `\n## Associated items\n\n${blocks.join('')}`;
  };

  const implementationLine = (rec, implementation) => {
    const { list, clauses } = renderer.generics(implementation.generics);
    const unsafety = implementation.is_unsafe ? 'unsafe ' : '';
    const negative = implementation.is_negative ? '!' : '';
    const head = `${unsafety}impl${list} ${negative}${renderer.pathWithArguments(implementation.trait)} for ${renderer.type(implementation.for)}`;
    const text = clauses.length ? `${head} where ${clauses.join(', ')}` : head;
    const url = implementation.trait.id === null ? null : routeForId(registry, rec.crate, implementation.trait.id);
    return url ? `- [\`${text}\`](${url})` : `- \`${text}\``;
  };

  const traitImplementationsSection = (entry) => {
    const none = { aside: '', list: '' };
    if (!['struct', 'enum'].includes(entry.kind)) return none;
    const rec = record(entry);
    if (entry.publicPath.length === 3 && NO_TRAIT_LIST.has(entry.publicPath[1])) return none;
    const data = rec.item.inner[entry.kind];
    const lines = [];
    const negatives = new Set();
    for (const implId of data.impls || []) {
      const implementation = rec.crate.index[keyOf(implId)]?.inner?.impl;
      if (!implementation?.trait || implementation.blanket_impl) continue;
      const traitName = implementation.trait.path;
      if (implementation.is_synthetic) {
        if (implementation.is_negative && ['Send', 'Sync'].includes(traitName)) negatives.add(traitName);
        continue;
      }
      if (['StructuralPartialEq'].includes(traitName) || implementation.trait.path.includes('sealed')) continue;
      lines.push(implementationLine(rec, implementation));
    }
    let aside = '';
    if (negatives.size) {
      const names = [...negatives].sort().map((name) => `\`${name}\``);
      const subject = negatives.size === 2 ? `neither ${names[0]} nor ${names[1]}` : `not ${names[0]}`;
      aside = `\n:::note[Thread safety]\nThis type is ${subject}, so it cannot be moved or shared across tasks.\n:::\n`;
    }
    return { aside, list: lines.length ? `\n## Trait implementations\n\n${lines.join('\n')}\n` : '' };
  };

  const implementorsSection = (entry) => {
    if (entry.kind !== 'trait') return '';
    const targets = [...entry.abis.values()].flatMap((abiRecord) => (abiRecord.crate.implementors.get(keyOf(abiRecord.id)) || [])
      .map((implementation) => implementation.for?.resolved_path)
      .filter(Boolean)
      .map((resolved) => {
        const exposed = abiRecord.crate.exposed.get(keyOf(resolved.id));
        return exposed ? registry.entries.get(exposed.publicPath.join('::')) : null;
      })
      .filter(Boolean));
    if (!targets.length) return '';
    const unique = [...new Map(targets.map((target) => [target.key, target])).values()]
      .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
    if (!unique.length) return '';
    if (unique.length > MAX_LISTED_IMPLEMENTORS) {
      return `\n## Implementors\n\nImplemented by ${unique.length} generated types. Browse them through the [module index](${registry.entries.get(unique[0].publicPath.slice(0, -1).join('::'))?.route ?? '/reference/'}).\n`;
    }
    return `\n## Implementors\n\n${unique.map((target) => linkTo(target)).join(' · ')}\n`;
  };

  const usedBySection = (entry) => {
    const users = relations.valueUsers.get(entry.key);
    if (!users?.length) return '';
    const rows = users.map((info) => `| ${linkTo(info.entry)} | ${info.ownerName ? (relations.classes.get(info.ownerName) ? linkTo(relations.classes.get(info.ownerName).entry) : info.ownerName) : '—'} | ${accessText(info)} |`);
    return `\n## Used by attributes\n\n| Attribute | Class | Access |\n| --- | --- | --- |\n${rows.join('\n')}\n`;
  };

  /* ---------- structured pages for generated MUI vocabulary ---------- */

  const nativeRows = (rows) => `| Property | Value |\n| --- | --- |\n${rows.filter(Boolean).map(([key, value]) => `| ${key} | ${value} |`).join('\n')}\n`;
  const headerText = (header) => (header ? `\`${header.header}\` line ${header.line}` : null);

  const classPage = (entry) => {
    const info = relations.classes.get(entry.name);
    const rec = record(entry);
    const chain = [];
    for (let cursor = info; cursor; cursor = cursor.parent) chain.push(cursor);
    const inherited = chain.slice(1).filter((ancestor) => ancestor.attributes.length || ancestor.methods.length);
    const attributeRows = info.attributes.map((attribute) => `| ${linkTo(attribute.entry)} | ${valueLink(attribute)} | ${accessText(attribute)}${abiSuffix(attribute.entry)} |`);
    const methodRows = info.methods.map((method) => `| ${linkTo(method.entry)} | ${method.safe ? 'safe' : 'unsafe, raw message'}${abiSuffix(method.entry)} |`);
    const own = isGeneratedStub(rec.item.docs) ? '' : docsOf(rec);
    let body = `${abiNote(abisOf(entry), 'class')}${nativeRows([
      ['Native class', `\`${info.header?.native ?? entry.name}\``],
      ['Class identifier', info.classId ? `\`${info.classId}\`` : null],
      ['Superclass', info.parent ? linkTo(info.parent.entry) : 'none (root class)'],
      ['Inheritance chain', chain.map((cursor) => linkTo(cursor.entry)).join(' → ')],
      ['Native header', headerText(info.header)],
      abisOf(entry).length === allAbis.size ? null : ['Availability', `${abisOf(entry).map((abi) => ABI_LABEL[abi]).join(' and ')} only`],
    ])}\n`;
    if (own) body += `${own}\n\n`;
    body += `Create an instance with \`scope.builder::<${entry.name}>()\` inside [\`Mui::scope\`](${registry.entries.get('aros_mui::Mui')?.route ?? '/reference/'}); the typed attributes and methods below are the ones this class accepts, together with those inherited from its superclasses.\n`;
    if (attributeRows.length) body += `\n## Attributes defined by this class\n\n| Attribute | Value | Access |\n| --- | --- | --- |\n${attributeRows.join('\n')}\n`;
    if (methodRows.length) body += `\n## Methods defined by this class\n\n| Method | Dispatch |\n| --- | --- |\n${methodRows.join('\n')}\n`;
    if (inherited.length) {
      body += `\n## Inherited\n\n${inherited.map((ancestor) => `- ${linkTo(ancestor.entry)}: ${ancestor.attributes.length} attribute${ancestor.attributes.length === 1 ? '' : 's'}, ${ancestor.methods.length} method${ancestor.methods.length === 1 ? '' : 's'}`).join('\n')}\n`;
    }
    if (info.children.length) body += `\n## Subclasses\n\n${info.children.map((child) => linkTo(child.entry)).join(' · ')}\n`;
    return { body, description: generatedSummary(entry) };
  };

  const attributePage = (entry) => {
    const info = relations.attributes.get(entry.key);
    const rec = record(entry);
    const owner = info.owner ? linkTo(info.owner.entry) : info.ownerName ?? 'unknown';
    const usage = [];
    const target = info.ownerName ?? 'Class';
    const usageName = entry.name;
    if (info.build) usage.push(`// at construction\nlet object = scope.builder::<${target}>().with::<${usageName}>(value)?.build()?;`);
    if (info.set) usage.push(`// write\nobject.set::<${usageName}>(value)?;`);
    if (info.get) usage.push(`// read\nlet value = object.get::<${usageName}>()?;`);
    const unsafeUsage = [];
    if (!info.build && info.rawBuild) unsafeUsage.push(`// unsafe construction tag\nunsafe { builder.with_raw::<${usageName}>(word) }`);
    if (!info.set && info.rawSet) unsafeUsage.push(`// unsafe write\nunsafe { object.set_raw::<${usageName}>(word)? };`);
    if (!info.get && info.rawGet) unsafeUsage.push(`// unsafe read\nlet word = unsafe { object.get_raw::<${usageName}>()? };`);
    const subclassNote = info.owner?.children.length
      ? 'It is accepted by this class and by every subclass listed on the class page.'
      : 'It is accepted by this class.';
    const own = isGeneratedStub(rec.item.docs) ? '' : docsOf(rec);
    let body = `${abiNote(abisOf(entry), 'attribute')}${nativeRows([
      ['Native tag', info.tag ? `\`${info.tag}\`` : null],
      ['Class', owner],
      ['Native type', info.cType ? `\`${info.cType}\`` : null],
      ['Rust value', valueLink(info)],
      ['Access', accessText(info)],
      ['Native header', headerText(info.header)],
      abisOf(entry).length === allAbis.size ? null : ['Availability', `${abisOf(entry).map((abi) => ABI_LABEL[abi]).join(' and ')} only`],
    ])}\n${own ? `${own}\n\n` : ''}${subclassNote}\n`;
    if (usage.length) body += `\n## Usage\n\n${code(usage.join('\n\n'))}\n`;
    if (unsafeUsage.length) {
      body += `\n## Raw access\n\n:::caution[Safety]\nThe typed API does not offer every operation for this attribute. The raw operations take a machine word; the caller must uphold the full native contract for the value type \`${info.cType ?? 'unknown'}\`, including pointer lifetime and retention.\n:::\n\n${code(unsafeUsage.join('\n\n'))}\n`;
    }
    return { body, description: generatedSummary(entry) };
  };

  const methodPage = (entry) => {
    const info = relations.methods.get(entry.key);
    const rec = record(entry);
    const owner = info.owner ? linkTo(info.owner.entry) : info.ownerName ?? 'unknown';
    const own = isGeneratedStub(rec.item.docs) ? '' : docsOf(rec);
    let body = `${abiNote(abisOf(entry), 'method')}${nativeRows([
      ['Native method', info.tag ? `\`${info.tag}\`` : null],
      ['Class', owner],
      ['Message structure', info.message ? `\`${info.message}\`` : null],
      ['Dispatch', info.safe ? 'safe, typed arguments' : 'unsafe, caller supplies the native message'],
      ['Native header', headerText(info.header)],
      abisOf(entry).length === allAbis.size ? null : ['Availability', `${abisOf(entry).map((abi) => ABI_LABEL[abi]).join(' and ')} only`],
    ])}\n${own ? `${own}\n\n` : ''}`;
    if (info.safe) {
      body += `## Usage\n\n${code(`let output = object.call::<${entry.name}>(arguments);`)}\n`;
    } else {
      body += `## Usage\n\n:::caution[Safety]\nEvery pointer, lifetime, message ID and retained resource in the message must satisfy the native MUI method contract. Prefer the typed attribute, notification and builder APIs where they exist.\n:::\n\n${code(`let output = unsafe { object.call_raw::<${entry.name}>(&mut message) };`)}\n`;
    }
    return { body, description: generatedSummary(entry) };
  };

  /* ---------- module and landing pages ---------- */

  const hierarchyList = (nodes, depth = 0) => nodes
    .map((node) => `${'    '.repeat(depth)}- ${linkTo(node.entry)}${node.attributes.length ? ` — ${node.attributes.length} attributes` : ''}${node.children.length ? `\n${hierarchyList(node.children, depth + 1)}` : ''}`)
    .join('\n');

  const classesIndex = (entry) => {
    const roots = [...relations.classes.values()].filter((info) => !info.parent)
      .sort((a, b) => a.entry.name.localeCompare(b.entry.name));
    return `\n## Class hierarchy\n\nEvery class derives from the root class. Attributes and methods of a class are also valid on its subclasses.\n\n${hierarchyList(roots)}\n\n## All classes\n\n${itemTable(childrenOf(entry))}\n`;
  };

  const attributesIndex = (entry) => {
    const rows = childrenOf(entry).map((child) => {
      const info = relations.attributes.get(child.key);
      if (!info) return `| ${linkTo(child)} | — | — | — |`;
      return `| ${linkTo(child)}${abiSuffix(child)} | ${info.owner ? linkTo(info.owner.entry) : info.ownerName ?? '—'} | ${valueLink(info)} | ${accessText(info)} |`;
    });
    return `\n## All attributes\n\n| Attribute | Class | Value | Access |\n| --- | --- | --- | --- |\n${rows.join('\n')}\n`;
  };

  const methodsIndex = (entry) => {
    const rows = childrenOf(entry).map((child) => {
      const info = relations.methods.get(child.key);
      return `| ${linkTo(child)}${abiSuffix(child)} | ${info?.owner ? linkTo(info.owner.entry) : info?.ownerName ?? '—'} | ${info?.safe ? 'safe' : 'unsafe'} |`;
    });
    return `\n## All methods\n\n| Method | Class | Dispatch |\n| --- | --- | --- |\n${rows.join('\n')}\n`;
  };

  const valuesIndex = (entry) => {
    const rows = childrenOf(entry).map((child) => {
      const rec = record(child);
      const variants = rec.item.inner?.enum?.variants?.length;
      const users = relations.valueUsers.get(child.key)?.length ?? 0;
      return `| ${linkTo(child)}${abiSuffix(child)} | ${child.kind} | ${variants ?? '—'} | ${users || '—'} |`;
    });
    return `\n## All value types\n\n| Type | Kind | Variants | Attributes using it |\n| --- | --- | --- | --- |\n${rows.join('\n')}\n`;
  };

  const modulePage = (entry) => {
    const rec = record(entry);
    const intro = docsOf(rec, 1);
    const key = entry.publicPath.length === 2 ? entry.publicPath[1] : '';
    let listing;
    if (entry.crateName === 'aros_mui' && key === 'classes') listing = classesIndex(entry);
    else if (entry.crateName === 'aros_mui' && key === 'attributes') listing = attributesIndex(entry);
    else if (entry.crateName === 'aros_mui' && key === 'methods') listing = methodsIndex(entry);
    else if (entry.crateName === 'aros_mui' && key === 'values') listing = valuesIndex(entry);
    else {
      const children = childrenOf(entry);
      listing = children.length ? `\n## ${entry.publicPath.length === 1 ? 'Public items' : 'Items'}\n\n${itemTable(children)}\n` : '';
    }
    const guide = entry.publicPath.length === 1
      ? `\nFor the programming model, ownership rules and worked examples, see the [${entry.crateName.replace('_', '-')} guide](${entry.crateName === 'aros' ? '/api/aros/' : '/api/aros-mui/'}).\n`
      : '';
    return { body: `${intro}\n${guide}${listing}`, description: plainSummaryOf(entry) };
  };

  const itemPage = (entry) => {
    const rec = record(entry);
    const attributes = (rec.item.attrs || []).some((a) => a === 'non_exhaustive')
      ? ':::note\nThis type is `#[non_exhaustive]`; new variants or fields can appear in a compatible release.\n:::\n\n' : '';
    const signature = renderer.itemSignature(rec.item, entry.name);
    const body = docsOf(rec, 1);
    const source = sourceLine(rec.item);
    let page = `${abiNote(abisOf(entry))}${attributes}${code(signature)}\n\n${body ? `${body}\n` : ''}`;
    if (source) page += `\n<p class="source-link">Source: ${source}</p>\n`;
    const traits = traitImplementationsSection(entry);
    page += traits.aside;
    page += fieldsSection(entry);
    page += variantsSection(entry);
    page += traitItemsSection(entry);
    page += constantsSection(entry);
    page += methodsSection(entry);
    page += traits.list;
    page += implementorsSection(entry);
    page += usedBySection(entry);
    return { body: page, description: plainSummaryOf(entry) };
  };

  const renderEntry = async (entry) => {
    checkDeclaration(entry.key, new Set(entry.abis.keys()), record(entry).item.docs, [...allAbis]);
    let result;
    if (entry.kind === 'module') result = modulePage(entry);
    else if (entry.publicPath.length === 3 && entry.publicPath[1] === 'classes' && relations.classes.has(entry.name)) result = classPage(entry);
    else if (entry.publicPath.length === 3 && entry.publicPath[1] === 'attributes' && relations.attributes.has(entry.key)) result = attributePage(entry);
    else if (entry.publicPath.length === 3 && entry.publicPath[1] === 'methods' && relations.methods.has(entry.key)) result = methodPage(entry);
    else result = itemPage(entry);
    const description = result.description || `${KIND_LABEL[entry.kind] ?? entry.kind} ${entry.publicPath.join('::')}`;
    await writePage(entry.file, `${frontmatter(titleOf(entry), description)}\n${breadcrumb(entry)}${result.body}`);
  };

  const landing = async () => {
    const crates = [...registry.entries.values()].filter((entry) => entry.publicPath.length === 1)
      .sort((a, b) => a.name.localeCompare(b.name));
    const rows = crates.map((entry) => `| ${linkTo(entry)} | ${tableCell(plainSummaryOf(entry))} |`);
    await writePage(['index.md'], `${frontmatter('Rust API reference', 'Reference documentation for the public aros and aros-mui crates, generated from the source.')}
This reference is generated from the public items and Rustdoc comments of the
\`aros\` and \`aros-mui\` crates at revision [\`${revision.slice(0, 12)}\`](${repository}/tree/${revision}).
The API is the same on every supported target. The few items that exist on only one ABI profile (the AROS ABI is selected by the Cargo target, not by the API) say so at the top of their page.

| Crate | Purpose |
| --- | --- |
${rows.join('\n')}

## How to read this reference

- **Signatures** are shown as written in the source, with module paths shortened.
- **Safety and Panics** sections are highlighted; read them before calling an \`unsafe\` item.
- **Errors** sections name the \`ErrorKind\` a call can return.
- **Thread safety** notes appear on types that are neither \`Send\` nor \`Sync\`. Every handle derived from \`aros::Context\` belongs to the task that created it.
- The raw \`aros-sys\` and \`aros-mui-sys\` crates are intentionally not part of this reference.
- MUI [classes](/reference/aros_mui/classes/), [attributes](/reference/aros_mui/attributes/), [methods](/reference/aros_mui/methods/) and [value types](/reference/aros_mui/values/) are generated from the type relations in the crate, so their hierarchy and access rules are exact.

For concepts and worked examples, start with the [programming model](/api/) and the [consumer guide](/consumer-guide/).
`);
  };

  const abiDifferencesPage = async () => {
    const only = (abi) => [...registry.entries.values()].filter((entry) => entry.abis.size === 1 && entry.abis.has(abi));
    const variantRows = [];
    for (const entry of [...registry.entries.values()].filter((candidate) => candidate.kind === 'enum')) {
      const variants = mergeMembers(entry, (rec) => (rec.item.inner?.enum?.variants || [])
        .map((id, index) => ({ kind: 'variant', index, item: rec.crate.index[keyOf(id)] })).filter((member) => member.item));
      for (const variant of variants.filter((candidate) => candidate.abis.size < abisOf(entry).length)) {
        variantRows.push(`| ${linkTo(entry)} | \`${variant.item.name}\` | ${[...variant.abis].map((abi) => ABI_LABEL[abi]).join(', ')} only |`);
      }
    }
    const section = (abi) => {
      const entries = only(abi).sort((a, b) => a.key.localeCompare(b.key));
      if (!entries.length) return `\n## Declared only for ${ABI_LABEL[abi]}\n\nNothing: every public item is available on both targets.\n`;
      const groups = new Map();
      for (const entry of entries) {
        const key = entry.publicPath.length > 2 ? entry.publicPath[1] : 'crate root';
        groups.set(key, [...(groups.get(key) || []), entry]);
      }
      const blocks = [...groups].map(([group, members]) => `### ${group}\n\n${itemTable(members.map((member) => member)).replace(/ \*\([^)]*only\)\*/g, '')}`);
      return `\n## Declared only for ${ABI_LABEL[abi]}\n\n${entries.length} items. Using one of them on the other target is a compile error.\n\n${blocks.join('\n\n')}\n`;
    };
    const counts = [...allAbis].map((abi) => `${only(abi).length || 'no'} item${only(abi).length === 1 ? '' : 's'} for ${ABI_LABEL[abi]} only`).join(' and ');
    await writePage(['abi-differences.md'], `${frontmatter('ABI differences', 'The public items and enum variants that are available on only one of the two AROS ABI profiles.')}
[Rust API](/reference/) › ABI differences

The safe \`aros\` and \`aros-mui\` APIs are the same on ABI-v1 and ABI-v11: the Cargo target selects the ABI and
application source does not change. The items on this page are the exceptions. They come from the public MUI headers of the two
AROS builds: [Deadwood's AROS](https://github.com/deadwood2/AROS) (ABI-v11) does not declare the \`Panel\` family in
\`mui.h\`, while upstream AROS (ABI-v1, pinned through AROS-NX) does.

This page is generated by comparing the two builds, and the generator fails if it disagrees with the availability each item
states in its own documentation. Currently ${counts}.
${section('abi1')}${section('abi11')}
## Enum variants that differ

${variantRows.length ? `| Enum | Variant | Availability |\n| --- | --- | --- |\n${variantRows.join('\n')}` : 'No enum has a variant that exists on only one target.'}
`);
  };

  const sidebar = () => {
    const topLevel = (crateName) => [...registry.entries.values()]
      .filter((entry) => entry.crateName === crateName && entry.publicPath.length === 2)
      .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
    const crateEntry = (name) => registry.entries.get(name);
    const group = (crateName, label) => {
      const root = crateEntry(crateName);
      const items = [{ label: 'Crate overview', link: root.route }];
      for (const entry of topLevel(crateName)) {
        const special = crateName === 'aros_mui' && entry.kind === 'module';
        items.push({ label: special ? `${entry.name} (index)` : entry.name, link: entry.route });
      }
      return { label, collapsed: true, items };
    };
    return [{
      label: 'Rust API reference',
      items: [{ label: 'Overview', link: '/reference/' }, group('aros', 'aros'), group('aros_mui', 'aros-mui'), { label: 'ABI differences', link: '/reference/abi-differences/' }],
    }];
  };

  return {
    async writeAll() {
      for (const entry of [...registry.entries.values()].sort((a, b) => a.key.localeCompare(b.key))) await renderEntry(entry);
      await landing();
      await abiDifferencesPage();
      if (declarationErrors.length) {
        throw new Error(`ABI declarations disagree with the compiled builds:\n${declarationErrors.join('\n')}`);
      }
      await writePage(['sidebar.json'], JSON.stringify(sidebar(), null, 2));
      return written.length;
    },
    slug,
    scalar,
  };
}
