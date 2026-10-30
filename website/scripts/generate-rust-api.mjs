import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const [outputArgument, abiProfile, ...inputArguments] = process.argv.slice(2);
if (!outputArgument || !['abi1', 'abi11'].includes(abiProfile) || inputArguments.length !== 2) {
  throw new Error('usage: generate-rust-api.mjs OUTPUT_DIR abi1|abi11 AROS_JSON AROS_MUI_JSON');
}

const outputRoot = path.resolve(outputArgument);
const profileLabel = abiProfile === 'abi1' ? 'ABI-v1' : 'ABI-v11';

if (path.basename(outputRoot) !== 'generated' || outputRoot === path.parse(outputRoot).root) {
  throw new Error('OUTPUT_DIR must be a dedicated directory named generated');
}

const scalar = (value) => value === null || value === undefined ? '' : String(value);
const keyOf = (id) => String(id);
const innerKind = (item) => Object.keys(item?.inner || {})[0] || 'item';
const cleanName = (value) => scalar(value).replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^-|-$/g, '').toLowerCase();
const frontmatterString = (value) => JSON.stringify(scalar(value).replace(/\s+/g, ' ').trim());
const summary = (docs) => scalar(docs).split(/\n\s*\n/)[0].replace(/\s+/g, ' ').trim();
const metaSummary = (docs) => summary(docs)
  .replace(/\[(`?)([^\]]+?)\1\](?:\([^)]*\))?/g, '$2')
  .replace(/`([^`]+)`/g, '$1');
const tableCell = (value) => scalar(value).replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim() || '—';
const isHidden = (item) => (item?.attrs || []).some((attribute) => JSON.stringify(attribute).includes('doc(hidden)'));

function angleArguments(args, renderType) {
  const angle = args?.angle_bracketed;
  if (!angle) return '';
  const values = (angle.args || []).map((argument) => {
    if (argument.type) return renderType(argument.type);
    if (argument.lifetime) return argument.lifetime;
    if (argument.const) return scalar(argument.const.expr || argument.const);
    return '_';
  });
  for (const constraint of angle.constraints || []) {
    values.push(constraint.name || '_');
  }
  return values.length ? `<${values.join(', ')}>` : '';
}

function typeRenderer(index) {
  const renderType = (type) => {
    if (type === null || type === undefined) return '()';
    if (typeof type === 'string') return type;
    if (type.primitive) return type.primitive;
    if (type.generic) return type.generic;
    if (type.resolved_path) {
      const resolved = type.resolved_path;
      return `${resolved.path}${angleArguments(resolved.args, renderType)}`;
    }
    if (type.borrowed_ref) {
      const borrowed = type.borrowed_ref;
      const lifetime = borrowed.lifetime ? `${borrowed.lifetime} ` : '';
      return `&${lifetime}${borrowed.is_mutable ? 'mut ' : ''}${renderType(borrowed.type)}`;
    }
    if (type.raw_pointer) {
      return `*${type.raw_pointer.is_mutable ? 'mut' : 'const'} ${renderType(type.raw_pointer.type)}`;
    }
    if (type.slice) return `[${renderType(type.slice)}]`;
    if (type.array) return `[${renderType(type.array.type)}; ${scalar(type.array.len)}]`;
    if (type.tuple) return `(${type.tuple.map(renderType).join(', ')}${type.tuple.length === 1 ? ',' : ''})`;
    if (type.impl_trait) return `impl ${type.impl_trait.map(renderBound).join(' + ')}`;
    if (type.dyn_trait) return `dyn ${(type.dyn_trait.traits || []).map((trait) => renderType(trait.trait)).join(' + ')}`;
    if (type.function_pointer) {
      const declaration = type.function_pointer.sig;
      const inputs = (declaration.inputs || []).map((input) => renderType(input[1])).join(', ');
      const output = declaration.output ? ` -> ${renderType(declaration.output)}` : '';
      return `fn(${inputs})${output}`;
    }
    if (type.qualified_path) {
      return `<${renderType(type.qualified_path.self_type)} as ${renderType(type.qualified_path.trait)}>::${type.qualified_path.name}`;
    }
    if (type.pat) return renderType(type.pat.type);
    if (type.infer) return '_';
    return '_';
  };

  const renderBound = (bound) => {
    if (bound?.trait_bound) {
      const trait = bound.trait_bound.trait;
      return `${trait.path}${angleArguments(trait.args, renderType)}`;
    }
    if (bound?.outlives) return bound.outlives;
    if (bound?.use) return `use<${(bound.use || []).join(', ')}>`;
    return '_';
  };

  const generics = (data) => {
    const params = (data?.params || []).map((parameter) => {
      if (parameter.kind?.lifetime) return parameter.name;
      if (parameter.kind?.type) {
        const bounds = (parameter.kind.type.bounds || []).map(renderBound);
        return bounds.length ? `${parameter.name}: ${bounds.join(' + ')}` : parameter.name;
      }
      if (parameter.kind?.const) return `const ${parameter.name}: ${renderType(parameter.kind.const.type)}`;
      return parameter.name;
    });
    return params.length ? `<${params.join(', ')}>` : '';
  };

  const functionSignature = (item, qualifiedName = item.name, includeVisibility = false) => {
    const functionData = item.inner.function;
    const header = functionData.header || {};
    const qualifiers = [header.is_const && 'const', header.is_async && 'async', header.is_unsafe && 'unsafe']
      .filter(Boolean).join(' ');
    const prefix = qualifiers ? `${qualifiers} ` : '';
    const inputs = (functionData.sig.inputs || []).map(([name, type]) => {
      if (name === 'self' && type?.generic === 'Self') return 'self';
      if (name === 'self' && type?.borrowed_ref?.type?.generic === 'Self') {
        const borrowed = type.borrowed_ref;
        const lifetime = borrowed.lifetime && borrowed.lifetime !== "'_" ? `${borrowed.lifetime} ` : '';
        return `&${lifetime}${borrowed.is_mutable ? 'mut ' : ''}self`;
      }
      return `${name}: ${renderType(type)}`;
    });
    if (functionData.sig.is_c_variadic) inputs.push('...');
    const output = functionData.sig.output ? ` -> ${renderType(functionData.sig.output)}` : '';
    const visibility = includeVisibility && item.visibility === 'public' ? 'pub ' : '';
    return `${visibility}${prefix}fn ${qualifiedName}${generics(functionData.generics)}(${inputs.join(', ')})${output}`;
  };

  const itemSignature = (item, displayName) => {
    const kind = innerKind(item);
    const name = displayName || item.name || '_';
    if (kind === 'function') return functionSignature(item, name, true);
    if (kind === 'struct') return `pub struct ${name}${generics(item.inner.struct.generics)}`;
    if (kind === 'enum') return `pub enum ${name}${generics(item.inner.enum.generics)}`;
    if (kind === 'trait') return `pub trait ${name}${generics(item.inner.trait.generics)}`;
    if (kind === 'union') return `pub union ${name}${generics(item.inner.union.generics)}`;
    if (kind === 'type_alias') return `pub type ${name}${generics(item.inner.type_alias.generics)} = ${renderType(item.inner.type_alias.type)}`;
    if (kind === 'constant') return `pub const ${name}: ${renderType(item.inner.constant.type)}`;
    if (kind === 'static') return `pub static ${name}: ${renderType(item.inner.static.type)}`;
    if (kind === 'macro') return `macro_rules! ${name}`;
    if (kind === 'proc_macro') return `pub macro ${name}`;
    if (kind === 'module') return `pub mod ${name}`;
    return `pub ${kind} ${name}`;
  };

  return { renderType, functionSignature, itemSignature };
}

function apiModel(document) {
  const index = document.index;
  const crateItem = index[keyOf(document.root)];
  const crateName = crateItem.name;
  const routes = new Map();
  const entries = [];
  const visitedModules = new Set();

  function expose(id, publicPath, displayName) {
    const key = keyOf(id);
    const item = index[key];
    if (!item) return;
    const kind = innerKind(item);
    const candidate = { id: key, item, kind, publicPath, displayName: displayName || item.name };
    const existing = routes.get(key);
    if (!existing || publicPath.length < existing.publicPath.length) routes.set(key, candidate);
    if (kind === 'module') walkModule(key, publicPath);
  }

  function walkModule(id, publicPath) {
    const visitKey = `${id}:${publicPath.join('::')}`;
    if (visitedModules.has(visitKey)) return;
    visitedModules.add(visitKey);
    const moduleItem = index[keyOf(id)];
    for (const childId of moduleItem?.inner?.module?.items || []) {
      const child = index[keyOf(childId)];
      if (!child || child.visibility !== 'public' || isHidden(child)) continue;
      const useData = child.inner?.use;
      if (useData) {
        if (useData.id === null || useData.id === undefined) continue;
        if (useData.is_glob) walkModule(keyOf(useData.id), publicPath);
        else expose(useData.id, [...publicPath, useData.name], useData.name);
        continue;
      }
      if (!child.name) continue;
      expose(childId, [...publicPath, child.name], child.name);
    }
  }

  walkModule(document.root, [crateName]);
  for (const entry of routes.values()) {
    const relative = entry.publicPath.slice(1).map(cleanName);
    const kind = entry.kind;
    const filename = kind === 'module' ? 'index.md' : `${kind}-${relative.pop()}.md`;
    entry.outputParts = [abiProfile, cleanName(crateName), ...relative, filename];
    const routeParts = kind === 'module' ? entry.outputParts.slice(0, -1) : entry.outputParts;
    entry.route = `/reference/generated/${routeParts.join('/').replace(/\.md$/, '')}/`;
    entries.push(entry);
  }
  const crateEntry = {
    id: keyOf(document.root), item: crateItem, kind: 'module', publicPath: [crateName],
    displayName: crateName, outputParts: [abiProfile, cleanName(crateName), 'index.md'], route: `/reference/generated/${abiProfile}/${cleanName(crateName)}/`,
  };
  routes.set(crateEntry.id, crateEntry);
  for (const entry of entries) {
    const anchors = [
      ...memberIds(entry.item),
      ...(entry.item.inner?.enum?.variants || []),
      ...(entry.item.inner?.trait?.items || []),
    ];
    const data = entry.item.inner?.[entry.kind];
    for (const implId of data?.impls || []) {
      const implementation = index[keyOf(implId)]?.inner?.impl;
      if (!implementation || implementation.trait || implementation.is_synthetic || implementation.blanket_impl) continue;
      anchors.push(...(implementation.items || []));
    }
    for (const anchorId of anchors) {
      const anchorItem = index[keyOf(anchorId)];
      if (!anchorItem?.name || routes.has(keyOf(anchorId))) continue;
      routes.set(keyOf(anchorId), { route: `${entry.route}#${cleanName(anchorItem.name)}` });
    }
  }
  return { document, index, crateName, crateEntry, entries, routes };
}

function markdownLinker(model) {
  return (docs, item) => {
    let output = scalar(docs).replace(/^```ignore\s*$/gm, '```rust');
    const links = Object.entries(item?.links || {}).sort((a, b) => b[0].length - a[0].length);
    for (const [label, id] of links) {
      const target = model.routes.get(keyOf(id));
      if (!target) continue;
      output = output
        .split(`](${label})`).join(`](${target.route})`)
        .split(`[${label}]`).join(`[${label}](${target.route})`);
    }
    return output;
  };
}

function memberIds(item) {
  const data = item.inner?.[innerKind(item)];
  if (!data) return [];
  if (data.kind?.plain?.fields) return data.kind.plain.fields;
  if (data.kind?.tuple) return data.kind.tuple.filter((id) => id !== null);
  return [];
}

function inherentMethods(model, item) {
  const data = item.inner?.[innerKind(item)];
  const results = [];
  for (const implId of data?.impls || []) {
    const implementation = model.index[keyOf(implId)]?.inner?.impl;
    if (!implementation || implementation.trait || implementation.is_synthetic || implementation.blanket_impl) continue;
    for (const methodId of implementation.items || []) {
      const method = model.index[keyOf(methodId)];
      if (method?.visibility === 'public' && method.inner?.function) results.push(method);
    }
  }
  return results;
}

async function writePage(relativeParts, contents) {
  const destination = path.join(outputRoot, ...relativeParts);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, contents.endsWith('\n') ? contents : `${contents}\n`, 'utf8');
}

async function renderModel(model) {
  const { itemSignature, functionSignature } = typeRenderer(model.index);
  const linkDocs = markdownLinker(model);
  const sortedEntries = [...model.entries].filter((entry) => entry.id !== model.crateEntry.id)
    .sort((a, b) => a.publicPath.join('::').localeCompare(b.publicPath.join('::')));

  const byParent = new Map();
  for (const entry of sortedEntries) {
    const parent = entry.publicPath.slice(0, -1).join('::');
    const bucket = byParent.get(parent) || [];
    bucket.push(entry);
    byParent.set(parent, bucket);
  }

  const crateRows = (byParent.get(model.crateName) || []).map((entry) =>
    `| [\`${entry.displayName}\`](${entry.route}) | ${entry.kind} | ${tableCell(summary(entry.item.docs))} |`).join('\n');
  const cratePage = `---\ntitle: ${frontmatterString(model.crateName)}\ndescription: ${frontmatterString(metaSummary(model.crateEntry.item.docs))}\n---\n\n${linkDocs(model.crateEntry.item.docs, model.crateEntry.item)}\n\n## Public items\n\n| Item | Kind | Summary |\n| --- | --- | --- |\n${crateRows || '| — | — | No public items. |'}\n`;
  await writePage(model.crateEntry.outputParts, cratePage);

  for (const entry of sortedEntries) {
    const { item, kind } = entry;
    const canonical = entry.publicPath.join('::');
    if (kind === 'module') {
      const rows = (byParent.get(canonical) || []).map((child) =>
        `| [\`${child.displayName}\`](${child.route}) | ${child.kind} | ${tableCell(summary(child.item.docs))} |`).join('\n');
      await writePage(entry.outputParts, `---\ntitle: ${frontmatterString(`module ${canonical}`)}\ndescription: ${frontmatterString(metaSummary(item.docs))}\n---\n\n${linkDocs(item.docs, item)}\n\n## Items\n\n| Item | Kind | Summary |\n| --- | --- | --- |\n${rows || '| — | — | No public items. |'}\n`);
      continue;
    }

    let body = `---\ntitle: ${frontmatterString(`${kind} ${entry.displayName}`)}\ndescription: ${frontmatterString(metaSummary(item.docs))}\n---\n\n\`\`\`rust\n${itemSignature(item, entry.displayName)}\n\`\`\`\n\n${linkDocs(item.docs, item)}\n`;

    const fields = memberIds(item).map((id) => model.index[keyOf(id)]).filter(Boolean);
    if (fields.length) {
      body += '\n## Fields\n\n';
      for (const [fieldIndex, field] of fields.entries()) {
        const fieldName = field.name || fieldIndex;
        const fieldType = field.inner?.struct_field ? `\n\n\`\`\`rust\n${field.name ? `pub ${field.name}: ` : ''}${typeRenderer(model.index).renderType(field.inner.struct_field)}\n\`\`\`` : '';
        body += `### \`${fieldName}\`${fieldType}\n\n${linkDocs(field.docs, field)}\n\n`;
      }
    }

    const variants = (item.inner?.enum?.variants || []).map((id) => model.index[keyOf(id)]).filter(Boolean);
    if (variants.length) {
      body += '\n## Variants\n\n';
      for (const variant of variants) body += `### \`${variant.name}\`\n\n${linkDocs(variant.docs, variant)}\n\n`;
    }

    const methods = inherentMethods(model, item);
    if (methods.length) {
      body += '\n## Methods\n\n';
      for (const method of methods) {
        body += `### \`${method.name}\`\n\n\`\`\`rust\n${functionSignature(method, method.name)}\n\`\`\`\n\n${linkDocs(method.docs, method)}\n\n`;
      }
    }

    const traitItems = (item.inner?.trait?.items || []).map((id) => model.index[keyOf(id)]).filter(Boolean);
    if (traitItems.length) {
      body += '\n## Required items\n\n';
      for (const traitItem of traitItems) {
        body += `### \`${traitItem.name}\`\n\n\`\`\`rust\n${itemSignature(traitItem, traitItem.name)}\n\`\`\`\n\n${linkDocs(traitItem.docs, traitItem)}\n\n`;
      }
    }

    await writePage(entry.outputParts, body);
  }
}

await rm(path.join(outputRoot, abiProfile), { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });

const models = [];
const seenCrates = new Set();
for (const input of inputArguments) {
  const document = JSON.parse(await readFile(input, 'utf8'));
  if (document.format_version !== 60) {
    throw new Error(`unsupported rustdoc JSON format ${document.format_version} in ${input}`);
  }
  const model = apiModel(document);
  if (!['aros', 'aros_mui'].includes(model.crateName) || seenCrates.has(model.crateName)) {
    throw new Error(`expected exactly one aros and one aros_mui input, found ${model.crateName}`);
  }
  seenCrates.add(model.crateName);
  models.push(model);
  await renderModel(model);
}
if (seenCrates.size !== 2) throw new Error('expected exactly one aros and one aros_mui input');

const landingRows = models.map((model) =>
  `| [\`${model.crateName}\`](${model.crateEntry.route}) | ${tableCell(summary(model.crateEntry.item.docs))} |`).join('\n');
await writePage([abiProfile, 'index.md'], `---\ntitle: ${profileLabel} Rust API\ndescription: Source-derived ${profileLabel} API documentation for the public ami-rust crates.\n---\n\nThis reference is generated from the public items and Rustdoc comments in the\ncrate sources for x86-64 AROS ${profileLabel}. Signatures, ownership contracts,\nand safety sections follow the selected repository revision. Raw \`*-sys\` crates\nand hidden implementation details are excluded.\n\n| Crate | Purpose |\n| --- | --- |\n${landingRows}\n`);
await writePage(['index.md'], `---\ntitle: Rust API reference\ndescription: Source-derived API documentation for the public ami-rust crates.\n---\n\nChoose the AROS ABI selected by your target triple. Each reference is generated\nfrom the public Rust items and Rustdoc comments in the same repository revision.\n\n- [ABI-v1](/reference/generated/abi1/)\n- [ABI-v11](/reference/generated/abi11/)\n`);

console.log(`generated ${models.reduce((count, model) => count + model.entries.length, 0)} ${abiProfile} API items in ${outputRoot}`);
