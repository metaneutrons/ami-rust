// Generates the Rust API reference pages from rustdoc JSON.
//
// usage: generate-rust-api.mjs OUTPUT_DIR REVISION \
//          ABI1_AROS_JSON ABI1_AROS_MUI_JSON ABI11_AROS_JSON ABI11_AROS_MUI_JSON
//
// Both ABI profiles are merged into one reference tree. The output directory
// is owned by this script and is removed before writing.

import { readFile, rm, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { buildRegistry, loadCrate } from './rustdoc/model.mjs';
import { createPageWriter } from './rustdoc/render.mjs';
import { buildMuiRelations } from './rustdoc/relations.mjs';

const REPOSITORY = 'https://github.com/metaneutrons/ami-rust';
const [outputArgument, revision, ...inputs] = process.argv.slice(2);
if (!outputArgument || !/^[0-9a-f]{40}$/.test(revision || '') || inputs.length !== 12) {
  throw new Error('usage: generate-rust-api.mjs OUTPUT_DIR 40_HEX_REVISION ABI1_AROS ABI1_AROS_MUI ABI1_AROS_TIMER ABI1_AROS_GRAPHICS ABI1_AROS_INTUITION ABI1_AROS_ASL ABI11_AROS ABI11_AROS_MUI ABI11_AROS_TIMER ABI11_AROS_GRAPHICS ABI11_AROS_INTUITION ABI11_AROS_ASL');
}

const outputRoot = path.resolve(outputArgument);
if (path.basename(outputRoot) !== 'reference' || outputRoot === path.parse(outputRoot).root) {
  throw new Error('OUTPUT_DIR must be a dedicated directory named reference');
}

const crates = [];
for (const [abi, files] of [['abi1', inputs.slice(0, 6)], ['abi11', inputs.slice(6)]]) {
  const names = new Set();
  for (const file of files) {
    const crate = loadCrate(JSON.parse(await readFile(file, 'utf8')), abi);
    if (!['aros', 'aros_mui', 'aros_timer', 'aros_graphics', 'aros_intuition', 'aros_asl'].includes(crate.crateName) || names.has(crate.crateName)) {
      throw new Error(`expected one aros, one aros_mui, one aros_timer, one aros_graphics, one aros_intuition and one aros_asl document per ABI, found ${crate.crateName}`);
    }
    names.add(crate.crateName);
    crates.push(crate);
  }
  if (names.size !== 6) throw new Error(`${abi}: expected aros, aros_mui, aros_timer, aros_graphics, aros_intuition and aros_asl`);
}

const registry = buildRegistry(crates);
const relations = buildMuiRelations(registry);

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });
const writer = createPageWriter({ registry, relations, outputRoot, repository: REPOSITORY, revision });
const count = await writer.writeAll();
console.log(`generated ${count} reference pages (${registry.entries.size} items, ${relations.classes.size} classes) in ${outputRoot}`);
