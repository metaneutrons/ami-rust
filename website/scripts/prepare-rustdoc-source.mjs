import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const [sourceArgument] = process.argv.slice(2);
if (!sourceArgument) throw new Error('usage: prepare-rustdoc-source.mjs SOURCE_ROOT');

const sourceRoot = path.resolve(sourceArgument);
const original = 'target_abi = ""';
// Use a compiler-known ABI value that none of the supported documentation hosts
// has, so check-cfg remains quiet while the host's built-in empty ABI is masked.
const replacement = 'target_abi = "uwp"';
let replacements = 0;

async function rewrite(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await rewrite(entryPath);
    } else if (entry.isFile() && entry.name.endsWith('.rs')) {
      const input = await readFile(entryPath, 'utf8');
      const occurrences = input.split(original).length - 1;
      if (occurrences === 0) continue;
      await writeFile(entryPath, input.split(original).join(replacement), 'utf8');
      replacements += occurrences;
    }
  }
}

await rewrite(path.join(sourceRoot, 'crates'));
if (replacements === 0) throw new Error('no host-compatible target_abi cfg clauses found');
console.log(`prepared Rustdoc source snapshot with ${replacements} target ABI cfg replacements`);
