#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Keeps the documentation rules from being forgotten. Every crate published to
// the ami-rust registry must deny `missing_docs`, and nothing in its sources
// may switch the lint off. Every published crate must also have a guide page,
// `docs/api/<crate>.md`, that is listed in the site's content collection and in
// its sidebar.
//
// A crate denies the lint when its manifest says so under `[lints.rust]`. A
// crate may instead opt in to `[workspace.lints]` (`[lints] workspace =
// true`), in which case the workspace manifest that governs it must deny the
// lint; the repository sets the lint per crate, because Cargo warns about every
// workspace member that does not inherit workspace lints, and the example and
// test programs are deliberately outside the policy.
//
// usage: check-docs-policy.mjs [REPOSITORY_ROOT]

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseToml } from './registry/toml.mjs';

export const REGISTRY = 'metaneutrons';
const DENIED = new Set(['deny', 'forbid']);
const GROUPS = ['crates', 'tooling/crates'];

const levelOf = (value) => (typeof value === 'string' ? value : value?.level);

/** The published crates under `root` as `{ name, directory, manifest }`. */
export function publishedCrates(root) {
  const found = [];
  for (const group of GROUPS) {
    let entries;
    try {
      entries = readdirSync(join(root, group)).sort();
    } catch {
      continue;
    }
    for (const entry of entries) {
      const directory = join(root, group, entry);
      let text;
      try {
        text = readFileSync(join(directory, 'Cargo.toml'), 'utf8');
      } catch {
        continue;
      }
      const manifest = parseToml(text);
      const publish = manifest.package?.publish;
      if (Array.isArray(publish) && publish.includes(REGISTRY)) found.push({ name: manifest.package.name, directory, manifest });
    }
  }
  return found;
}

function* sourceFiles(directory) {
  for (const entry of readdirSync(directory).sort()) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) yield* sourceFiles(path);
    else if (entry.endsWith('.rs')) yield path;
  }
}

/** Every problem found, as one string per problem. */
export function check(root) {
  const problems = [];
  const workspaces = {
    crates: parseToml(readFileSync(join(root, 'Cargo.toml'), 'utf8')),
    'tooling/crates': parseToml(readFileSync(join(root, 'tooling/Cargo.toml'), 'utf8')),
  };
  const read = (path) => (existsSync(join(root, path)) ? readFileSync(join(root, path), 'utf8') : '');
  const collection = read('website/src/content.config.ts');
  const sidebar = read('website/astro.config.mjs');
  for (const crate of publishedCrates(root)) {
    const group = GROUPS.find((candidate) => crate.directory.startsWith(join(root, candidate) + '/'));
    const own = crate.manifest.lints;
    let level;
    if (own?.workspace === true) level = levelOf(workspaces[group].workspace?.lints?.rust?.missing_docs);
    else level = levelOf(own?.rust?.missing_docs);
    if (!DENIED.has(level)) problems.push(`${crate.name}: missing_docs is not denied (level ${level ?? 'unset'})`);
    const guide = `docs/api/${crate.name}.md`;
    if (!existsSync(join(root, guide))) problems.push(`${crate.name}: has no guide page ${guide}`);
    if (!collection.includes(`'api/${crate.name}.md'`)) problems.push(`${crate.name}: guide page is not in website/src/content.config.ts`);
    if (!sidebar.includes(`link: '/api/${crate.name}/'`)) problems.push(`${crate.name}: guide page is not in the sidebar of website/astro.config.mjs`);
    for (const file of sourceFiles(join(crate.directory, 'src'))) {
      const text = readFileSync(file, 'utf8');
      if (/#!?\[\s*(allow|warn|expect)\s*\([^\]]*\bmissing_docs\b/.test(text)) {
        problems.push(`${file.slice(root.length + 1)}: weakens the missing_docs lint`);
      }
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), '..');
  const crates = publishedCrates(root);
  const problems = check(root);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`docs policy: ${problem}`);
    process.exitCode = 1;
  } else {
    console.log(`docs policy: ${crates.length} published crates deny missing_docs and have a guide`);
  }
}
