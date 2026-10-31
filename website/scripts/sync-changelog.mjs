// Publishes the repository's CHANGELOG.md as a site page.
//
// release-please writes CHANGELOG.md. This copies it to docs/changelog.md (not
// committed) with the frontmatter Starlight needs, so the page is always the
// file in the repository and updates with every release.

import { readFile, writeFile } from 'node:fs/promises';

const source = new URL('../../CHANGELOG.md', import.meta.url);
const target = new URL('../../docs/changelog.md', import.meta.url);

const text = (await readFile(source, 'utf8')).replace(/^# Changelog\s*\n/, '').trim();
if (!/^## \d+\.\d+\.\d+/m.test(text)) throw new Error('CHANGELOG.md has no release section');

await writeFile(target, `---
title: Changelog
description: Notable changes in each ami-rust release.
editUrl: false
---

${text}
`, 'utf8');
console.log('wrote docs/changelog.md');
