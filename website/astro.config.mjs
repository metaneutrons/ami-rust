import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const root = new URL('./', import.meta.url);
const repository = 'https://github.com/metaneutrons/ami-rust';

const release = readFileSync(new URL('../version.txt', root), 'utf8').trim();
const revision = (() => {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root.pathname, encoding: 'utf8' }).trim();
  } catch {
    return '0'.repeat(40);
  }
})();

// The API reference sidebar is produced together with the reference pages.
const generatedSidebar = new URL('../docs/reference/sidebar.json', root);
const referenceSidebar = existsSync(generatedSidebar)
  ? JSON.parse(readFileSync(generatedSidebar, 'utf8'))
  : [{ label: 'Rust API reference', items: [{ label: 'Overview', link: '/reference/' }] }];

export default defineConfig({
  root: root.pathname,
  site: 'https://ami-rust.metaneutrons.cc',
  redirects: {
    '/reference/generated/': '/reference/',
    '/reference/generated/abi1/': '/reference/',
    '/reference/generated/abi11/': '/reference/',
  },
  vite: {
    define: {
      __DOCS_RELEASE__: JSON.stringify(release),
      __DOCS_REVISION__: JSON.stringify(revision),
    },
  },
  integrations: [
    starlight({
      title: 'ami-rust',
      description: 'Rust for AROS x86-64: safe, task-affine libraries and a Cargo cross-toolchain for ABI-v1 and ABI-v11.',
      logo: { src: './src/assets/ami-rust-mark.svg', replacesTitle: true },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: repository }],
      editLink: { baseUrl: `${repository}/edit/main/` },
      customCss: ['./src/styles/ami-rust.css'],
      components: { Footer: './src/components/Footer.astro' },
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: 'https://ami-rust.metaneutrons.cc/social-card.png' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: 'https://ami-rust.metaneutrons.cc/social-card.png' } },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Install and build', link: '/quickstart-toolchain/' },
            { label: 'Run on AROS', link: '/run-on-aros/' },
            { label: 'Targets and ABIs', link: '/targets-and-abis/' },
            { label: 'Compatibility', link: '/compatibility/' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Crates and consumer guide', link: '/consumer-guide/' },
            { label: 'Programming model', link: '/api/' },
            { label: 'The aros crate', link: '/api/aros/' },
            { label: 'The aros-mui crate', link: '/api/aros-mui/' },
            { label: 'Build system', link: '/build-system/' },
            { label: 'Troubleshooting', link: '/troubleshooting/' },
          ],
        },
        {
          label: 'Examples',
          items: [
            { label: 'MUI hello', link: '/mui-hello/' },
            { label: 'SHA-256', link: '/sha256sum/' },
          ],
        },
        ...referenceSidebar,
        {
          label: 'Project',
          items: [
            { label: 'Architecture', link: '/architecture/' },
            { label: 'Releases and versions', link: '/releases/' },
            { label: 'Platform roadmap', link: '/platform-roadmap/' },
            { label: 'Glossary', link: '/glossary/' },
          ],
        },
      ],
    }),
  ],
});
