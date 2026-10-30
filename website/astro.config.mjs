import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  root: new URL('./', import.meta.url).pathname,
  site: 'https://ami-rust.metaneutrons.cc',
  integrations: [
    starlight({
      title: 'ami-rust',
      description: 'Rust for AROS x86-64 ABI-v1 and ABI-v11.',
      logo: {
        src: './src/assets/ami-rust-mark.svg',
        replacesTitle: true,
      },
      favicon: '/favicon.svg',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/metaneutrons/ami-rust' },
      ],
      customCss: ['./src/styles/ami-rust.css'],
      sidebar: [
        { label: 'Start here', items: [
          { label: 'Overview', link: '/' },
          { label: 'Install and build', link: '/quickstart-toolchain/' },
          { label: 'Compatibility', link: '/compatibility/' },
        ] },
        { label: 'Examples', items: [
          { label: 'MUI hello', link: '/mui-hello/' },
          { label: 'SHA-256', link: '/sha256sum/' },
        ] },
        { label: 'Libraries', items: [
          { label: 'Crates and consumer guide', link: '/consumer-guide/' },
          { label: 'API overview', link: '/api/' },
          { label: 'aros API', link: '/api/aros/' },
          { label: 'aros-mui API', link: '/api/aros-mui/' },
          { label: 'Generated MUI API', link: '/mui-safe-api/' },
        ] },
        { label: 'Reference', items: [
          { label: 'Platform roadmap', link: '/platform-roadmap/' },
          { label: 'Release model', link: '/release-versioning/' },
          { label: 'Maintainers', link: '/maintainers/' },
          { label: 'Maintenance and security', link: '/maintenance/' },
        ] },
      ],
    }),
  ],
});
