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
          { label: 'Install and build', link: '/install/' },
          { label: 'Compatibility', link: '/compatibility/' },
        ] },
        { label: 'Libraries', items: [
          { label: 'Crates and APIs', link: '/crates/' },
          { label: 'MUI hello', link: '/mui-hello/' },
        ] },
        { label: 'Reference', items: [
          { label: 'Targets and ABI', link: '/targets/' },
          { label: 'Qualification', link: '/qualification/' },
          { label: 'Maintainers', link: '/maintainers/' },
        ] },
      ],
    }),
  ],
});
