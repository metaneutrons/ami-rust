import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
  docs: defineCollection({
    loader: glob({
      base: new URL('../../docs', import.meta.url).pathname,
      pattern: [
        'index.mdx',
        'api.md',
        'api/aros.md',
        'api/aros-mui.md',
        'compatibility.md',
        'consumer-guide.md',
        'maintainers.md',
        'maintenance.md',
        'mui-hello.mdx',
        'platform-roadmap.md',
        'quickstart-toolchain.md',
        'release-versioning.md',
        'sha256sum.md',
      ],
    }),
    schema: docsSchema(),
  }),
};
