// Renders public/social-card.png (1200x630) from the repository hero artwork.
import { readFile, writeFile } from 'node:fs/promises';
import sharp from 'sharp';

const hero = await readFile(new URL('../../assets/ami-rust-hero.svg', import.meta.url));
const artwork = await sharp(hero, { density: 192 }).resize({ width: 1040, withoutEnlargement: false }).png().toBuffer();
const card = await sharp({ create: { width: 1200, height: 630, channels: 4, background: '#0c1020' } })
  .composite([{ input: artwork, gravity: 'centre' }])
  .png({ compressionLevel: 9 })
  .toBuffer();
await writeFile(new URL('../public/social-card.png', import.meta.url), card);
console.log(`wrote public/social-card.png (${card.length} bytes)`);
