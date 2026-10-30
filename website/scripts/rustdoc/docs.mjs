// Turns Rustdoc comment text into site-ready Markdown.
//
// Rustdoc resolves intra-doc links into a `links` table keyed by the link
// destination exactly as written. This module applies that table, normalises
// code fences, removes doctest-hidden lines and keeps the heading outline
// beneath the page title.

const ASIDES = new Map([
  ['Safety', 'caution'],
  ['Panics', 'caution'],
]);

const FENCE = /^(\s*)(`{3,}|~{3,})\s*(.*)$/;
const HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;

const fenceLanguage = (info) => {
  const tokens = info.split(/[\s,]+/).filter(Boolean);
  if (tokens.includes('text') || tokens.includes('console') || tokens.includes('sh')) {
    return tokens.find((token) => ['text', 'console', 'sh'].includes(token));
  }
  if (tokens.includes('toml')) return 'toml';
  return 'rust';
};

// Rustdoc hides doctest lines that start with `# `; `##` escapes a literal `#`.
const visibleCodeLine = (line) => {
  const hidden = /^(\s*)#(?: (.*))?$/.exec(line);
  if (hidden) return null;
  return line.replace(/^(\s*)##/, '$1#');
};

function protectInlineCode(text) {
  const spans = [];
  const protectedText = text.replace(/`[^`\n]*`/g, (span) => {
    spans.push(span);
    return `\u0000${spans.length - 1}\u0000`;
  });
  const restore = (value) => value.replace(/\u0000(\d+)\u0000/g, (_, index) => spans[Number(index)]);
  return { protectedText, restore };
}

function rewriteLinks(text, resolver) {
  const { protectedText, restore } = protectInlineCode(text);
  const rewritten = protectedText.replace(/\[([^\[\]\n]+)\](\([^)\n]*\)|\[[^\]\n]*\])?/g, (match, label, suffix) => {
    const plainLabel = restore(label);
    let key;
    if (suffix?.startsWith('(')) {
      key = suffix.slice(1, -1).trim();
      if (/^(https?:|mailto:|#|\/|\.\.?\/)/.test(key)) return restore(match);
    } else if (suffix?.startsWith('[')) {
      key = suffix.slice(1, -1).trim() || plainLabel;
    } else {
      key = plainLabel;
    }
    if (!resolver.has(key)) return restore(match);
    const url = resolver.url(key);
    return url ? `[${plainLabel}](${url})` : plainLabel;
  });
  return restore(rewritten);
}

/**
 * @param {string} text Raw Rustdoc Markdown.
 * @param {{has(key: string): boolean, url(key: string): string | null}} resolver
 * @param {{shift?: number}} options Heading levels to add to the source headings.
 */
export function processDocs(text, resolver, { shift = 1 } = {}) {
  if (!text) return '';
  const output = [];
  let fence = null;
  let aside = false;
  let prose = [];
  const flushProse = () => {
    if (!prose.length) return;
    output.push(rewriteLinks(prose.join('\n'), resolver));
    prose = [];
  };
  const closeAside = () => {
    if (!aside) return;
    flushProse();
    output.push('', ':::', '');
    aside = false;
  };

  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    const fenceMatch = FENCE.exec(line);
    if (fence) {
      if (fenceMatch && fenceMatch[2][0] === fence.marker[0] && fenceMatch[2].length >= fence.marker.length && !fenceMatch[3]) {
        output.push(`${fence.indent}${fence.marker}`);
        fence = null;
      } else if (fence.language === 'rust') {
        const visible = visibleCodeLine(line);
        if (visible !== null) output.push(visible);
      } else {
        output.push(line);
      }
      continue;
    }
    if (fenceMatch) {
      flushProse();
      const language = fenceLanguage(fenceMatch[3]);
      fence = { marker: fenceMatch[2], indent: fenceMatch[1], language };
      output.push(`${fenceMatch[1]}${fenceMatch[2]}${language}`);
      continue;
    }
    const heading = HEADING.exec(line);
    if (heading) {
      closeAside();
      flushProse();
      const title = heading[2].replace(/`/g, '');
      const kind = ASIDES.get(title);
      if (kind) {
        output.push('', `:::${kind}[${title}]`);
        aside = true;
      } else {
        output.push(`${'#'.repeat(Math.min(6, heading[1].length + shift))} ${heading[2]}`);
      }
      continue;
    }
    prose.push(line);
  }
  flushProse();
  closeAside();
  return output.join('\n').replace(/\n{3,}/g, '\n\n').trim();
}

/** First paragraph of already processed Markdown. */
export function firstParagraph(markdown) {
  const paragraph = (markdown || '').split(/\n\s*\n/)[0] || '';
  if (/^(```|~~~|:::|#)/.test(paragraph.trim())) return '';
  return paragraph.replace(/\s+/g, ' ').trim();
}

/** Plain-text rendition for metadata: no links, no code spans. */
export function plainText(markdown) {
  return (markdown || '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Table-cell-safe Markdown. */
export const tableCell = (markdown) => (markdown || '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim() || '—';
