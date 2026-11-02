// SPDX-License-Identifier: MIT OR Apache-2.0
//
// A small TOML reader for Cargo manifests: tables, arrays of tables, dotted and
// quoted keys, basic and literal strings (single and multi-line), integers,
// floats, booleans, arrays and inline tables. Dates and times are refused, not
// guessed, because no manifest field the registry reads uses them.

export class TomlError extends Error {}

const BARE = /[A-Za-z0-9_-]/;

export function parseToml(text) {
  let position = 0;
  const root = {};
  let current = root;

  const fail = (message) => {
    const line = text.slice(0, position).split('\n').length;
    throw new TomlError(`TOML line ${line}: ${message}`);
  };
  const peek = (offset = 0) => text[position + offset];
  const startsWith = (token) => text.startsWith(token, position);

  const skipSpaces = () => {
    while (peek() === ' ' || peek() === '\t') position++;
  };
  const skipComment = () => {
    if (peek() === '#') while (position < text.length && peek() !== '\n') position++;
  };
  const skipBlank = () => {
    for (;;) {
      skipSpaces();
      skipComment();
      if (peek() === '\n' || peek() === '\r') position++;
      else return;
    }
  };
  const endOfLine = () => {
    skipSpaces();
    skipComment();
    if (position < text.length && peek() !== '\n' && peek() !== '\r') fail('expected the end of the line');
  };

  const escape = () => {
    const c = peek();
    position++;
    switch (c) {
      case 'b': return '\b';
      case 't': return '\t';
      case 'n': return '\n';
      case 'f': return '\f';
      case 'r': return '\r';
      case '"': return '"';
      case '\\': return '\\';
      case 'u':
      case 'U': {
        const length = c === 'u' ? 4 : 8;
        const hex = text.slice(position, position + length);
        if (!new RegExp(`^[0-9A-Fa-f]{${length}}$`).test(hex)) fail('bad unicode escape');
        position += length;
        return String.fromCodePoint(parseInt(hex, 16));
      }
      default:
        return fail(`unknown escape \\${c}`);
    }
  };

  const basicString = () => {
    position++; // opening quote
    let out = '';
    for (;;) {
      const c = peek();
      if (c === undefined || c === '\n') fail('unterminated string');
      position++;
      if (c === '"') return out;
      out += c === '\\' ? escape() : c;
    }
  };
  const literalString = () => {
    position++;
    const end = text.indexOf("'", position);
    const newline = text.indexOf('\n', position);
    if (end < 0 || (newline >= 0 && newline < end)) fail('unterminated literal string');
    const out = text.slice(position, end);
    position = end + 1;
    return out;
  };
  const multilineBasic = () => {
    position += 3;
    if (peek() === '\r' && peek(1) === '\n') position += 2;
    else if (peek() === '\n') position++;
    let out = '';
    for (;;) {
      if (position >= text.length) fail('unterminated multi-line string');
      if (startsWith('"""')) {
        position += 3;
        while (peek() === '"' && out.length >= 0) { // up to two extra quotes belong to the string
          out += '"';
          position++;
          if (out.endsWith('""') && peek() !== '"') break;
        }
        return out;
      }
      const c = peek();
      position++;
      if (c === '\\') {
        // A backslash before a line ending removes the whitespace that follows.
        const rest = text.slice(position);
        const trim = /^[ \t]*\r?\n\s*/.exec(rest);
        if (trim) position += trim[0].length;
        else out += escape();
      } else {
        out += c;
      }
    }
  };
  const multilineLiteral = () => {
    position += 3;
    if (peek() === '\r' && peek(1) === '\n') position += 2;
    else if (peek() === '\n') position++;
    const end = text.indexOf("'''", position);
    if (end < 0) fail('unterminated multi-line literal string');
    const out = text.slice(position, end);
    position = end + 3;
    return out;
  };

  const bareKeyPart = () => {
    const start = position;
    while (position < text.length && BARE.test(peek())) position++;
    if (position === start) fail('expected a key');
    return text.slice(start, position);
  };
  const keyPart = () => {
    if (peek() === '"') return basicString();
    if (peek() === "'") return literalString();
    return bareKeyPart();
  };
  const keyPath = () => {
    const parts = [keyPart()];
    for (;;) {
      skipSpaces();
      if (peek() !== '.') return parts;
      position++;
      skipSpaces();
      parts.push(keyPart());
    }
  };

  const value = () => {
    const c = peek();
    if (c === '"') return startsWith('"""') ? multilineBasic() : basicString();
    if (c === "'") return startsWith("'''") ? multilineLiteral() : literalString();
    if (c === '[') return array();
    if (c === '{') return inlineTable();
    if (startsWith('true') && !BARE.test(peek(4) ?? ' ')) { position += 4; return true; }
    if (startsWith('false') && !BARE.test(peek(5) ?? ' ')) { position += 5; return false; }
    const match = /^[+-]?(?:inf|nan|0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?)/.exec(text.slice(position));
    if (!match) return fail('expected a value');
    position += match[0].length;
    if (/^\d{4}-\d\d-\d\d|^\d\d:\d\d/.test(match[0] + (peek() ?? ''))) fail('dates and times are not supported');
    const token = match[0].replaceAll('_', '');
    if (/^[+-]?(inf|nan)$/.test(token)) fail('inf and nan are not supported');
    return token.startsWith('0x') || token.startsWith('0o') || token.startsWith('0b') ? Number(token) : Number(token);
  };

  const array = () => {
    position++;
    const items = [];
    for (;;) {
      skipBlank();
      if (peek() === ']') { position++; return items; }
      items.push(value());
      skipBlank();
      if (peek() === ',') { position++; continue; }
      skipBlank();
      if (peek() === ']') { position++; return items; }
      fail('expected , or ] in an array');
    }
  };

  const assign = (table, parts, val) => {
    let target = table;
    for (const part of parts.slice(0, -1)) {
      if (target[part] === undefined) target[part] = {};
      else if (typeof target[part] !== 'object' || Array.isArray(target[part])) fail(`key ${part} is not a table`);
      target = target[part];
    }
    const last = parts[parts.length - 1];
    if (Object.hasOwn(target, last)) fail(`duplicate key ${last}`);
    target[last] = val;
  };

  const inlineTable = () => {
    position++;
    const table = {};
    skipSpaces();
    if (peek() === '}') { position++; return table; }
    for (;;) {
      skipSpaces();
      const parts = keyPath();
      skipSpaces();
      if (peek() !== '=') fail('expected = in an inline table');
      position++;
      skipSpaces();
      assign(table, parts, value());
      skipSpaces();
      if (peek() === ',') { position++; continue; }
      if (peek() === '}') { position++; return table; }
      fail('expected , or } in an inline table');
    }
  };

  const descend = (parts, arrayOfTables) => {
    let target = root;
    parts.forEach((part, index) => {
      const last = index === parts.length - 1;
      let next = target[part];
      if (next === undefined) {
        next = last && arrayOfTables ? [] : {};
        target[part] = next;
      }
      if (Array.isArray(next)) {
        if (last && arrayOfTables) next.push({});
        else if (!last && next.length === 0) fail(`table ${part} is empty`);
        target = next[next.length - 1];
      } else if (typeof next === 'object') {
        if (last && arrayOfTables) fail(`${part} is not an array of tables`);
        target = next;
      } else {
        fail(`${part} is not a table`);
      }
    });
    return target;
  };

  for (;;) {
    skipBlank();
    if (position >= text.length) return root;
    if (peek() === '[') {
      const arrayOfTables = peek(1) === '[';
      position += arrayOfTables ? 2 : 1;
      skipSpaces();
      const parts = keyPath();
      skipSpaces();
      if (!startsWith(arrayOfTables ? ']]' : ']')) fail('expected the end of the table header');
      position += arrayOfTables ? 2 : 1;
      current = descend(parts, arrayOfTables);
      endOfLine();
    } else {
      const parts = keyPath();
      skipSpaces();
      if (peek() !== '=') fail('expected =');
      position++;
      skipSpaces();
      assign(current, parts, value());
      endOfLine();
    }
  }
}
