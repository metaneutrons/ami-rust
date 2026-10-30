// Renders rustdoc-JSON types, generics and signatures as Rust source text.

export const scalar = (value) => (value === null || value === undefined ? '' : String(value));
export const keyOf = (id) => String(id);
export const innerKind = (item) => Object.keys(item?.inner || {})[0] || 'item';

// Rustdoc keeps paths as written in the source (`crate::classes::Window`,
// `core::ffi::CStr`). Readers want the name, not the module spelling.
export const shortPath = (path) => {
  const text = scalar(path);
  const separator = text.lastIndexOf('::');
  return separator === -1 ? text : text.slice(separator + 2);
};

const MAX_LINE = 88;

export function createRenderer() {
  const type = (value) => {
    if (value === null || value === undefined) return '()';
    if (typeof value === 'string') return value;
    if (value.primitive) return value.primitive;
    if (value.generic) return value.generic;
    if (value.resolved_path) return pathWithArguments(value.resolved_path);
    if (value.borrowed_ref) {
      const reference = value.borrowed_ref;
      const lifetime = reference.lifetime ? `${reference.lifetime} ` : '';
      return `&${lifetime}${reference.is_mutable ? 'mut ' : ''}${type(reference.type)}`;
    }
    if (value.raw_pointer) return `*${value.raw_pointer.is_mutable ? 'mut' : 'const'} ${type(value.raw_pointer.type)}`;
    if (value.slice) return `[${type(value.slice)}]`;
    if (value.array) return `[${type(value.array.type)}; ${scalar(value.array.len)}]`;
    if (value.tuple) return `(${value.tuple.map(type).join(', ')}${value.tuple.length === 1 ? ',' : ''})`;
    if (value.impl_trait) return `impl ${value.impl_trait.map(bound).join(' + ')}`;
    if (value.dyn_trait) {
      const traits = (value.dyn_trait.traits || []).map((entry) => pathWithArguments(entry.trait));
      if (value.dyn_trait.lifetime) traits.push(value.dyn_trait.lifetime);
      return `dyn ${traits.join(' + ')}`;
    }
    if (value.function_pointer) {
      const signature = value.function_pointer.sig;
      const inputs = (signature.inputs || []).map((input) => type(input[1])).join(', ');
      const output = signature.output ? ` -> ${type(signature.output)}` : '';
      const header = value.function_pointer.header || {};
      const prefix = `${header.is_unsafe ? 'unsafe ' : ''}${abi(header.abi)}`;
      return `${prefix}fn(${inputs})${output}`;
    }
    if (value.qualified_path) {
      const qualified = value.qualified_path;
      const self = type(qualified.self_type);
      const traitPath = qualified.trait?.path;
      const name = `${qualified.name}${genericArguments(qualified.args)}`;
      if (!traitPath) return `${self}::${name}`;
      return `<${self} as ${pathWithArguments(qualified.trait)}>::${name}`;
    }
    if (value.pat) return type(value.pat.type);
    return '_';
  };

  const abi = (value) => {
    if (!value || value === 'Rust') return '';
    if (typeof value === 'string') return `extern "${value}" `;
    const name = Object.keys(value)[0];
    return name ? `extern "${name}" ` : '';
  };

  const genericArguments = (args) => {
    if (!args) return '';
    if (args.angle_bracketed) {
      const values = (args.angle_bracketed.args || []).map((argument) => {
        if (argument.type) return type(argument.type);
        if (argument.lifetime) return argument.lifetime;
        if (argument.const) return scalar(argument.const.expr ?? argument.const);
        return '_';
      });
      for (const constraint of args.angle_bracketed.constraints || []) {
        if (constraint.binding?.equality?.type) values.push(`${constraint.name} = ${type(constraint.binding.equality.type)}`);
        else if (constraint.binding?.constraint) values.push(`${constraint.name}: ${constraint.binding.constraint.map(bound).join(' + ')}`);
        else values.push(constraint.name);
      }
      return values.length ? `<${values.join(', ')}>` : '';
    }
    if (args.parenthesized) {
      const inputs = (args.parenthesized.inputs || []).map(type).join(', ');
      const output = args.parenthesized.output ? ` -> ${type(args.parenthesized.output)}` : '';
      return `(${inputs})${output}`;
    }
    return '';
  };

  function pathWithArguments(path) {
    return `${shortPath(path.path)}${genericArguments(path.args)}`;
  }

  function bound(value) {
    if (value?.trait_bound) {
      const modifier = value.trait_bound.modifier === 'maybe' ? '?' : '';
      return `${modifier}${pathWithArguments(value.trait_bound.trait)}`;
    }
    if (value?.outlives) return value.outlives;
    if (value?.use) return `use<${value.use.join(', ')}>`;
    return '_';
  }

  // Bounds naming a sealed module are an implementation detail, not API.
  const publicBounds = (bounds) => (bounds || []).filter((entry) => !JSON.stringify(entry).includes('sealed::'));

  const parameter = (entry) => {
    if (entry.kind?.lifetime) {
      const outlives = entry.kind.lifetime.outlives || [];
      return outlives.length ? `${entry.name}: ${outlives.join(' + ')}` : entry.name;
    }
    if (entry.kind?.type) {
      if (entry.kind.type.is_synthetic) return null;
      const bounds = publicBounds(entry.kind.type.bounds).map(bound);
      const base = bounds.length ? `${entry.name}: ${bounds.join(' + ')}` : entry.name;
      return entry.kind.type.default ? `${base} = ${type(entry.kind.type.default)}` : base;
    }
    if (entry.kind?.const) return `const ${entry.name}: ${type(entry.kind.const.type)}`;
    return entry.name;
  };

  const predicate = (entry) => {
    if (entry.bound_predicate) {
      const bounds = publicBounds(entry.bound_predicate.bounds).map(bound);
      if (!bounds.length) return null;
      return `${type(entry.bound_predicate.type)}: ${bounds.join(' + ')}`;
    }
    if (entry.lifetime_predicate) {
      return `${entry.lifetime_predicate.lifetime}: ${(entry.lifetime_predicate.outlives || []).join(' + ')}`;
    }
    if (entry.eq_predicate) return `${type(entry.eq_predicate.lhs)} == ${type(entry.eq_predicate.rhs?.type ?? entry.eq_predicate.rhs)}`;
    return null;
  };

  const generics = (data) => {
    const parameters = (data?.params || []).map(parameter).filter(Boolean);
    const clauses = (data?.where_predicates || []).map(predicate).filter(Boolean);
    return { list: parameters.length ? `<${parameters.join(', ')}>` : '', clauses };
  };

  const withWhere = (head, clauses) => {
    if (!clauses.length) return head;
    return `${head}\nwhere\n${clauses.map((clause) => `    ${clause},`).join('\n')}`;
  };

  const receiver = (name, value) => {
    if (name !== 'self') return null;
    if (value?.generic === 'Self') return 'self';
    if (value?.borrowed_ref?.type?.generic === 'Self') {
      const reference = value.borrowed_ref;
      const lifetime = reference.lifetime && reference.lifetime !== "'_" ? `${reference.lifetime} ` : '';
      return `&${lifetime}${reference.is_mutable ? 'mut ' : ''}self`;
    }
    return null;
  };

  const functionSignature = (item, name = item.name, { visibility = true } = {}) => {
    const data = item.inner.function;
    const header = data.header || {};
    const qualifiers = [header.is_const && 'const', header.is_async && 'async', header.is_unsafe && 'unsafe']
      .filter(Boolean).join(' ');
    const external = abi(header.abi);
    const prefix = `${visibility && item.visibility === 'public' ? 'pub ' : ''}${qualifiers ? `${qualifiers} ` : ''}${external}`;
    const inputs = (data.sig.inputs || []).map(([parameterName, parameterType]) =>
      receiver(parameterName, parameterType) ?? `${parameterName}: ${type(parameterType)}`);
    if (data.sig.is_c_variadic) inputs.push('...');
    const output = data.sig.output ? ` -> ${type(data.sig.output)}` : '';
    const { list, clauses } = generics(data.generics);
    const oneLine = `${prefix}fn ${name}${list}(${inputs.join(', ')})${output}`;
    if (oneLine.length <= MAX_LINE || inputs.length === 0) return withWhere(oneLine, clauses);
    const body = inputs.map((input) => `    ${input},`).join('\n');
    return withWhere(`${prefix}fn ${name}${list}(\n${body}\n)${output}`, clauses);
  };

  const supertraits = (item) => {
    const bounds = publicBounds(item.inner.trait.bounds).map(bound);
    return bounds.length ? `: ${bounds.join(' + ')}` : '';
  };

  const itemSignature = (item, name = item.name) => {
    const kind = innerKind(item);
    const data = item.inner[kind];
    const attributes = (item.attrs || [])
      .map((entry) => (entry.repr ? `#[repr(${entry.repr.int || entry.repr.kind})]` : entry === 'non_exhaustive' ? '#[non_exhaustive]' : null))
      .filter(Boolean);
    const lead = attributes.length ? `${attributes.join('\n')}\n` : '';
    const declared = (head) => {
      const { list, clauses } = generics(data.generics);
      return withWhere(`${head}${list}`, clauses);
    };
    if (kind === 'function') return functionSignature(item, name);
    if (kind === 'struct') return `${lead}${declared(`pub struct ${name}`)}`;
    if (kind === 'enum') return `${lead}${declared(`pub enum ${name}`)}`;
    if (kind === 'union') return `${lead}${declared(`pub union ${name}`)}`;
    if (kind === 'trait') {
      const unsafety = data.is_unsafe ? 'unsafe ' : '';
      const { list, clauses } = generics(data.generics);
      return withWhere(`${lead}pub ${unsafety}trait ${name}${list}${supertraits(item)}`, clauses);
    }
    if (kind === 'type_alias') {
      const { list } = generics(data.generics);
      return `pub type ${name}${list} = ${type(data.type)};`;
    }
    if (kind === 'constant') return `pub const ${name}: ${type(data.type)};`;
    if (kind === 'static') return `pub static ${name}: ${type(data.type)};`;
    if (kind === 'macro') return `macro_rules! ${name} { ... }`;
    if (kind === 'module') return `pub mod ${name}`;
    return `pub ${kind} ${name}`;
  };

  // Associated items, as written inside an impl or trait body.
  const associatedSignature = (item, { inTrait = false } = {}) => {
    const kind = innerKind(item);
    const data = item.inner[kind];
    if (kind === 'function') return functionSignature(item, item.name, { visibility: !inTrait });
    if (kind === 'assoc_const') {
      const value = !inTrait && data.value ? ` = ${data.value}` : '';
      return `${inTrait ? '' : 'pub '}const ${item.name}: ${type(data.type)}${value};`;
    }
    if (kind === 'assoc_type') {
      const bounds = publicBounds(data.bounds).map(bound);
      const clause = bounds.length ? `: ${bounds.join(' + ')}` : '';
      const value = data.type ? ` = ${type(data.type)}` : '';
      const { list } = generics(data.generics);
      return `type ${item.name}${list}${clause}${value};`;
    }
    return `${kind} ${item.name}`;
  };

  const fieldSignature = (field) => {
    const data = field.inner?.struct_field;
    const visibility = field.visibility === 'public' ? 'pub ' : '';
    return `${visibility}${field.name ? `${field.name}: ` : ''}${type(data)}`;
  };

  return {
    type, bound, generics, itemSignature, associatedSignature, functionSignature,
    fieldSignature, pathWithArguments, publicBounds,
  };
}
