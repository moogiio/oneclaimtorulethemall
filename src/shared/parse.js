// ADFS claim rule language lexer and parser. Pure ESM, shared between browser and server.
// The parser splits input into rules at top-level ';' so one broken rule does
// not prevent the rest of the file from being parsed.

export class ParseError extends Error {
  constructor(message, pos) {
    super(message);
    this.pos = pos;
  }
}

const OPERATORS = ['=>', '==', '=~', '!=', '!~', '&&', '>=', '<=', '=', '>', '<'];
const PUNCT = '[](),;:.@+';
const PROPS = ['Type', 'Value', 'Issuer', 'OriginalIssuer', 'ValueType', 'Properties'];

export function lex(source) {
  const tokens = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (/\s/.test(ch)) { i++; continue; }
    const start = i;
    if (ch === '"') {
      i++;
      while (i < source.length && source[i] !== '"') i += source[i] === '\\' ? 2 : 1;
      if (i >= source.length) throw new ParseError('Unterminated string', start);
      i++;
      tokens.push({ t: 'str', v: source.slice(start + 1, i - 1), start, end: i });
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      while (i < source.length && /[A-Za-z0-9_]/.test(source[i])) i++;
      tokens.push({ t: 'id', v: source.slice(start, i), start, end: i });
      continue;
    }
    if (/[0-9]/.test(ch)) {
      while (i < source.length && /[0-9]/.test(source[i])) i++;
      tokens.push({ t: 'num', v: Number(source.slice(start, i)), start, end: i });
      continue;
    }
    const op = OPERATORS.find((o) => source.startsWith(o, i));
    if (op) {
      i += op.length;
      tokens.push({ t: 'op', v: op, start, end: i });
      continue;
    }
    if (PUNCT.includes(ch)) {
      i++;
      tokens.push({ t: 'p', v: ch, start, end: i });
      continue;
    }
    throw new ParseError(`Unexpected character "${ch}"`, start);
  }
  return tokens;
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.i = 0;
  }

  peek(offset = 0) { return this.tokens[this.i + offset]; }

  is(t, v, offset = 0) {
    const tok = this.peek(offset);
    if (!tok || tok.t !== t) return false;
    if (v === undefined) return true;
    return t === 'id' ? tok.v.toLowerCase() === v.toLowerCase() : tok.v === v;
  }

  eat(t, v) {
    if (!this.is(t, v)) {
      const tok = this.peek();
      const found = tok ? `"${tok.v}"` : 'end of rule';
      throw new ParseError(`Expected ${v ? `"${v}"` : t} but found ${found}`, tok ? tok.start : null);
    }
    return this.tokens[this.i++];
  }

  rule() {
    const annotations = {};
    while (this.is('p', '@')) {
      this.eat('p', '@');
      const key = this.eat('id').v;
      this.eat('op', '=');
      annotations[key] = this.eat('str').v;
    }
    const conditions = [];
    if (!this.is('op', '=>')) {
      conditions.push(this.condition());
      while (this.is('op', '&&')) {
        this.eat('op', '&&');
        conditions.push(this.condition());
      }
    }
    this.eat('op', '=>');
    const action = this.action();
    this.eat('p', ';');
    if (this.peek()) throw new ParseError(`Unexpected "${this.peek().v}" after ";"`, this.peek().start);
    return { annotations, conditions, action };
  }

  condition() {
    if (this.is('id', 'NOT') && this.is('id', 'EXISTS', 1)) {
      this.i += 2;
      return { kind: 'exists', negate: true, criteria: this.aggregateArg() };
    }
    if (this.is('id', 'NOTEXISTS') || this.is('id', 'EXISTS')) {
      const negate = this.eat('id').v.toLowerCase() === 'notexists';
      return { kind: 'exists', negate, criteria: this.aggregateArg() };
    }
    if (this.is('id', 'COUNT') && this.is('p', '(', 1)) {
      this.eat('id');
      const criteria = this.aggregateArg();
      const op = this.eat('op').v;
      if (!['==', '!=', '>', '<', '>=', '<='].includes(op)) throw new ParseError(`Invalid COUNT comparison "${op}"`);
      return { kind: 'count', criteria, op, number: this.eat('num').v };
    }
    let variable = null;
    if (this.is('id') && this.is('p', ':', 1)) {
      variable = this.eat('id').v;
      this.eat('p', ':');
    }
    return { kind: 'select', variable, criteria: this.criteria() };
  }

  aggregateArg() {
    this.eat('p', '(');
    const criteria = this.criteria();
    this.eat('p', ')');
    return criteria;
  }

  criteria() {
    this.eat('p', '[');
    const list = [];
    if (!this.is('p', ']')) {
      list.push(this.criterion());
      while (this.is('p', ',')) {
        this.eat('p', ',');
        list.push(this.criterion());
      }
    }
    this.eat('p', ']');
    return list;
  }

  propName() {
    const tok = this.eat('id');
    const prop = PROPS.find((p) => p.toLowerCase() === tok.v.toLowerCase());
    if (!prop) throw new ParseError(`Unknown claim property "${tok.v}"`, tok.start);
    let key = null;
    if (prop === 'Properties') {
      this.eat('p', '[');
      key = this.eat('str').v;
      this.eat('p', ']');
    }
    return { prop, key };
  }

  criterion() {
    const { prop, key } = this.propName();
    const op = this.eat('op').v;
    if (!['==', '!=', '=~', '!~'].includes(op)) throw new ParseError(`Invalid comparison "${op}"`);
    return { prop, key, op, value: this.eat('str').v };
  }

  action() {
    const verb = this.eat('id').v.toLowerCase();
    if (verb !== 'issue' && verb !== 'add') throw new ParseError(`Expected issue or add but found "${verb}"`);
    this.eat('p', '(');
    const args = [this.arg()];
    while (this.is('p', ',')) {
      this.eat('p', ',');
      args.push(this.arg());
    }
    this.eat('p', ')');
    return { verb, args };
  }

  arg() {
    const tok = this.eat('id');
    const name = tok.v.toLowerCase();
    let key = null;
    if (name === 'properties') {
      this.eat('p', '[');
      key = this.eat('str').v;
      this.eat('p', ']');
    }
    this.eat('op', '=');
    if (name === 'types') {
      this.eat('p', '(');
      const items = [this.eat('str').v];
      while (this.is('p', ',')) {
        this.eat('p', ',');
        items.push(this.eat('str').v);
      }
      this.eat('p', ')');
      return { name, key, value: { kind: 'list', items } };
    }
    return { name, key, value: this.expr() };
  }

  expr() {
    const parts = [this.term()];
    while (this.is('p', '+')) {
      this.eat('p', '+');
      parts.push(this.term());
    }
    return parts.length === 1 ? parts[0] : { kind: 'concat', parts };
  }

  term() {
    if (this.is('str')) return { kind: 'string', value: this.eat('str').v };
    if (this.is('num')) return { kind: 'number', value: this.eat('num').v };
    const id = this.eat('id').v;
    if (this.is('p', '(')) {
      this.eat('p', '(');
      const args = [];
      if (!this.is('p', ')')) {
        args.push(this.expr());
        while (this.is('p', ',')) {
          this.eat('p', ',');
          args.push(this.expr());
        }
      }
      this.eat('p', ')');
      return { kind: 'call', name: id, args };
    }
    if (this.is('p', '.')) {
      this.eat('p', '.');
      const { prop, key } = this.propName();
      return { kind: 'ref', variable: id, prop, key };
    }
    return { kind: 'ident', name: id };
  }
}

// Splits source into rule chunks and parses each one.
// Returns [{ raw, ast | null, error | null }].
export function parseRules(source) {
  const text = String(source || '').replace(/^﻿/, '');
  let tokens;
  try {
    tokens = lex(text);
  } catch (err) {
    if (!(err instanceof ParseError)) throw err;
    return [{ raw: text.trim(), ast: null, error: `${err.message}${lineInfo(text, err.pos)}` }];
  }
  const chunks = [];
  let current = [];
  for (const tok of tokens) {
    current.push(tok);
    if (tok.t === 'p' && tok.v === ';') {
      chunks.push(current);
      current = [];
    }
  }
  if (current.length) chunks.push(current);

  return chunks.map((chunk) => {
    const raw = text.slice(chunk[0].start, chunk[chunk.length - 1].end);
    try {
      const ast = new Parser(chunk).rule();
      return { raw, ast, error: null };
    } catch (err) {
      if (!(err instanceof ParseError)) throw err;
      return { raw, ast: null, error: `${err.message}${lineInfo(text, err.pos)}` };
    }
  });
}

function lineInfo(text, pos) {
  if (pos == null) return '';
  const line = text.slice(0, pos).split('\n').length;
  return ` (line ${line})`;
}

// Rule text is parsed again on every keystroke and render; most texts are
// unchanged, so parses are cached. A small LRU: typing makes a new text per
// keystroke, and old ones age out fast. Callers treat the result as read-only.
// Big enough for every custom rule of an imported farm, so the linter and
// the plain-words explanations do not push each other's entries out.
const PARSE_CACHE_MAX = 500;
const parseCache = new Map();

export function parseRulesCached(source) {
  const key = String(source || '');
  let chunks = parseCache.get(key);
  if (chunks) {
    parseCache.delete(key);
  } else {
    chunks = parseRules(key);
    if (parseCache.size >= PARSE_CACHE_MAX) parseCache.delete(parseCache.keys().next().value);
  }
  parseCache.set(key, chunks);
  return chunks;
}

// The claim type a condition selects (c:[Type == "..."]), or ''.
function selectedType(conditions, variable) {
  const cond = conditions.find((c) => c.kind === 'select' && c.variable === variable);
  const type = cond && cond.criteria.find((c) => c.prop === 'Type' && c.op === '==');
  return type ? type.value : '';
}

// The claim types the action of a parsed custom rule makes: written out
// (Type = "...", types = (...)), or passed on from a condition (claim = c,
// Type = c.Type) when that condition selects one exact type.
function actionTypes(ast) {
  const types = [];
  for (const arg of ast.action.args) {
    const { kind } = arg.value;
    if (arg.name === 'type' && kind === 'string') types.push(arg.value.value);
    if (arg.name === 'types') types.push(...arg.value.items);
    if (arg.name === 'claim' && kind === 'ident') types.push(selectedType(ast.conditions, arg.value.name));
    if (arg.name === 'type' && kind === 'ref' && arg.value.prop === 'Type') types.push(selectedType(ast.conditions, arg.value.variable));
  }
  return types.filter(Boolean);
}

// Claim types a rule reads (inputs) and makes (outputs): from its fields,
// or from the parsed text of a custom rule. `issued` are the outputs that go
// into the token; add() only makes claims for later rules.
export function ruleIo(rule) {
  const inputs = (rule.conditions || []).map((c) => c.type).filter(Boolean);
  const outputs = [];
  const issued = [];
  if (rule.kind === 'claim') {
    if (rule.type) outputs.push(rule.type);
    issued.push(...outputs);
    if (rule.source === 'incoming' && rule.inputType) inputs.push(rule.inputType);
  } else if (rule.kind === 'lookup') {
    inputs.push(...rule.lookup.inputs.map((i) => i.type).filter(Boolean));
    outputs.push(...rule.lookup.outputs.map((o) => o.type).filter(Boolean));
    if (!rule.lookup.add) issued.push(...outputs);
  } else if (rule.kind === 'valuemap') {
    if (rule.valuemap.inputType) inputs.push(rule.valuemap.inputType);
    if (rule.valuemap.outputType) outputs.push(rule.valuemap.outputType);
    if (!rule.valuemap.add) issued.push(...outputs);
  } else if (rule.kind === 'raw') {
    for (const { ast } of parseRulesCached(rule.text)) {
      if (!ast) continue;
      const types = actionTypes(ast);
      outputs.push(...types);
      if (ast.action.verb === 'issue') issued.push(...types);
    }
  }
  return { inputs, outputs, issued };
}
