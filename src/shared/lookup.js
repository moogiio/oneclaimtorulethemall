// "Look up in an attribute store": a rule that needs several claims of the
// user, asks an attribute store with their values, and sends what the store
// returns as claims. In claim rule language that is a custom rule with
// store, types, query and param; here it is built by clicking. Pure ESM.
import { AD_STORE, claimTypeLabel } from './catalog.js';
import { newId } from './model.js';

// The stores a lookup can ask. Only Active Directory is built in; the
// others are added in AD FS Management (Service, Attribute Stores).
export const LOOKUP_STORES = [
  {
    key: 'ad',
    label: 'Active Directory',
    help: 'The query is ;mail,displayName;{0}: the AD attributes to read between two semicolons, then {0}, the user as DOMAIN\\name. '
      + 'Send one claim type below per attribute, in the same order.',
    example: ';mail,displayName;{0}',
  },
  {
    key: 'sql',
    label: 'SQL store',
    help: 'A SQL attribute store runs the query as SQL. {0}, {1} and so on are the values below, in order. '
      + 'Send one claim type below per column the query returns, in the same order.',
    example: 'SELECT role FROM users WHERE account = {0}',
  },
  {
    key: 'other',
    label: 'Another store',
    help: 'An attribute store added in AD FS (an LDAP or custom store). The store decides the query format; '
      + '{0}, {1} and so on usually stand for the values below, in order.',
    example: '',
  },
];

export const lookupStore = (key) => LOOKUP_STORES.find((s) => s.key === key) || LOOKUP_STORES[0];

export const newLookupInput = (type = '') => ({
  id: newId('k'), type, issuer: '', value: '',
});

export const newLookupParam = (input = '') => ({
  id: newId('k'), input, transform: 'none', prefix: '', pattern: '', replacement: '',
});

export const newLookupOutput = (type = '') => ({ id: newId('k'), type });

// The lookup part of a new "Look up in an attribute store" rule: one claim
// to start from and one claim to send, asking Active Directory.
export function newLookup() {
  const input = newLookupInput('http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname');
  input.issuer = 'AD AUTHORITY';
  return {
    storeKind: 'ad',
    store: AD_STORE,
    query: '',
    inputs: [input],
    params: [newLookupParam(input.id)],
    outputs: [newLookupOutput()],
    add: false,
  };
}

// The {0}, {1} placeholders a query uses, as numbers.
export function queryPlaceholders(query) {
  return [...new Set([...String(query || '').matchAll(/\{(\d+)\}/g)].map((m) => Number(m[1])))].sort((a, b) => a - b);
}

// The AD attributes an Active Directory query reads (";mail,sn;{0}").
export function adQueryAttributes(query) {
  const parts = String(query || '').split(';');
  return parts.length === 3 ? parts[1].split(',').map((a) => a.trim()).filter(Boolean) : null;
}

// The name of input `id` in the rule text: c1, c2 in the order of the inputs.
export const inputVariable = (lookup, id) => `c${lookup.inputs.findIndex((i) => i.id === id) + 1}`;

const list = (items) => (items.length > 1 ? `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}` : items[0] || '');

function paramText(lookup, param) {
  const input = lookup.inputs.find((i) => i.id === param.input);
  const name = input ? claimTypeLabel(input.type) || input.type || 'a claim' : 'a claim';
  if (param.transform === 'prefix') return `${name} with "${param.prefix}" in front`;
  if (param.transform === 'regex') return `${name} with ${param.pattern} replaced by "${param.replacement}"`;
  return name;
}

// A short line for rule cards: "Asks Active Directory · sends E-Mail Address".
export function lookupSubtitle(l) {
  const store = l.storeKind === 'ad' ? 'Active Directory' : l.store || 'an attribute store (no name yet)';
  const n = l.outputs.length;
  const what = n === 1 ? claimTypeLabel(l.outputs[0].type) || 'a claim (no claim type yet)' : `${n} claim types`;
  return `Asks ${store} · ${l.add ? 'keeps' : 'sends'} ${what}`;
}

// The lookup in plain words.
export function explainLookup(rule) {
  const l = rule.lookup;
  const store = l.storeKind === 'ad' ? 'Active Directory' : `the attribute store "${l.store || '(no name yet)'}"`;
  const values = l.params.map((p) => paramText(l, p));
  const sends = l.outputs.map((o) => claimTypeLabel(o.type) || o.type).filter(Boolean);
  const needs = l.inputs.filter((i) => i.type).map((i) => {
    const checks = [i.value && `the value ${i.value}`, i.issuer && `from ${i.issuer}`].filter(Boolean);
    return `a ${claimTypeLabel(i.type) || i.type} claim${checks.length ? ` (${checks.join(', ')})` : ''}`;
  });
  let text = `Asks ${store}${values.length ? ` with ${list(values)}` : ''}`;
  text += sends.length ? `, and ${l.add ? 'keeps' : 'sends'} what it returns as ${list(sends)}` : ', but sends nothing yet';
  if (l.add) text += ' for the rules after it (it is not sent to the application)';
  if (needs.length) text += `. Only for users with ${list(needs)}`;
  return `${text}.`;
}
