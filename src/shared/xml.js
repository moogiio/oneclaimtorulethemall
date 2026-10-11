// A small, strict XML reader for metadata files: elements, attributes,
// namespaces and text. No DOCTYPE and no entities beyond the five built-in
// ones, so nothing can expand or reach outside the text. Pure ESM, shared
// between browser and server (Node has no DOMParser).

export const XMLNS = 'http://www.w3.org/2000/xmlns/';
const XML_NS = 'http://www.w3.org/XML/1998/namespace';
const MAX_DEPTH = 64;

export class XmlError extends Error {}
const fail = (message) => { throw new XmlError(message); };
export const NOT_XML = 'This is not a valid XML file';

const ENTITIES = new Map([['lt', '<'], ['gt', '>'], ['amp', '&'], ['quot', '"'], ['apos', "'"]]);

// Characters XML allows; the workspace takes no control characters either.
const xmlChar = (code) => code === 9 || code === 10 || code === 13 || (code >= 0x20 && code <= 0xd7ff && code !== 0x7f)
  || (code >= 0xe000 && code <= 0xfffd) || (code >= 0x10000 && code <= 0x10ffff);

// Text with its entities (&amp; &#38; &#x26;) decoded. A bare & is not XML.
function decode(text) {
  return text.replace(/&(?:([^;&\s]{1,10});)?/g, (whole, name) => {
    if (name === undefined) fail(NOT_XML);
    if (ENTITIES.has(name)) return ENTITIES.get(name);
    const m = /^#(?:x([0-9a-f]{1,6})|([0-9]{1,7}))$/i.exec(name);
    const code = m ? parseInt(m[1] || m[2], m[1] ? 16 : 10) : NaN;
    if (!xmlChar(code)) fail(NOT_XML);
    return String.fromCodePoint(code);
  });
}

// The attributes of a start tag ("a='1' b=\"2\""), or throws.
function readAttributes(body) {
  const attrs = [];
  const re = /\s+([^\s=/<>"']+)\s*=\s*(?:"([^"<]*)"|'([^'<]*)')/y;
  let at = 0;
  for (let m = re.exec(body); m; m = re.exec(body)) {
    attrs.push([m[1], decode(m[2] ?? m[3])]);
    at = re.lastIndex;
  }
  if (body.slice(at).trim()) fail(NOT_XML);
  return attrs;
}

export function splitName(qname) {
  const i = qname.indexOf(':');
  return i === -1 ? ['', qname] : [qname.slice(0, i), qname.slice(i + 1)];
}

// Namespace declarations live in prototype-free maps, so a prefix like
// "constructor" is only known when the file declares it.
function newElement(qname, attrs, parent, start) {
  const scope = Object.assign(Object.create(null), parent.scope || { xml: XML_NS });
  const declares = Object.create(null);
  for (const [name, value] of attrs) {
    if (name === 'xmlns') declares[''] = value;
    else if (name.startsWith('xmlns:')) declares[name.slice(6)] = value;
  }
  Object.assign(scope, declares);
  const [prefix, local] = splitName(qname);
  if (prefix && !(prefix in scope)) fail(NOT_XML);
  const resolved = attrs.map(([name, value]) => {
    const [p, l] = splitName(name);
    if (name === 'xmlns' || p === 'xmlns') return { ns: XMLNS, local: l, value };
    if (p && !(p in scope)) fail(NOT_XML);
    return { ns: p ? scope[p] : '', local: l, value };
  });
  return {
    qname, ns: scope[prefix] || '', local, attrs: resolved, scope, declares, children: [], text: '', start, end: start,
  };
}

// The root element of `text`, as { qname, ns, local, attrs, scope, declares,
// children, text, start, end }: `start` and `end` are where the element is
// in `text`. Comments and processing instructions are skipped.
export function parseXml(text) {
  const doc = { children: [] };
  const stack = [doc];
  let i = 0;
  const need = (at) => (at === -1 ? fail(NOT_XML) : at);
  while (i < text.length) {
    const lt = text.indexOf('<', i);
    const end = lt === -1 ? text.length : lt;
    const top = stack[stack.length - 1];
    if (end > i) {
      const chunk = text.slice(i, end);
      if (top === doc) {
        if (chunk.trim()) fail(NOT_XML);
      } else {
        top.text += decode(chunk);
      }
    }
    if (lt === -1) break;
    if (text.startsWith('<!--', lt)) {
      i = need(text.indexOf('-->', lt + 4)) + 3;
    } else if (text.startsWith('<![CDATA[', lt)) {
      const close = need(text.indexOf(']]>', lt));
      if (top === doc) fail(NOT_XML);
      top.text += text.slice(lt + 9, close);
      i = close + 3;
    } else if (text.startsWith('<?', lt)) {
      i = need(text.indexOf('?>', lt)) + 2;
    } else if (text.startsWith('<!', lt)) {
      fail('The file has a DOCTYPE, which AD FS does not accept in metadata');
    } else if (text[lt + 1] === '/') {
      const close = need(text.indexOf('>', lt));
      if (top === doc || text.slice(lt + 2, close).trim() !== top.qname) fail(NOT_XML);
      top.end = close + 1;
      stack.pop();
      i = close + 1;
    } else {
      // A start tag ends at the first > outside quotes.
      let close = lt + 1;
      let quote = '';
      for (; close < text.length; close++) {
        const ch = text[close];
        if (quote) {
          if (ch === quote) quote = '';
        } else if (ch === '"' || ch === "'") {
          quote = ch;
        } else if (ch === '>') {
          break;
        }
      }
      if (close >= text.length) fail(NOT_XML);
      let body = text.slice(lt + 1, close);
      const empty = body.endsWith('/');
      if (empty) body = body.slice(0, -1);
      const name = /^[^\s/<>"'=]+/.exec(body);
      if (!name) fail(NOT_XML);
      if (top === doc && doc.children.length) fail(NOT_XML);
      const element = newElement(name[0], readAttributes(body.slice(name[0].length)), top, lt);
      top.children.push(element);
      if (empty) {
        element.end = close + 1;
      } else {
        if (stack.length > MAX_DEPTH) fail('The file is nested too deeply to be metadata');
        stack.push(element);
      }
      i = close + 1;
    }
  }
  if (stack.length !== 1 || doc.children.length !== 1) fail(NOT_XML);
  return doc.children[0];
}

export const attr = (el, local, ns = '') => {
  const found = el.attrs.find((a) => a.local === local && a.ns === ns);
  return found ? found.value : '';
};
export const kids = (el, ns, local) => el.children.filter((c) => c.ns === ns && c.local === local);
export const kid = (el, ns, local) => kids(el, ns, local)[0];

// xs:boolean: "true" or "1".
export const isTrue = (value) => value === 'true' || value === '1';
export const isFalse = (value) => value === 'false' || value === '0';

const escapeAttr = (value) => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');

// The text of `el` on its own, with the namespaces its ancestors declared
// (and `el` does not) added to its start tag, so it reads the same.
export function standalone(text, el) {
  const inherited = Object.entries(el.scope).filter(([prefix, uri]) => prefix !== 'xml' && !(prefix in el.declares) && uri);
  const extra = inherited.map(([prefix, uri]) => ` ${prefix ? `xmlns:${prefix}` : 'xmlns'}="${escapeAttr(uri)}"`).join('');
  const nameEnd = el.start + 1 + el.qname.length;
  return `${text.slice(el.start, nameEnd)}${extra}${text.slice(nameEnd, el.end)}`;
}
