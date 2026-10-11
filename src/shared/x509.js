// The validity dates of an X.509 certificate, as metadata carries it
// (base64 DER in ds:X509Certificate). Only reads; nothing is verified. Pure
// ESM, shared between browser and server.

class DerError extends Error {}
const fail = () => { throw new DerError('not a certificate'); };

// One DER element at `pos`: { tag, start, end } of its content.
function element(bytes, pos) {
  if (pos + 2 > bytes.length) fail();
  const tag = bytes[pos];
  let length = bytes[pos + 1];
  let start = pos + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n < 1 || n > 4) fail();
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + bytes[start++];
  }
  if (start + length > bytes.length) fail();
  return { tag, start, end: start + length };
}

const SEQUENCE = 0x30;
const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;

// UTCTime "YYMMDDHHMMSSZ" (YY of 50 and up is 19YY) or GeneralizedTime
// "YYYYMMDDHHMMSSZ", as a Date.
function readTime(bytes, el) {
  const text = String.fromCharCode(...bytes.subarray(el.start, el.end));
  const m = el.tag === UTC_TIME ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text)
    : el.tag === GENERALIZED_TIME && /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (!m) fail();
  let year = Number(m[1]);
  if (el.tag === UTC_TIME) year += year >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
}

// { notBefore, notAfter } as Dates, or null when `base64` is not a certificate.
export function certificateDates(base64) {
  try {
    const binary = atob(String(base64 || '').replace(/\s+/g, ''));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const cert = element(bytes, 0);
    const tbs = element(bytes, cert.start);
    if (cert.tag !== SEQUENCE || tbs.tag !== SEQUENCE) fail();
    // tbsCertificate: [0] version (optional), serial, signature, issuer, validity.
    let at = element(bytes, tbs.start);
    if (at.tag === 0xa0) at = element(bytes, at.end);
    for (let i = 0; i < 3; i++) at = element(bytes, at.end);
    if (at.tag !== SEQUENCE) fail();
    const notBefore = element(bytes, at.start);
    const notAfter = element(bytes, notBefore.end);
    return { notBefore: readTime(bytes, notBefore), notAfter: readTime(bytes, notAfter) };
  } catch (err) {
    if (err instanceof DerError || err instanceof DOMException || err instanceof RangeError) return null;
    throw err;
  }
}
