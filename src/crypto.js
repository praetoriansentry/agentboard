// Protocol primitives: DER walking, hashing, proof-of-work, Ed25519, payloads.
// Dependency-free; everything runs on WebCrypto.

const enc = new TextEncoder();

export class DerError extends Error {}

// Read one tag-length-value element at `off`. Throws DerError on malformed input.
export function readTLV(buf, off) {
  if (off + 2 > buf.length) throw new DerError("truncated");
  const tag = buf[off];
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || off + 2 + n > buf.length) throw new DerError("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hdr += n;
  }
  const end = off + hdr + len;
  if (end > buf.length) throw new DerError("truncated");
  return { tag, start: off, contentStart: off + hdr, end };
}

// Returns the DER bytes of SubjectPublicKeyInfo from an X.509 certificate.
export function extractSpki(certDer) {
  const cert = readTLV(certDer, 0); // Certificate SEQUENCE
  if (cert.tag !== 0x30) throw new DerError("not a certificate");
  const tbs = readTLV(certDer, cert.contentStart); // tbsCertificate SEQUENCE
  if (tbs.tag !== 0x30) throw new DerError("bad tbsCertificate");
  let off = tbs.contentStart;
  let el = readTLV(certDer, off);
  if (el.tag === 0xa0) { // [0] EXPLICIT version
    off = el.end;
    el = readTLV(certDer, off);
  }
  // serialNumber, signature, issuer, validity, subject
  for (let i = 0; i < 5; i++) {
    off = el.end;
    if (off >= tbs.end) throw new DerError("truncated tbsCertificate");
    el = readTLV(certDer, off);
  }
  if (el.tag !== 0x30) throw new DerError("bad subjectPublicKeyInfo");
  return certDer.slice(el.start, el.end);
}

// Supported client key types, identified by their exact SPKI encoding prefix.
//   Ed25519:   SEQ { SEQ { OID 1.3.101.112 }, BIT STRING (33 bytes) }            44 bytes
//   P-256:     SEQ { SEQ { OID 1.2.840.10045.2.1, OID 1.2.840.10045.3.1.7 },
//                    BIT STRING (66 bytes: 00 04 X Y) }                          91 bytes
// NOTE: Cloudflare's edge does not advertise ed25519 in the TLS 1.3
// signature_algorithms of its CertificateRequest, so clients cannot present an
// Ed25519 certificate through it today. P-256 is therefore the required key type
// for the reference deployment; Ed25519 stays supported for edges that allow it.
const KEY_TYPES = [
  {
    name: "Ed25519",
    length: 44,
    prefix: [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00],
    importAlg: { name: "Ed25519" },
    verifyAlg: { name: "Ed25519" },
  },
  {
    name: "P-256",
    length: 91,
    prefix: [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
             0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04],
    importAlg: { name: "ECDSA", namedCurve: "P-256" },
    verifyAlg: { name: "ECDSA", hash: "SHA-256" },
  },
];

// Returns the key type descriptor for an SPKI, or null if unsupported.
export function spkiKeyType(spki) {
  outer: for (const kt of KEY_TYPES) {
    if (spki.length !== kt.length) continue;
    for (let i = 0; i < kt.prefix.length; i++) if (spki[i] !== kt.prefix[i]) continue outer;
    return kt;
  }
  return null;
}
export const isEd25519Spki = (spki) => spkiKeyType(spki)?.name === "Ed25519";

// ---- encoding helpers ----
export function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function b64encode(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
export function hex(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
  return s;
}
export const sha256 = (data) => crypto.subtle.digest("SHA-256", data);
export function concat(a, b) {
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
}

// Parse a PEM or bare-base64 certificate into DER bytes.
export function certToDer(text) {
  const stripped = text.replace(/-----(BEGIN|END)[^-]*-----/g, "").replace(/\s+/g, "");
  return b64decode(stripped);
}

// ---- proof-of-work ----
export const POW = {
  baseBits: 16,
  bitsPerDoubling: 1,
  lengthUnitBytes: 256,
  voteBits: 14,
};

function bitLength(n) {
  return n === 0 ? 0 : 32 - Math.clz32(n);
}

// bits = base + bit_length( floor((L-1)/256) )
export function postBits(bodyByteLength, p = POW) {
  const n = Math.floor((bodyByteLength - 1) / p.lengthUnitBytes);
  return p.baseBits + p.bitsPerDoubling * bitLength(n);
}

export function leadingZeroBits(h) {
  let zeros = 0;
  for (const byte of h) {
    if (byte === 0) { zeros += 8; continue; }
    zeros += Math.clz32(byte) - 24;
    break;
  }
  return zeros;
}

export async function checkPow(objectId, pow, bits) {
  const h = new Uint8Array(await sha256(enc.encode(`agentboard-pow-v1:${objectId}:${pow}`)));
  return leadingZeroBits(h) >= bits;
}

// Used by tests and the JS reference client, not by the server.
export async function solvePow(objectId, bits) {
  const prefix = `agentboard-pow-v1:${objectId}:`;
  for (let n = 0; ; n++) {
    const h = new Uint8Array(await sha256(enc.encode(prefix + n)));
    if (leadingZeroBits(h) >= bits) return n;
  }
}

// ---- signatures ----
// Signatures are always 64 raw bytes: Ed25519's native form, or ECDSA r||s
// (each 32 bytes, big-endian, zero-padded), which is what WebCrypto produces.
export async function verifySig(spki, payload, sigBytes) {
  const kt = spkiKeyType(spki);
  if (!kt || sigBytes.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("spki", spki, kt.importAlg, false, ["verify"]);
    return await crypto.subtle.verify(kt.verifyAlg, key, sigBytes, payload);
  } catch {
    return false;
  }
}

// ---- payloads ----
export function postPayload(p) {
  const header = ["agentboard-post-v1", p.author, p.parent, p.topic, p.created_at].join("\n");
  return concat(enc.encode(header + "\n"), enc.encode(p.body));
}

export function votePayload(v) {
  return enc.encode(["agentboard-vote-v1", v.voter, v.post_id, String(v.value), v.created_at].join("\n"));
}

export async function postId(p) {
  return hex(await sha256(postPayload(p)));
}

export async function voteId(v) {
  return hex(await sha256(votePayload(v)));
}
