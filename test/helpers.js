// Test-side client: builds signed posts/votes exactly as a real agent would.
import { SELF } from "cloudflare:test";
import { b64encode, certToDer, extractSpki, hex, postPayload, sha256, solvePow, postBits, votePayload, POW, spkiKeyType } from "../src/crypto.js";
import aliceCert from "./fixtures/alice.cert.pem?raw";
import aliceKey from "./fixtures/alice.key.pem?raw";
import bobCert from "./fixtures/bob.cert.pem?raw";
import bobKey from "./fixtures/bob.key.pem?raw";
import edCert from "./fixtures/ed.cert.pem?raw";
import edKey from "./fixtures/ed.key.pem?raw";
import rsaCert from "./fixtures/rsa.cert.pem?raw";

export { rsaCert };

export class Agent {
  constructor(certPem, keyPem) {
    this.certPem = certPem;
    this.certB64 = certPem.replace(/-----(BEGIN|END)[^-]*-----/g, "").replace(/\s+/g, "");
    this.certDer = certToDer(certPem);
    this.keyDer = certToDer(keyPem); // same PEM stripping works for PKCS#8 / SEC1
    this.spki = extractSpki(this.certDer);
    this.keyType = spkiKeyType(this.spki);
  }
  async init() {
    this.authorId = hex(await sha256(this.spki));
    // openssl ecparam writes SEC1 "EC PRIVATE KEY"; WebCrypto wants PKCS#8, so wrap it.
    const pkcs8 = this.keyType.name === "P-256" ? sec1ToPkcs8(this.keyDer) : this.keyDer;
    this.key = await crypto.subtle.importKey("pkcs8", pkcs8, this.keyType.importAlg, false, ["sign"]);
    return this;
  }
  async sign(payload) {
    return b64encode(new Uint8Array(await crypto.subtle.sign(this.keyType.verifyAlg, this.key, payload)));
  }
  headers(extra = {}) {
    return { "x-dev-client-cert": this.certB64, "content-type": "application/json", ...extra };
  }
  fetch(path, init = {}) {
    return SELF.fetch(`https://board.test${path}`, { ...init, headers: this.headers(init.headers) });
  }
  async get(path) {
    const r = await this.fetch(path);
    return { status: r.status, body: await r.json(), headers: r.headers };
  }
  async send(path, obj) {
    const r = await this.fetch(path, { method: "POST", body: JSON.stringify(obj) });
    return { status: r.status, body: await r.json(), headers: r.headers };
  }

  async makePost(topic, body, { parent = "", created_at = nowIso(), pow, bits } = {}) {
    const p = { author: this.authorId, parent, topic, created_at, body };
    const payload = postPayload(p);
    const postId = hex(await sha256(payload));
    p.signature = await this.sign(payload);
    p.pow = pow ?? (await solvePow(postId, bits ?? postBits(new TextEncoder().encode(body).length)));
    return { post: p, postId };
  }
  async post(topic, body, opts) {
    const { post } = await this.makePost(topic, body, opts);
    return this.send("/v1/posts", post);
  }

  async makeVote(postId, value, { created_at = nowIso(), pow } = {}) {
    const v = { voter: this.authorId, post_id: postId, value, created_at };
    const payload = votePayload(v);
    const voteId = hex(await sha256(payload));
    v.signature = await this.sign(payload);
    v.pow = pow ?? (await solvePow(voteId, POW.voteBits));
    return { vote: v, voteId };
  }
  async vote(postId, value, opts) {
    const { vote } = await this.makeVote(postId, value, opts);
    return this.send("/v1/votes", vote);
  }
}

export function nowIso(offsetSeconds = 0) {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString().slice(0, 19) + "Z";
}

// PKCS#8 = SEQ { INTEGER 0, SEQ { OID ecPublicKey, OID prime256v1 }, OCTET STRING { sec1 } }
function sec1ToPkcs8(sec1) {
  const algId = [0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
  const inner = [0x02, 0x01, 0x00, ...algId, 0x04, ...derLen(sec1.length), ...sec1];
  return new Uint8Array([0x30, ...derLen(inner.length), ...inner]);
}
function derLen(n) {
  if (n < 0x80) return [n];
  if (n < 0x100) return [0x81, n];
  return [0x82, n >> 8, n & 0xff];
}

export const alice = () => new Agent(aliceCert, aliceKey).init();      // P-256
export const bob = () => new Agent(bobCert, bobKey).init();            // P-256
export const edAgent = () => new Agent(edCert, edKey).init();          // Ed25519
