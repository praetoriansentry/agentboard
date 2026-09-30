import { describe, it, expect } from "vitest";
import { postBits, leadingZeroBits, checkPow, extractSpki, certToDer, isEd25519Spki, spkiKeyType, hex, sha256, postPayload } from "../src/crypto.js";
import aliceCert from "./fixtures/alice.cert.pem?raw";
import edCert from "./fixtures/ed.cert.pem?raw";
import rsaCert from "./fixtures/rsa.cert.pem?raw";

describe("postBits", () => {
  it("matches the spec table", () => {
    expect(postBits(1)).toBe(16);
    expect(postBits(256)).toBe(16);
    expect(postBits(257)).toBe(17);
    expect(postBits(512)).toBe(17);
    expect(postBits(513)).toBe(18);
    expect(postBits(1024)).toBe(18);
    expect(postBits(2048)).toBe(19);
    expect(postBits(4096)).toBe(20);
    expect(postBits(8192)).toBe(21);
    expect(postBits(16384)).toBe(22);
  });
});

describe("leadingZeroBits", () => {
  it("counts across bytes", () => {
    expect(leadingZeroBits(new Uint8Array([0x80]))).toBe(0);
    expect(leadingZeroBits(new Uint8Array([0x01]))).toBe(7);
    expect(leadingZeroBits(new Uint8Array([0x00, 0x00, 0x3f]))).toBe(18);
    expect(leadingZeroBits(new Uint8Array([0, 0, 0]))).toBe(24);
  });
});

describe("checkPow", () => {
  it("agrees with the int(H) < 2^(256-bits) formulation", async () => {
    const id = "ab".repeat(32);
    for (let n = 0; n < 200; n++) {
      const h = new Uint8Array(await sha256(new TextEncoder().encode(`agentboard-pow-v1:${id}:${n}`)));
      const big = BigInt("0x" + hex(h));
      for (const bits of [1, 4, 8, 9]) {
        expect(await checkPow(id, n, bits)).toBe(big < (1n << BigInt(256 - bits)));
      }
    }
  });
});

describe("extractSpki", () => {
  it("pulls the Ed25519 SPKI out of an openssl self-signed cert", async () => {
    const spki = extractSpki(certToDer(edCert));
    expect(isEd25519Spki(spki)).toBe(true);
    // openssl pkey -in ed.key.pem -pubout -outform DER | sha256sum
    expect(hex(await sha256(spki))).toBe("57251b3e1c5782315c3f1cda5b244c4291c0e5c221398567073d1cf51b772cd8");
  });
  it("pulls the P-256 SPKI out of an openssl self-signed cert", async () => {
    const spki = extractSpki(certToDer(aliceCert));
    expect(spkiKeyType(spki)?.name).toBe("P-256");
    expect(spki.length).toBe(91);
    // openssl pkey -in alice.key.pem -pubout -outform DER | sha256sum
    expect(hex(await sha256(spki))).toBe("b26fe09fe0b022d23c9fdb3313bd389d77f559de10e5c29a12f2f7b17f297467");
  });
  it("finds the SPKI of an RSA cert but flags it as unsupported", () => {
    const spki = extractSpki(certToDer(rsaCert));
    expect(spki[0]).toBe(0x30);
    expect(spkiKeyType(spki)).toBeNull();
  });
  it("rejects garbage", () => {
    expect(() => extractSpki(new Uint8Array([0x30, 0x82, 0xff]))).toThrow();
    expect(() => extractSpki(new Uint8Array([0x04, 0x02, 1, 2]))).toThrow();
    expect(() => extractSpki(new Uint8Array(0))).toThrow();
  });
});

describe("postPayload", () => {
  it("matches the Python reference byte-for-byte", async () => {
    // python3 -c 'import hashlib; print(hashlib.sha256(b"agentboard-post-v1\n" + b"a"*64 + b"\n\nprotocols\n2026-09-30T18:20:00Z\nhello\nworld").hexdigest())'
    const p = { author: "a".repeat(64), parent: "", topic: "protocols", created_at: "2026-09-30T18:20:00Z", body: "hello\nworld" };
    expect(hex(await sha256(postPayload(p)))).toBe("4a9be586aa5b4b2056e23cf661a0ddb8cbb56a22c3cdd15ca212ad6b07a6c257");
  });
});
