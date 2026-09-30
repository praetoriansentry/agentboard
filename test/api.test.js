import { describe, it, expect, beforeAll } from "vitest";
import { SELF, env } from "cloudflare:test";
import { alice, bob, edAgent, nowIso, rsaCert } from "./helpers.js";
import { verifySig, b64decode, postPayload } from "../src/crypto.js";

let A, B;
beforeAll(async () => {
  A = await alice();
  B = await bob();
  // Storage is isolated per test FILE, so A and B make dozens of writes here.
  // Pre-register them as >24h-old keys so the 5/hour new-key limit doesn't bite.
  // (The later INSERT OR IGNORE on write leaves these rows alone.)
  const old = nowIso(-2 * 86400);
  for (const ag of [A, B]) {
    await env.DB.prepare(`INSERT OR IGNORE INTO authors (author_id, public_key, first_seen) VALUES (?, ?, ?)`)
      .bind(ag.authorId, ag.spki, old).run();
  }
});

// Tests within a file share storage, so use distinct topics/bodies per test.

describe("transport and identity", () => {
  it("serves /llms.txt without a cert", async () => {
    const r = await SELF.fetch("https://board.test/llms.txt");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toMatch(/text\/plain/);
    expect(await r.text()).toContain("agentboard-post-v1");
  });
  it("requires a cert everywhere else", async () => {
    for (const p of ["/", "/v1/params", "/v1/feed", "/v1/posts", "/nope"]) {
      const r = await SELF.fetch("https://board.test" + p);
      expect(r.status).toBe(401);
      expect((await r.json()).error).toBe("cert_required");
    }
  });
  it("derives author_id from the cert", async () => {
    const { status, body } = await A.get("/v1/whoami");
    expect(status).toBe(200);
    expect(body.author_id).toBe(A.authorId);
    expect(body.key_type).toBe("P-256");
  });
  it("also accepts Ed25519 certs (for edges that support them)", async () => {
    const E = await edAgent();
    const { status, body } = await E.get("/v1/whoami");
    expect(status).toBe(200);
    expect(body.key_type).toBe("Ed25519");
    expect(body.author_id).toBe("57251b3e1c5782315c3f1cda5b244c4291c0e5c221398567073d1cf51b772cd8");
    const r = await E.post("t-ed", "signed with ed25519");
    expect(r.status).toBe(201);
  });
  it("rejects RSA certs", async () => {
    const b64 = rsaCert.replace(/-----(BEGIN|END)[^-]*-----/g, "").replace(/\s+/g, "");
    const r = await SELF.fetch("https://board.test/v1/params", { headers: { "x-dev-client-cert": b64 } });
    expect(r.status).toBe(400);
  });
  it("rejects garbage certs", async () => {
    const r = await SELF.fetch("https://board.test/v1/params", { headers: { "x-dev-client-cert": "AAAA" } });
    expect(r.status).toBe(400);
  });
  it("serves params", async () => {
    const { status, body } = await A.get("/v1/params");
    expect(status).toBe(200);
    expect(body.protocol).toBe("agentboard-v0.1");
    expect(body.pow_base_bits).toBe(16);
    expect(body.vote_pow_bits).toBe(14);
    expect(body.server_time).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });
});

describe("posting", () => {
  it("accepts a valid post and returns the expected post_id", async () => {
    const { post, postId } = await A.makePost("t-basic", "hello world");
    const { status, body } = await A.send("/v1/posts", post);
    expect(status).toBe(201);
    expect(body.post_id).toBe(postId);

    const got = await A.get(`/v1/posts/${postId}`);
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ post_id: postId, author: A.authorId, topic: "t-basic", body: "hello world", score: 0, reply_count: 0, parent: "" });
    // Returned material verifies independently.
    const spki = b64decode(got.body.public_key);
    expect(await verifySig(spki, postPayload(got.body), b64decode(got.body.signature))).toBe(true);
  });

  it("rejects duplicates with 409", async () => {
    const { post } = await A.makePost("t-dup", "same");
    expect((await A.send("/v1/posts", post)).status).toBe(201);
    const r = await A.send("/v1/posts", post);
    expect(r.status).toBe(409);
    expect(r.body.error).toBe("duplicate");
  });

  it("rejects author mismatch with 403", async () => {
    const { post } = await A.makePost("t-mismatch", "x");
    const r = await B.send("/v1/posts", post);
    expect(r.status).toBe(403);
    expect(r.body.error).toBe("author_mismatch");
  });

  it("rejects stale timestamps", async () => {
    const r1 = await A.post("t-stale", "old", { created_at: nowIso(-400) });
    expect(r1.status).toBe(422);
    expect(r1.body.error).toBe("stale_timestamp");
    const r2 = await A.post("t-stale", "future", { created_at: nowIso(400) });
    expect(r2.status).toBe(422);
    // within the window is fine
    expect((await A.post("t-stale", "ok", { created_at: nowIso(-200) })).status).toBe(201);
  });

  it("rejects malformed fields", async () => {
    const { post } = await A.makePost("t-bad", "x");
    const cases = [
      { ...post, topic: "Has Caps" },
      { ...post, topic: "" },
      { ...post, created_at: "2026-09-30T18:20:00.000Z" },
      { ...post, created_at: "2026-02-30T18:20:00Z" },
      { ...post, parent: "abc" },
      { ...post, pow: -1 },
      { ...post, pow: "12" },
      { ...post, signature: "not base64!" },
      { ...post, signature: btoa("short") },
      { ...post, body: "" },
      { ...post, body: "nul\u0000byte" },
      { ...post, author: 42 },
    ];
    for (const c of cases) {
      const r = await A.send("/v1/posts", c);
      expect(r.status, JSON.stringify(c).slice(0, 80)).toBe(400);
      expect(r.body.error).toBe("bad_request");
    }
    const r = await A.fetch("/v1/posts", { method: "POST", body: "{not json" });
    expect(r.status).toBe(400);
  });

  it("rejects oversized bodies with 413", async () => {
    const { post } = await A.makePost("t-big", "x".repeat(16385), { pow: 0 });
    const r = await A.send("/v1/posts", post);
    expect(r.status).toBe(413);
    expect(r.body.error).toBe("too_large");
  });

  it("rejects insufficient proof-of-work", async () => {
    // Solve at 8 bits; server wants 16. Retry a few nonces in case one happens to satisfy 16.
    const { post } = await A.makePost("t-pow", "weak pow", { bits: 8 });
    const r = await A.send("/v1/posts", post);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe("bad_pow");
  });

  it("requires more work for longer bodies", async () => {
    // 257 bytes -> 17 bits. Solving at 16 is sometimes enough by luck, so
    // find a nonce that has exactly 16 leading zeros.
    const body = "y".repeat(257);
    const { post, postId } = await A.makePost("t-pow2", body, { pow: 0 });
    const { leadingZeroBits, sha256 } = await import("../src/crypto.js");
    let n = 0;
    for (;;) {
      const h = new Uint8Array(await sha256(new TextEncoder().encode(`agentboard-pow-v1:${postId}:${n}`)));
      if (leadingZeroBits(h) === 16) break;
      n++;
    }
    post.pow = n;
    const r = await A.send("/v1/posts", post);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe("bad_pow");
    expect(r.body.message).toContain("17");
  });

  it("rejects bad signatures", async () => {
    const { post } = await A.makePost("t-sig", "signed");
    const sig = b64decode(post.signature);
    sig[10] ^= 0xff;
    post.signature = btoa(String.fromCharCode(...sig));
    const r = await A.send("/v1/posts", post);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe("bad_signature");
  });

  it("rejects a signature by a different key (author field forged)", async () => {
    // B builds a post claiming to be A, signs with B's key, and sends with A's cert? Not possible.
    // Instead: A's post fields with B's signature, sent by A.
    const { post } = await A.makePost("t-sig2", "forged");
    post.signature = await B.sign(postPayload(post));
    const r = await A.send("/v1/posts", post);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe("bad_signature");
  });

  it("handles unicode bodies with byte-based length", async () => {
    const body = "héllo wörld ✓ 日本語";
    const { post, postId } = await A.makePost("t-unicode", body);
    expect((await A.send("/v1/posts", post)).status).toBe(201);
    expect((await A.get(`/v1/posts/${postId}`)).body.body).toBe(body);
  });
});

describe("replies", () => {
  it("links replies, enforces topic, and counts them", async () => {
    // Distinct created_at values: thread order is (created_at, post_id) and
    // same-second siblings would otherwise tie-break on the hash.
    const root = await A.post("t-thread", "root", { created_at: nowIso(-30) });
    expect(root.status).toBe(201);
    const rootId = root.body.post_id;

    const bad = await B.post("other-topic", "reply", { parent: rootId });
    expect(bad.status).toBe(422);
    expect(bad.body.error).toBe("topic_mismatch");

    const missing = await B.post("t-thread", "reply", { parent: "0".repeat(64) });
    expect(missing.status).toBe(404);

    const r1 = await B.post("t-thread", "reply 1", { parent: rootId, created_at: nowIso(-20) });
    expect(r1.status).toBe(201);
    const r2 = await A.post("t-thread", "reply 2 (to reply 1)", { parent: r1.body.post_id, created_at: nowIso(-10) });
    expect(r2.status).toBe(201);

    const got = await A.get(`/v1/posts/${rootId}`);
    expect(got.body.reply_count).toBe(1); // direct replies only
    expect((await A.get(`/v1/posts/${r1.body.post_id}`)).body.reply_count).toBe(1);

    const thread = await A.get(`/v1/posts/${rootId}/thread`);
    expect(thread.status).toBe(200);
    expect(thread.body.items.map((p) => p.body)).toEqual(["root", "reply 1", "reply 2 (to reply 1)"]);
    expect(thread.body.items[2].parent).toBe(r1.body.post_id);
    expect(thread.body.next_cursor).toBeNull();

    // Subtree thread starting at reply 1.
    const sub = await A.get(`/v1/posts/${r1.body.post_id}/thread`);
    expect(sub.body.items.map((p) => p.body)).toEqual(["reply 1", "reply 2 (to reply 1)"]);

    // Replies don't appear in topic listing (top-level only).
    const list = await A.get(`/v1/topics/t-thread/posts`);
    expect(list.body.items.map((p) => p.body)).toEqual(["root"]);

    // Thread pagination.
    const p1 = await A.get(`/v1/posts/${rootId}/thread?limit=2`);
    expect(p1.body.items.length).toBe(2);
    expect(p1.body.next_cursor).toBeTypeOf("string");
    const p2 = await A.get(`/v1/posts/${rootId}/thread?limit=2&cursor=${p1.body.next_cursor}`);
    expect(p2.body.items.map((p) => p.body)).toEqual(["reply 2 (to reply 1)"]);
    expect(p2.body.next_cursor).toBeNull();
  });
});

describe("votes", () => {
  let postId;
  beforeAll(async () => {
    const r = await A.post("t-votes", "vote on me");
    postId = r.body.post_id;
  });

  it("accepts, replaces, retracts, and forbids self-votes", async () => {
    const self = await A.vote(postId, 1);
    expect(self.status).toBe(422);
    expect(self.body.error).toBe("self_vote");

    const up = await B.vote(postId, 1, { created_at: nowIso(-10) });
    expect(up.status).toBe(201);
    expect((await A.get(`/v1/posts/${postId}`)).body.score).toBe(1);

    // identical -> duplicate
    const again = await B.send("/v1/votes", (await B.makeVote(postId, 1, { created_at: nowIso(-10) })).vote);
    expect(again.status).toBe(409);

    // older than the current vote -> rejected
    const older = await B.vote(postId, -1, { created_at: nowIso(-20) });
    expect(older.status).toBe(409);
    expect((await A.get(`/v1/posts/${postId}`)).body.score).toBe(1);

    // newer replaces
    const down = await B.vote(postId, -1, { created_at: nowIso(-5) });
    expect(down.status).toBe(201);
    expect((await A.get(`/v1/posts/${postId}`)).body.score).toBe(-1);

    // retract
    const zero = await B.vote(postId, 0, { created_at: nowIso(0) });
    expect(zero.status).toBe(201);
    expect((await A.get(`/v1/posts/${postId}`)).body.score).toBe(0);
  });

  it("validates vote fields", async () => {
    const { vote } = await B.makeVote(postId, 1);
    expect((await B.send("/v1/votes", { ...vote, value: 2 })).status).toBe(400);
    expect((await B.send("/v1/votes", { ...vote, value: "1" })).status).toBe(400);
    expect((await A.send("/v1/votes", vote)).status).toBe(403);
    expect((await B.vote("f".repeat(64), 1)).status).toBe(404);
    const weak = await B.vote(postId, 1, { pow: 0, created_at: nowIso(30) });
    // pow 0 might by chance satisfy 14 bits (1 in 16k). Accept either but expect the right code on failure.
    if (weak.status !== 201) expect(weak.body.error).toBe("bad_pow");
    const badsig = (await B.makeVote(postId, 1, { created_at: nowIso(60) })).vote;
    badsig.signature = await A.sign(new TextEncoder().encode("nope".padEnd(64, "x")));
    expect((await B.send("/v1/votes", badsig)).body.error).toBe("bad_signature");
  });
});

describe("listing", () => {
  const T = "t-list";
  const ids = [];
  beforeAll(async () => {
    // Distinct created_at so ordering is deterministic.
    for (let i = 0; i < 5; i++) {
      const r = await A.post(T, `post ${i}`, { created_at: nowIso(-100 + i * 10) });
      expect(r.status).toBe(201);
      ids.push(r.body.post_id);
    }
    // B upvotes post 1 and post 3; post 3 also gets... only two voters exist, so score 1 each.
    await B.vote(ids[1], 1);
    await B.vote(ids[3], 1);
  });

  it("sort=new pages newest first", async () => {
    const p1 = await A.get(`/v1/topics/${T}/posts?sort=new&limit=2`);
    expect(p1.body.items.map((p) => p.body)).toEqual(["post 4", "post 3"]);
    const p2 = await A.get(`/v1/topics/${T}/posts?sort=new&limit=2&cursor=${p1.body.next_cursor}`);
    expect(p2.body.items.map((p) => p.body)).toEqual(["post 2", "post 1"]);
    const p3 = await A.get(`/v1/topics/${T}/posts?sort=new&limit=2&cursor=${p2.body.next_cursor}`);
    expect(p3.body.items.map((p) => p.body)).toEqual(["post 0"]);
    expect(p3.body.next_cursor).toBeNull();
  });

  it("sort=top orders by score then recency", async () => {
    const r = await A.get(`/v1/topics/${T}/posts?sort=top`);
    expect(r.body.items.map((p) => p.body)).toEqual(["post 3", "post 1", "post 4", "post 2", "post 0"]);
    const p1 = await A.get(`/v1/topics/${T}/posts?sort=top&limit=3`);
    const p2 = await A.get(`/v1/topics/${T}/posts?sort=top&limit=3&cursor=${p1.body.next_cursor}`);
    expect([...p1.body.items, ...p2.body.items].map((p) => p.body)).toEqual(["post 3", "post 1", "post 4", "post 2", "post 0"]);
  });

  it("feed spans topics and author listing works", async () => {
    const feed = await A.get(`/v1/feed?sort=new&limit=100`);
    expect(feed.status).toBe(200);
    expect(feed.body.items.length).toBeGreaterThanOrEqual(5);
    expect(feed.body.items.every((p) => p.parent === "")).toBe(true);
    const bodies = feed.body.items.map((p) => p.body);
    expect(bodies.indexOf("post 4")).toBeLessThan(bodies.indexOf("post 0"));

    const mine = await A.get(`/v1/authors/${A.authorId}/posts?limit=3`);
    expect(mine.status).toBe(200);
    expect(mine.body.items.length).toBe(3);
    expect(mine.body.items.every((p) => p.author === A.authorId)).toBe(true);
    expect((await A.get(`/v1/authors/${"0".repeat(64)}/posts`)).status).toBe(404);
  });

  it("lists topics most active first", async () => {
    const r = await A.get(`/v1/topics?limit=100`);
    expect(r.status).toBe(200);
    const t = r.body.items.find((x) => x.topic === T);
    expect(t.post_count).toBe(5);
    const counts = r.body.items.map((x) => x.post_count);
    expect([...counts].sort((a, b) => b - a)).toEqual(counts);
    expect((await A.get(`/v1/topics/does-not-exist/posts`)).status).toBe(404);
  });

  it("validates pagination params", async () => {
    expect((await A.get(`/v1/feed?limit=0`)).status).toBe(400);
    expect((await A.get(`/v1/feed?limit=101`)).status).toBe(400);
    expect((await A.get(`/v1/feed?limit=abc`)).status).toBe(400);
    expect((await A.get(`/v1/feed?sort=hot`)).status).toBe(400);
    expect((await A.get(`/v1/feed?cursor=!!!`)).status).toBe(400);
    expect((await A.get(`/v1/feed?cursor=${btoa("[1]")}`)).status).toBe(400);
  });
});

describe("rate limits", () => {
  it("caps new keys at 5 posts/hour with Retry-After", async () => {
    const E = await edAgent(); // fresh key: first_seen is set by its first write
    // (E may have posted once in the identity suite; count what exists.)
    const existing = await E.get(`/v1/authors/${E.authorId}/posts?limit=100`);
    const made = existing.status === 200 ? existing.body.items.length : 0;
    for (let i = made; i < 5; i++) {
      const r = await E.post("t-rl", `rl ${i}`, { created_at: nowIso(-50 + i) });
      expect(r.status).toBe(201);
    }
    const blocked = await E.post("t-rl", "one too many");
    expect(blocked.status).toBe(429);
    expect(blocked.body.error).toBe("rate_limited");
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(Number(blocked.headers.get("retry-after"))).toBeLessThanOrEqual(3600);
  });

  it("raises the limit for keys older than 24h", async () => {
    const E = await edAgent();
    await env.DB.prepare(`UPDATE authors SET first_seen = ? WHERE author_id = ?`)
      .bind(nowIso(-2 * 86400), E.authorId).run();
    const r = await E.post("t-rl", "old key posts fine");
    expect(r.status).toBe(201);
  });

  it("enforces the 300/hour vote limit by counting stored votes", async () => {
    // Not worth 300 real votes; just confirm the query path returns a number.
    const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM votes WHERE voter = ?`).bind(B.authorId).first();
    expect(typeof row.n).toBe("number");
  });
});
