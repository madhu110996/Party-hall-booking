// Hall Bookings: sends phone push notifications to everyone on the team.
// Uses only features built into Node (no npm packages needed).
//
// No Netlify settings are needed. (Optional: add VAPID_PRIVATE_KEY in Netlify to use your own signing key.)

const crypto = require("crypto");

const JSONBIN = "https://api.jsonbin.io/v3/b";
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
// Only genuine browser push services are allowed as destinations.
const PUSH_HOSTS = [
  /(^|\.)googleapis\.com$/,        // Chrome / Android
  /(^|\.)push\.apple\.com$/,       // Safari / iPhone
  /(^|\.)mozilla\.com$/,           // Firefox
  /(^|\.)mozaws\.net$/,
  /(^|\.)notify\.windows\.com$/    // Edge
];
const MAX_DEVICES = 20;

function b64u(input){ return Buffer.from(input).toString("base64url"); }
function clip(v, n){ return String(v == null ? "" : v).slice(0, n); }

// ---------- VAPID (proves to the push service that this server is allowed to send) ----------

function vapidKeys(privateB64){
  let d = Buffer.from(String(privateB64).trim(), "base64url");
  if (d.length > 32 || d.length < 30) throw new Error("bad key length");
  if (d.length < 32) d = Buffer.concat([Buffer.alloc(32 - d.length), d]);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();   // 65 bytes, uncompressed
  const privateKey = crypto.createPrivateKey({
    key: { kty: "EC", crv: "P-256", d: d.toString("base64url"),
           x: pub.subarray(1, 33).toString("base64url"), y: pub.subarray(33, 65).toString("base64url") },
    format: "jwk"
  });
  return { pubB64: pub.toString("base64url"), privateKey };
}

// Signing key made from the app's storage key, so nothing has to be set up in Netlify.
function deriveVapidPrivate(secret){
  for (let i = 0; i < 10; i++){
    const d = crypto.createHmac("sha256", "hall-bookings-push-v1").update(String(secret) + ":" + i).digest();
    try{ crypto.createECDH("prime256v1").setPrivateKey(d); return d.toString("base64url"); }catch(e){}
  }
  throw new Error("could not derive key");
}

function vapidHeader(audience, subject, keys){
  const header = b64u(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = b64u(JSON.stringify({ aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject }));
  const input = header + "." + claims;
  const sig = crypto.sign("sha256", Buffer.from(input), { key: keys.privateKey, dsaEncoding: "ieee-p1363" });
  return "vapid t=" + input + "." + sig.toString("base64url") + ", k=" + keys.pubB64;
}

// ---------- Payload encryption (RFC 8291 / RFC 8188, aes128gcm) ----------

function hkdf(salt, ikm, info, length){
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();
  let t = Buffer.alloc(0), okm = Buffer.alloc(0), i = 1;
  while (okm.length < length){
    t = crypto.createHmac("sha256", prk).update(Buffer.concat([t, info, Buffer.from([i++])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, length);
}

function encrypt(sub, plaintext, test){
  const uaPublic = Buffer.from(sub.keys.p256dh, "base64url");
  const authSecret = Buffer.from(sub.keys.auth, "base64url");
  const ecdh = crypto.createECDH("prime256v1");
  if (test && test.asPrivate) ecdh.setPrivateKey(test.asPrivate); else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const secret = ecdh.computeSecret(uaPublic);
  const salt = (test && test.salt) || crypto.randomBytes(16);
  const keyInfo = Buffer.concat([Buffer.from("WebPush: info\0"), uaPublic, asPublic]);
  const ikm = hkdf(authSecret, secret, keyInfo, 32);
  const cek = hkdf(salt, ikm, Buffer.from("Content-Encoding: aes128gcm\0"), 16);
  const nonce = hkdf(salt, ikm, Buffer.from("Content-Encoding: nonce\0"), 12);
  const cipher = crypto.createCipheriv("aes-128-gcm", cek, nonce);
  const data = Buffer.concat([Buffer.from(plaintext), Buffer.from([2])]);   // 0x02 = last record
  const encrypted = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPublic.length]), asPublic, encrypted]);
}

// ---------- team data (stored in the same jsonbin record as the bookings) ----------

async function jb(path, key, init){
  const res = await fetch(JSONBIN + path, Object.assign({ signal: AbortSignal.timeout(8000) }, init, {
    headers: Object.assign({ "X-Master-Key": key }, (init && init.headers) || {})
  }));
  if (!res.ok){ const e = new Error("jsonbin " + res.status); e.status = res.status; throw e; }
  return res;
}
async function getRecord(docId, key){
  const res = await jb("/" + encodeURIComponent(docId) + "/latest", key, { headers: { "X-Bin-Meta": "false" } });
  const rec = await res.json();
  return (rec && typeof rec === "object") ? rec : {};
}
// Re-reads the newest record right before writing so bookings are never overwritten with stale data.
async function updateRecord(docId, key, mutate){
  const rec = await getRecord(docId, key);
  if (!Array.isArray(rec.push)) rec.push = [];
  if (!mutate(rec)) return rec;
  await jb("/" + encodeURIComponent(docId), key, {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rec)
  });
  return rec;
}

function validSub(s){
  try{
    if (!s || typeof s.endpoint !== "string" || !s.keys) return false;
    const u = new URL(s.endpoint);
    if (u.protocol !== "https:" || !PUSH_HOSTS.some(re => re.test(u.hostname))) return false;
    return Buffer.from(String(s.keys.p256dh), "base64url").length === 65 &&
           Buffer.from(String(s.keys.auth), "base64url").length >= 16;
  }catch(e){ return false; }
}

async function sendOne(sub, payload, keys, subject){
  const audience = new URL(sub.endpoint).origin;
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
      "TTL": "86400", "Urgency": "high", "Authorization": vapidHeader(audience, subject, keys)
    },
    body: encrypt(sub, payload),
    signal: AbortSignal.timeout(8000)
  });
  return { ok: res.status >= 200 && res.status < 300, status: res.status };
}

// ---------- the endpoint ----------

exports.handler = async (event) => {
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
  const reply = (statusCode, obj) => ({ statusCode, headers, body: JSON.stringify(obj) });

  if (event.httpMethod !== "POST") return reply(405, { error: "method" });

  let body;
  try{
    const raw = event.isBase64Encoded ? Buffer.from(event.body || "", "base64").toString() : (event.body || "");
    body = JSON.parse(raw);
  }catch(e){ return reply(400, { error: "bad_json" }); }

  const jbKey = process.env.JSONBIN_KEY || String(body.key || "");
  const privEnv = process.env.VAPID_PRIVATE_KEY;
  if (!privEnv && !jbKey) return reply(400, { error: "no_key" });
  let keys;
  try{ keys = vapidKeys(privEnv || deriveVapidPrivate(jbKey)); }catch(e){ return reply(500, { error: "bad_key" }); }

  if (body.action === "key") return reply(200, { publicKey: keys.pubB64 });

  const docId = String(body.docId || "");
  if (!ID_RE.test(docId)) return reply(400, { error: "bad_doc" });

  const host = (event.headers && (event.headers["x-forwarded-host"] || event.headers.host)) || "";
  const subject = host ? "https://" + host : "mailto:admin@example.com";
  const action = body.action;

  try{
    if (action === "subscribe"){
      if (!validSub(body.subscription)) return reply(400, { error: "bad_subscription" });
      const s = body.subscription;
      const entry = { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth }, name: clip(body.name, 40) };
      const rec = await updateRecord(docId, jbKey, (r) => {
        const i = r.push.findIndex(x => x.endpoint === entry.endpoint);
        let changed = false;
        if (i < 0){ entry.addedAt = Date.now(); r.push.push(entry); changed = true; }
        else if (r.push[i].keys.p256dh !== entry.keys.p256dh || r.push[i].keys.auth !== entry.keys.auth || r.push[i].name !== entry.name){
          entry.addedAt = r.push[i].addedAt; r.push[i] = entry; changed = true;
        }
        while (r.push.length > MAX_DEVICES){ r.push.shift(); changed = true; }
        return changed;
      });
      return reply(200, { ok: true, devices: rec.push.length });
    }

    if (action === "unsubscribe"){
      const ep = String(body.endpoint || "");
      await updateRecord(docId, jbKey, (r) => {
        const before = r.push.length;
        r.push = r.push.filter(x => x.endpoint !== ep);
        return r.push.length !== before;
      });
      return reply(200, { ok: true });
    }

    const rec = await getRecord(docId, jbKey);
    const subs = Array.isArray(rec.push) ? rec.push : [];

    if (action === "test"){
      const sub = subs.find(x => x.endpoint === body.endpoint);
      if (!sub) return reply(404, { error: "not_subscribed" });
      const payload = JSON.stringify({ title: "Test notification", body: "Alerts are working on this phone.", url: clip(body.url, 300) });
      const r = await sendOne(sub, payload, keys, subject);
      return reply(200, { ok: r.ok, status: r.status });
    }

    if (action === "notify"){
      if (!subs.length) return reply(200, { sent: 0, gone: 0, failed: 0 });
      const payload = JSON.stringify({
        title: clip(body.title, 80) || "Hall Bookings", body: clip(body.body, 200), url: clip(body.url, 300)
      });
      const results = await Promise.all(subs.map(async (sub) => {
        try{ return Object.assign({ endpoint: sub.endpoint }, await sendOne(sub, payload, keys, subject)); }
        catch(e){ return { endpoint: sub.endpoint, ok: false, status: 0 }; }
      }));
      const gone = results.filter(r => r.status === 404 || r.status === 410).map(r => r.endpoint);
      if (gone.length){
        try{ await updateRecord(docId, jbKey, (r) => { const n = r.push.length; r.push = r.push.filter(x => !gone.includes(x.endpoint)); return r.push.length !== n; }); }
        catch(e){}
      }
      return reply(200, { sent: results.filter(r => r.ok).length, gone: gone.length, failed: results.filter(r => !r.ok && !gone.includes(r.endpoint)).length });
    }

    return reply(400, { error: "bad_action" });
  }catch(e){
    const missing = e && (e.status === 404 || e.status === 422);
    return reply(missing ? 404 : 502, { error: missing ? "team_not_found" : "upstream_error" });
  }
};

// exposed for tests only
exports._test = { encrypt, vapidKeys, vapidHeader, hkdf, deriveVapidPrivate };
