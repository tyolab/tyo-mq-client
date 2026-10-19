'use strict';

/**
 * End-to-end encrypted payloads — WebCrypto implementation of the SAME suite
 * as lib/e2ee.js (`ecdh-es-p256-a256gcm`: ephemeral-static ECDH on P-256 →
 * HKDF-SHA256 → AES-256-GCM), byte-for-byte wire-compatible: a payload sealed
 * here opens in Node, and vice versa (pinned by test/e2ee-browser.test.js
 * against tests/e2ee-vectors.json).
 *
 * This file is what the browser bundle gets for `./e2ee` (package.json
 * "browser" field): Node's crypto.hkdfSync / createECDH do not exist in the
 * browserify shim, so the Node file silently cannot run in a browser.
 *
 * Differences from the Node file, dictated by WebCrypto:
 *   - EVERY function returns a Promise (subtle.* is async). publisher.produce
 *     returns a Promise when it encrypts through this file; subscriber awaits
 *     open() before handing plaintext to the app.
 *   - A private key is a CryptoKey, a JWK ({kty:'EC', crv:'P-256', d, x, y}),
 *     or a raw pair {privateKey: 32B scalar, publicKey: 65B point} — WebCrypto
 *     cannot import a bare scalar without its public point. generateKeyPair()
 *     returns {privateKey: <JWK>, publicKey: <Uint8Array 65B>}.
 *   - open() resolves a Uint8Array; use decodeText() for UTF-8.
 * No Buffer, no Node modules: runs on globalThis.crypto.subtle (browsers,
 * and Node 20+ for tests).
 */

var ALG = 'ecdh-es-p256-a256gcm';
var CURVE = 'P-256';
var INFO_PREFIX = 'tyo-mq-e2ee-v1:';
var TAG_BITS = 128;
var IV_BYTES = 12;

function subtle() {
    var c = (typeof globalThis !== 'undefined') ? globalThis.crypto : null;
    if (!c || !c.subtle) throw new Error('e2ee: WebCrypto (crypto.subtle) is not available in this environment');
    return c.subtle;
}
function randomBytes(n) {
    var out = new Uint8Array(n);
    globalThis.crypto.getRandomValues(out);
    return out;
}

// ── bytes / base64 helpers (no Buffer) ─────────────────────────────────────
function utf8(str) { return new TextEncoder().encode(String(str)); }
function decodeText(bytes) { return new TextDecoder().decode(toBytes(bytes)); }
function b64decode(str) {
    var bin = atob(String(str).replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
function b64encode(bytes) {
    var s = '';
    bytes = toBytes(bytes);
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}
function b64url(bytes) { return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
// Accepts Uint8Array, ArrayBuffer, Node Buffer (a Uint8Array subclass), or a
// base64 string. Strings are BASE64 here (keys/ciphertext), never UTF-8 — use
// utf8() for text.
function toBytes(x) {
    if (x instanceof Uint8Array) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (typeof x === 'string') return b64decode(x);
    if (x && typeof x.length === 'number') return Uint8Array.from(x);
    throw new Error('e2ee: unsupported byte source');
}
function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
}

// aad binds a ciphertext to its cleartext routing — identical bytes to the Node
// implementation: event "\n" to "\n" from.
function aad(event, to, from) {
    return utf8((event || '') + '\n' + (to || '') + '\n' + (from || ''));
}

// ── key import ─────────────────────────────────────────────────────────────
function importPublic(raw) {
    var bytes = toBytes(raw);
    if (bytes.length !== 65 || bytes[0] !== 4) throw new Error('e2ee: expected a 65-byte uncompressed P-256 public point');
    return subtle().importKey('raw', bytes, { name: 'ECDH', namedCurve: CURVE }, true, []);
}
function jwkFromRawPair(priv, pub) {
    var d = toBytes(priv), p = toBytes(pub);
    if (d.length !== 32) throw new Error('e2ee: expected a 32-byte P-256 private scalar');
    if (p.length !== 65 || p[0] !== 4) throw new Error('e2ee: expected a 65-byte uncompressed P-256 public point');
    return { kty: 'EC', crv: CURVE, d: b64url(d), x: b64url(p.subarray(1, 33)), y: b64url(p.subarray(33, 65)) };
}
function isCryptoKey(k) { return typeof CryptoKey !== 'undefined' && k instanceof CryptoKey; }
// A private key: CryptoKey | JWK | {privateKey, publicKey}. Resolves {key, jwk|null}.
function importPrivate(priv) {
    if (isCryptoKey(priv)) return Promise.resolve({ key: priv, jwk: null });
    var jwk;
    if (priv && typeof priv === 'object' && priv.kty === 'EC') jwk = priv;
    else if (priv && typeof priv === 'object' && priv.privateKey !== undefined && priv.publicKey !== undefined)
        jwk = jwkFromRawPair(priv.privateKey, priv.publicKey);
    else
        throw new Error('e2ee (browser): a private key must be a CryptoKey, a JWK, or {privateKey, publicKey} — a bare scalar cannot be imported without its public point');
    return subtle().importKey('jwk', jwk, { name: 'ECDH', namedCurve: CURVE }, false, ['deriveBits'])
        .then(function (key) { return { key: key, jwk: jwk }; });
}
function rawPublicFromJwk(jwk) {
    return concat(new Uint8Array([4]), concat(b64decode(jwk.x), b64decode(jwk.y)));
}

// ── KDF ────────────────────────────────────────────────────────────────────
// HKDF-SHA256, empty salt, info = "tyo-mq-e2ee-v1:<alg>:<kid>" → AES-256-GCM key.
function deriveKey(sharedX, kid) {
    var info = utf8(INFO_PREFIX + ALG + ':' + (kid || ''));
    var s = subtle();
    return s.importKey('raw', toBytes(sharedX), 'HKDF', false, ['deriveBits'])
        .then(function (k) { return s.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: info }, k, 256); })
        .then(function (bits) { return s.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']); });
}
function ecdh(privKey, pubKey) {
    return subtle().deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256).then(function (b) { return new Uint8Array(b); });
}

// ── seal / open ────────────────────────────────────────────────────────────
// seal(recipientPub, event, to, from, plaintext, opts) → Promise<{enc, message}>.
// plaintext: Uint8Array | string (UTF-8). opts.ephemeralPriv ({privateKey,
// publicKey} | JWK) and opts.iv make it deterministic for vector checks.
function seal(recipientPub, event, to, from, plaintext, opts) {
    opts = opts || {};
    var s = subtle();
    var pt = (typeof plaintext === 'string') ? utf8(plaintext) : toBytes(plaintext);
    var kid = opts.kid || '';
    var iv = opts.iv ? toBytes(opts.iv) : randomBytes(IV_BYTES);
    var ephemeral = opts.ephemeralPriv
        ? importPrivate(opts.ephemeralPriv).then(function (r) { return { priv: r.key, epk: rawPublicFromJwk(r.jwk) }; })
        : s.generateKey({ name: 'ECDH', namedCurve: CURVE }, true, ['deriveBits']).then(function (pair) {
            return s.exportKey('raw', pair.publicKey).then(function (raw) { return { priv: pair.privateKey, epk: new Uint8Array(raw) }; });
        });
    return Promise.all([ephemeral, importPublic(recipientPub)]).then(function (r) {
        var eph = r[0], recipient = r[1];
        return ecdh(eph.priv, recipient).then(function (sharedX) { return deriveKey(sharedX, kid); }).then(function (key) {
            return s.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad(event, to, from), tagLength: TAG_BITS }, key, pt);
        }).then(function (box) {
            return {
                enc: { v: 1, alg: ALG, epk: b64encode(eph.epk), iv: b64encode(iv), kid: kid },
                message: b64encode(new Uint8Array(box)),
            };
        });
    });
}

// open(myPriv, enc, event, to, from, message) → Promise<Uint8Array>. Rejects on
// a bad tag / AAD / key, or an unsupported alg.
function open(myPriv, enc, event, to, from, message) {
    if (!enc || enc.alg !== ALG) return Promise.reject(new Error('e2ee: unsupported alg ' + (enc && enc.alg)));
    var s = subtle();
    return Promise.all([importPrivate(myPriv), importPublic(b64decode(enc.epk))]).then(function (r) {
        return ecdh(r[0].key, r[1]);
    }).then(function (sharedX) { return deriveKey(sharedX, enc.kid || ''); }).then(function (key) {
        return s.decrypt({ name: 'AES-GCM', iv: b64decode(enc.iv), additionalData: aad(event, to, from), tagLength: TAG_BITS }, key, b64decode(message));
    }).then(function (pt) { return new Uint8Array(pt); }, function (err) {
        // WebCrypto reports a bad tag as a bare OperationError; name it.
        throw new Error('e2ee: decrypt failed' + (err && err.message ? ' (' + err.message + ')' : ''));
    });
}

// generateKeyPair() → Promise<{privateKey: JWK, publicKey: Uint8Array(65)}>.
function generateKeyPair() {
    var s = subtle();
    return s.generateKey({ name: 'ECDH', namedCurve: CURVE }, true, ['deriveBits']).then(function (pair) {
        return Promise.all([s.exportKey('jwk', pair.privateKey), s.exportKey('raw', pair.publicKey)]);
    }).then(function (r) {
        var jwk = r[0];
        return { privateKey: { kty: 'EC', crv: CURVE, d: jwk.d, x: jwk.x, y: jwk.y }, publicKey: new Uint8Array(r[1]) };
    });
}
// publicKeyFromPrivate(JWK | {privateKey, publicKey}) → Uint8Array(65). Sync.
function publicKeyFromPrivate(priv) {
    if (priv && priv.kty === 'EC') return rawPublicFromJwk(priv);
    if (priv && priv.publicKey !== undefined) return toBytes(priv.publicKey);
    throw new Error('e2ee (browser): cannot derive a public point from a bare scalar');
}

// isEnvelope: is this `enc` value THIS suite's envelope (something open() can
// act on), as opposed to a bare `enc: true` flag or a foreign scheme's object?
function isEnvelope(enc) {
    return !!enc && typeof enc === 'object' && enc.alg === ALG
        && typeof enc.epk === 'string' && typeof enc.iv === 'string';
}

module.exports = {
    ALG: ALG, CURVE: CURVE, async: true,
    seal: seal, open: open, deriveKey: deriveKey, aad: aad,
    generateKeyPair: generateKeyPair, publicKeyFromPrivate: publicKeyFromPrivate,
    isEnvelope: isEnvelope, decodeText: decodeText,
};
