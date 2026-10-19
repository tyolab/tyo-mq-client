'use strict';
/**
 * WebCrypto E2EE (lib/e2ee-browser.js) — wire-compatible with the Node suite —
 * and the subscriber's treatment of `enc` that is NOT this suite's envelope.
 *
 * Why: the browser bundle's crypto shim has no hkdfSync/createECDH, so the Node
 * e2ee.js silently cannot run in a browser (hilia-web, 2026-10-15). And
 * subscriber.js used to DROP any frame carrying `enc` unless its resolver
 * decrypted it — including a bare `enc: true` from a client that does its own
 * cryptography (the Hilia apps carry Signal ciphertext and set the flag to
 * satisfy an e2ee:required realm), which made such realms undeliverable to any
 * tyo-mq-client consumer.
 *
 * Runs under Node 20+ (globalThis.crypto.subtle is WebCrypto there too), so
 * the browser implementation is exercised for real, not mocked.
 *
 * Usage: node test/e2ee-browser.test.js
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { test, run } = require('./runner');
const { installFakeIo } = require('./fake-socket-io');

const fakeIo = installFakeIo();
const Factory = require('../lib/factory');
const protocolEvents = require('tyo-mq-protocol').events;
const nodeE2ee = require('../lib/e2ee');
const webE2ee = require('../lib/e2ee-browser');

const quietLogger = { log() {}, info() {}, warn() {}, error() {}, debug() {}, trace() {}, critical() {}, output() {} };
function lastSocket() { return fakeIo.connections[fakeIo.connections.length - 1]; }

// Conformance vectors are the broker repo's (one copy, both languages pin it).
const VECTORS_PATH = path.join(__dirname, '..', '..', 'tyo-mq', 'tests', 'e2ee-vectors.json');
// The file is a single vector object today; accept a list or {vectors:[…]} too.
const vectors = (function () {
    if (!fs.existsSync(VECTORS_PATH)) return null;
    const v = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
    return Array.isArray(v) ? v : (Array.isArray(v.vectors) ? v.vectors : [v]);
})();

test('browser e2ee: opens every published conformance vector (Node-sealed) to the exact plaintext', async () => {
    assert.ok(vectors && vectors.length, 'vectors file present: ' + VECTORS_PATH);
    for (const v of vectors) {
        const priv = { privateKey: v.recipient_private_b64, publicKey: v.recipient_public_b64 };
        const pt = await webE2ee.open(priv, v.enc, v.routing.event, v.routing.to, v.routing.from, v.message_b64);
        assert.strictEqual(webE2ee.decodeText(pt), v.plaintext_utf8, 'vector ' + (v.name || v.routing.kid));
    }
});

test('browser e2ee ↔ node e2ee: each implementation opens what the other sealed (fresh keys both ways)', async () => {
    // Node recipient, browser sender
    const nodeKeys = nodeE2ee.generateKeyPair();
    const sealedByWeb = await webE2ee.seal(nodeKeys.publicKey, 'chat.msg', 'bob', 'alice', '{"t":"hi from the browser"}', { kid: 'k1' });
    assert.ok(nodeE2ee.isEnvelope(sealedByWeb.enc) && webE2ee.isEnvelope(sealedByWeb.enc));
    const openedByNode = nodeE2ee.open(nodeKeys.privateKey, sealedByWeb.enc, 'chat.msg', 'bob', 'alice', sealedByWeb.message);
    assert.strictEqual(openedByNode.toString('utf8'), '{"t":"hi from the browser"}');

    // Browser recipient, Node sender
    const webKeys = await webE2ee.generateKeyPair();
    assert.strictEqual(webKeys.publicKey.length, 65);
    const sealedByNode = nodeE2ee.seal(Buffer.from(webKeys.publicKey), 'chat.msg', 'alice', 'bob', Buffer.from('{"t":"hi from node"}'), { kid: 'k2' });
    const openedByWeb = await webE2ee.open(webKeys.privateKey, sealedByNode.enc, 'chat.msg', 'alice', 'bob', sealedByNode.message);
    assert.strictEqual(webE2ee.decodeText(openedByWeb), '{"t":"hi from node"}');

    // AAD binds routing: the same ciphertext under a different `to` fails in the browser too
    await assert.rejects(() => webE2ee.open(webKeys.privateKey, sealedByNode.enc, 'chat.msg', 'mallory', 'bob', sealedByNode.message), /decrypt failed/);
    // and the raw public point derived from the JWK matches what generateKeyPair returned
    assert.deepStrictEqual(Array.from(webE2ee.publicKeyFromPrivate(webKeys.privateKey)), Array.from(webKeys.publicKey));
});

test('browser e2ee: deterministic seal (fixed ephemeral + iv) reproduces the Node bytes exactly', async () => {
    const recipient = nodeE2ee.generateKeyPair();
    const eph = nodeE2ee.generateKeyPair();
    const iv = Buffer.from('000102030405060708090a0b', 'hex');
    const opts = { kid: 'det', iv };
    const byNode = nodeE2ee.seal(recipient.publicKey, 'ev', 'to', 'from', Buffer.from('same bytes'), Object.assign({ ephemeralPriv: eph.privateKey }, opts));
    const byWeb = await webE2ee.seal(recipient.publicKey, 'ev', 'to', 'from', 'same bytes', Object.assign({ ephemeralPriv: { privateKey: eph.privateKey, publicKey: eph.publicKey } }, opts));
    assert.deepStrictEqual(byWeb.enc, byNode.enc);
    assert.strictEqual(byWeb.message, byNode.message);
});

test('isEnvelope: only this suite\'s envelope counts — a bare flag or a foreign object does not', () => {
    for (const impl of [nodeE2ee, webE2ee]) {
        assert.strictEqual(impl.isEnvelope(true), false);
        assert.strictEqual(impl.isEnvelope({ scheme: 'signal' }), false);
        assert.strictEqual(impl.isEnvelope({ alg: 'other-alg', epk: 'x', iv: 'y' }), false);
        assert.strictEqual(impl.isEnvelope({ v: 1, alg: impl.ALG, epk: 'x', iv: 'y', kid: '' }), true);
    }
});

// ── subscriber: enc that is not ours is delivered, not dropped ─────────────

function subscriberWith(name, e2eeOpts) {
    const factory = new Factory(Object.assign({ logger: quietLogger }, e2eeOpts ? { e2ee: e2eeOpts } : {}));
    let consumer;
    factory.createConsumer(name, function (c) { consumer = c; });
    lastSocket()._simulateConnect();
    return { consumer, socket: lastSocket() };
}
function consumeEventFor(event, who) {
    return protocolEvents.toConsumeEvent(protocolEvents.toConsumerEvent(protocolEvents.toEventString(event), who));
}

test('subscriber: a bare `enc: true` (client carrying its own ciphertext) is delivered untouched, with enc visible, resolver or not', async () => {
    const { consumer, socket } = subscriberWith('mirror-browser');
    const got = [];
    consumer.subscribe('phone', 'chat.mirror', function (message, from, ack, raw) { got.push({ message, from, enc: raw && raw.enc }); });
    const ev = consumeEventFor('chat.mirror', 'phone');
    socket._trigger(ev, { message: { ciphertext: 'opaque-signal-bytes' }, from: 'phone', enc: true });
    socket._trigger(ev, { message: 'c2lnbmFs', from: 'phone', enc: { scheme: 'signal', v: 3 } });
    await new Promise((r) => setTimeout(r, 10));
    assert.strictEqual(got.length, 2, 'both non-suite frames reach the application');
    assert.deepStrictEqual(got[0].message, { ciphertext: 'opaque-signal-bytes' });
    assert.strictEqual(got[0].enc, true);
    assert.deepStrictEqual(got[1].enc, { scheme: 'signal', v: 3 });
});

test('subscriber: this suite\'s envelope is still decrypted (and dropped without a resolver / on a bad key)', async () => {
    const keys = nodeE2ee.generateKeyPair();
    const sealed = nodeE2ee.seal(keys.publicKey, protocolEvents.toEventString('chat.msg'), 'reader', 'writer', Buffer.from(JSON.stringify({ ok: 1 })), { kid: 'k' });
    const frame = { message: sealed.message, enc: sealed.enc, from: 'writer', to: 'reader', event: protocolEvents.toEventString('chat.msg') };
    const ev = consumeEventFor('chat.msg', 'writer');

    // no resolver → dropped (ciphertext must never reach the app)
    const a = subscriberWith('reader');
    const gotA = [];
    a.consumer.subscribe('writer', 'chat.msg', function (m) { gotA.push(m); });
    a.socket._trigger(ev, frame);
    await new Promise((r) => setTimeout(r, 10));
    assert.strictEqual(gotA.length, 0);

    // right resolver → decrypted plaintext
    const b = subscriberWith('reader', { resolver: { privateKey: () => keys.privateKey, publicKey: () => null } });
    const gotB = [];
    b.consumer.subscribe('writer', 'chat.msg', function (m) { gotB.push(m); });
    b.socket._trigger(ev, frame);
    await new Promise((r) => setTimeout(r, 10));
    assert.deepStrictEqual(gotB, [{ ok: 1 }]);

    // wrong key → dropped
    const other = nodeE2ee.generateKeyPair();
    const c = subscriberWith('reader', { resolver: { privateKey: () => other.privateKey, publicKey: () => null } });
    const gotC = [];
    c.consumer.subscribe('writer', 'chat.msg', function (m) { gotC.push(m); });
    c.socket._trigger(ev, frame);
    await new Promise((r) => setTimeout(r, 10));
    assert.strictEqual(gotC.length, 0);
});

// ── producer registration: an anonymous producer registers under its minted name ──

test('publisher: an anonymous producer\'s PRODUCER frame carries its minted ANONYMOUS-<uuid> name (was {} → refused by the broker)', () => {
    const factory = new Factory({ logger: quietLogger });
    let producer;
    factory.createProducer(undefined, function (p) { producer = p; }); // (name, callback) — no name → anonymous
    lastSocket()._simulateConnect();
    const socket = lastSocket();
    const reg = socket.emits.find((e) => e.event === 'PRODUCER');
    assert.ok(reg, 'expected a PRODUCER emit');
    assert.ok(/^ANONYMOUS-[0-9a-f-]{36}$/.test(reg.payload.name), 'registered name: ' + JSON.stringify(reg.payload));
    assert.strictEqual(reg.payload.name, producer.name, 'registers under the same name it uses as `from`');
});

run();
