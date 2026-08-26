/**
 * @file client.test.js
 *
 * Standalone unit tests for tyo-mq-client. Unlike tyo-mq's integration tests
 * (which need a live broker), these run against a mocked socket.io-client
 * transport (see fake-socket-io.js) — no server required.
 */

'use strict';

const assert = require('assert');
const { test, run } = require('./runner');
const { installFakeIo } = require('./fake-socket-io');

// Must happen before the first require of lib/socket.js (directly, or
// transitively via factory/subscriber/publisher) so every
// `require('socket.io-client')` call in lib/ resolves to the fake.
const fakeIo = installFakeIo();

const Factory = require('../lib/factory');
const Subscriber = require('../lib/subscriber');
const Publisher = require('../lib/publisher');
const e2ee = require('../lib/e2ee');
const protocol = require('tyo-mq-protocol');
const protocolEvents = protocol.events;

const quietLogger = { log: function () {}, warn: function () {}, error: function () {} };

function lastSocket() {
    return fakeIo.connections[fakeIo.connections.length - 1];
}

// ---------------------------------------------------------------------------
// 1. e2ee round-trip — pure crypto.js code, no socket involved at all.
// ---------------------------------------------------------------------------

test('e2ee: seal/open round-trips plaintext and produces ciphertext that differs from it', () => {
    const recipient = e2ee.generateKeyPair();
    const plaintext = 'hello from a unit test, no server required';

    const sealed = e2ee.seal(recipient.publicKey, 'my-event', 'bob', 'alice', plaintext);
    assert.strictEqual(sealed.enc.alg, e2ee.ALG);
    assert.notStrictEqual(sealed.message, plaintext, 'ciphertext must differ from plaintext');
    assert.ok(!sealed.message.includes('unit test'), 'ciphertext must not leak the plaintext');

    const opened = e2ee.open(recipient.privateKey, sealed.enc, 'my-event', 'bob', 'alice', sealed.message);
    assert.strictEqual(opened.toString('utf8'), plaintext);
});

test('e2ee: open rejects a payload whose AAD (event/to/from) does not match what it was sealed for', () => {
    const recipient = e2ee.generateKeyPair();
    const sealed = e2ee.seal(recipient.publicKey, 'my-event', 'bob', 'alice', 'secret');

    assert.throws(() => {
        e2ee.open(recipient.privateKey, sealed.enc, 'my-event', 'eve', 'alice', sealed.message);
    }, /.+/);
});

// ---------------------------------------------------------------------------
// 2. Factory builds real Subscriber / Publisher instances.
// ---------------------------------------------------------------------------

test('Factory.createConsumer yields a Subscriber, connected through the mocked transport', () => {
    const factory = new Factory({ logger: quietLogger });
    let consumer = null;
    let callbackErr;

    factory.createConsumer('sub-factory-test', function (c, err) {
        consumer = c;
        callbackErr = err;
    });

    const socket = lastSocket();
    assert.ok(socket, 'expected the factory to have opened a (fake) socket connection');
    socket._simulateConnect();

    assert.ok(!callbackErr, 'expected no connect error');
    assert.ok(consumer instanceof Subscriber, 'expected a Subscriber instance');
    assert.strictEqual(consumer.name, 'sub-factory-test');
});

test('Factory.createProducer yields a Publisher, connected through the mocked transport', () => {
    const factory = new Factory({ logger: quietLogger });
    let producer = null;

    factory.createProducer('pub-factory-test', function (p) {
        producer = p;
    });

    lastSocket()._simulateConnect();

    assert.ok(producer instanceof Publisher, 'expected a Publisher instance');
    assert.ok(producer instanceof Subscriber, 'Publisher extends Subscriber');
    assert.strictEqual(producer.name, 'pub-factory-test');
});

test('Factory exposes Subscriber/Publisher (and legacy Consumer/Producer aliases) as statics', () => {
    assert.strictEqual(Factory.Subscriber, Subscriber);
    assert.strictEqual(Factory.Publisher, Publisher);
    assert.strictEqual(Factory.Consumer, Subscriber);
    assert.strictEqual(Factory.Producer, Publisher);
});

// ---------------------------------------------------------------------------
// 3. Publish/subscribe emit the wire events tyo-mq-protocol's `events` module
//    says they should — this is the test that guards client/server protocol
//    drift: if lib/subscriber.js or lib/publisher.js ever stop calling
//    tyo-mq-protocol's formatting helpers correctly, this fails.
// ---------------------------------------------------------------------------

test('publisher.produce() emits a PRODUCE frame with the event/message/from wire shape', () => {
    const factory = new Factory({ logger: quietLogger });
    let producer;
    factory.createProducer('pub-wire-test', function (p) { producer = p; });
    lastSocket()._simulateConnect();

    const socket = lastSocket();
    producer.produce('order.created', { orderId: 42 });

    const produceCall = socket.emits.find((e) => e.event === 'PRODUCE');
    assert.ok(produceCall, 'expected a PRODUCE emit');
    assert.strictEqual(produceCall.payload.event, 'order.created');
    assert.deepStrictEqual(produceCall.payload.message, { orderId: 42 });
    assert.strictEqual(produceCall.payload.from, 'pub-wire-test');
});

test('subscriber.subscribe() emits SUBSCRIBE and registers the exact CONSUME-* listener tyo-mq-protocol computes, and inbound messages reach the handler', () => {
    const factory = new Factory({ logger: quietLogger });
    let consumer;
    factory.createConsumer('sub-wire-test', function (c) { consumer = c; });
    lastSocket()._simulateConnect();
    const socket = lastSocket();

    let received = null;
    let receivedFrom = null;
    consumer.subscribe('order-service', 'order.created', function (message, from) {
        received = message;
        receivedFrom = from;
    });

    // (a) the SUBSCRIBE frame itself matches the protocol's event-string formatting
    const expectedEventStr = protocolEvents.toEventString('order.created');
    const subscribeCall = socket.emits.find((e) => e.event === 'SUBSCRIBE');
    assert.ok(subscribeCall, 'expected a SUBSCRIBE emit');
    assert.strictEqual(subscribeCall.payload.event, expectedEventStr);
    assert.strictEqual(subscribeCall.payload.producer, 'order-service');
    assert.strictEqual(subscribeCall.payload.consumer, 'sub-wire-test');

    // (b) the listener registered on the socket for inbound messages is named
    // exactly what tyo-mq-protocol's events module derives from the same
    // (event, producer) pair — this is the client<->server naming contract.
    const consumerEventStr = protocolEvents.toConsumerEvent(expectedEventStr, 'order-service');
    const consumeEventStr = protocolEvents.toConsumeEvent(consumerEventStr);
    assert.ok(socket.listeners(consumeEventStr).length > 0,
        'expected a listener registered for ' + consumeEventStr);

    // (c) driving that exact wire event through the mocked transport reaches
    // the application callback with the decoded message/from.
    socket._trigger(consumeEventStr, { message: { hello: 'world' }, from: 'order-service' });
    assert.deepStrictEqual(received, { hello: 'world' });
    assert.strictEqual(receivedFrom, 'order-service');
});

// Regression test for the fixed buffer.constants shadowing bug. Previously
// lib/subscriber.js did `const { constants } = require('buffer')`, which
// shadowed the file's own capitalised `Constants` (tyo-mq-protocol's) for
// the lone lowercase use `eventStr = constants.EVENT_ALL` on the no-event
// path — resolving to Node's buffer.constants.EVENT_ALL (undefined) and
// making events.toConsumerEvent() throw "Unknown event object". The
// two-arg subscribe(who, callback) form (subscribe to *everything* from a
// producer) is exactly the caller that takes that path, so it exercises the
// previously-broken line end to end.
test('subscriber.subscribe(who, callback) with no event name uses EVENT_ALL/ALL scope (regression: buffer.constants shadowing)', () => {
    const factory = new Factory({ logger: quietLogger });
    let consumer;
    factory.createConsumer('sub-all-test', function (c) { consumer = c; });
    lastSocket()._simulateConnect();
    const socket = lastSocket();

    let received = null;
    let receivedFrom = null;
    // No event name -> subscribe to all events from 'order-service'. This is
    // the path that threw "Unknown event object" before the fix.
    consumer.subscribe('order-service', function (message, from) {
        received = message;
        receivedFrom = from;
    });

    // (a) the SUBSCRIBE frame carries tyo-mq-protocol's EVENT_ALL under the ALL scope
    const subscribeCall = socket.emits.filter((e) => e.event === 'SUBSCRIBE').pop();
    assert.ok(subscribeCall, 'expected a SUBSCRIBE emit');
    assert.strictEqual(subscribeCall.payload.event, protocol.constants.EVENT_ALL);
    assert.strictEqual(subscribeCall.payload.scope, protocol.constants.SCOPE_ALL);
    assert.strictEqual(subscribeCall.payload.producer, 'order-service');

    // (b) the consume listener is named exactly what tyo-mq-protocol derives
    // for the EVENT_ALL/scope_all case, and inbound messages reach the handler.
    const consumerEventStr = protocolEvents.toConsumerEvent(protocol.constants.EVENT_ALL, 'order-service', true);
    const consumeEventStr = protocolEvents.toConsumeEvent(consumerEventStr);
    assert.ok(socket.listeners(consumeEventStr).length > 0,
        'expected a listener registered for ' + consumeEventStr);

    socket._trigger(consumeEventStr, { message: { hi: 5 }, from: 'order-service' });
    assert.deepStrictEqual(received, { hi: 5 });
    assert.strictEqual(receivedFrom, 'order-service');
});

// ---------------------------------------------------------------------------
// 4. Sealed emit guards — _sealedEmit must never hang forever: it times out
//    against a dead/never-acking broker and rejects immediately when the
//    socket disconnects mid-wait, in both the Promise and callback styles.
// ---------------------------------------------------------------------------

function makeSealedConsumer(name) {
    const factory = new Factory({ logger: quietLogger });
    let consumer;
    factory.createConsumer(name, function (c) { consumer = c; });
    lastSocket()._simulateConnect();
    return { consumer, socket: lastSocket() };
}

// Fails cleanly (instead of hanging npm test) when the promise under test
// never settles — the exact bug these tests guard against.
function within(promise, ms) {
    return Promise.race([
        promise,
        new Promise((_, reject) => setTimeout(
            () => reject(new Error('promise did not settle within ' + ms + 'ms')), ms))
    ]);
}

test('_sealedEmit: rejects within the (shortened) timeout when the broker never acks', async () => {
    const originalTimeout = Subscriber.EMIT_ACK_TIMEOUT_MS;
    Subscriber.EMIT_ACK_TIMEOUT_MS = 50;
    try {
        const { consumer } = makeSealedConsumer('sealed-timeout-test');
        // Never ack the recorded emit — a dead broker.
        await assert.rejects(
            within(consumer.sendSealed('realm', 'bob', 'uak', 'blob', 'm1'), 1000),
            /SEALED_DELIVER failed: .*timed out/);
    } finally {
        Subscriber.EMIT_ACK_TIMEOUT_MS = originalTimeout;
    }
});

test('_sealedEmit: rejects promptly when the socket disconnects mid-wait (default 15s timeout NOT waited out)', async () => {
    const { consumer, socket } = makeSealedConsumer('sealed-disconnect-test');
    const pending = consumer.requestSenderCert('alice', 'identity-key-b64', 1);
    socket.disconnect();
    // Must settle in well under EMIT_ACK_TIMEOUT_MS (15s): 1s race window.
    await assert.rejects(within(pending, 1000), /SEALED_CERT_REQUEST failed: .*disconnected/);
});

test('_sealedEmit: a normal ack still resolves, and {ok:false} still rejects with the broker message', async () => {
    const { consumer, socket } = makeSealedConsumer('sealed-ack-test');

    const okPending = consumer.setUak('alice', 'uak-b64');
    socket.emits.find((e) => e.event === 'SEALED_UAK_SET').ack({ ok: true, mode: 'require-uak' });
    const response = await within(okPending, 1000);
    assert.strictEqual(response.ok, true);
    assert.strictEqual(response.mode, 'require-uak');

    const failPending = consumer.sendSealed('realm', 'bob', 'uak', 'blob', 'm2');
    socket.emits.filter((e) => e.event === 'SEALED_DELIVER').pop().ack({ ok: false, message: 'uak mismatch' });
    await assert.rejects(within(failPending, 1000), /uak mismatch/);
});

test('_sealedEmit: callback-style API receives timeout and disconnect errors too', async () => {
    const originalTimeout = Subscriber.EMIT_ACK_TIMEOUT_MS;
    Subscriber.EMIT_ACK_TIMEOUT_MS = 50;
    try {
        const { consumer, socket } = makeSealedConsumer('sealed-callback-test');

        // (a) timeout reaches the err-first callback
        const timeoutErr = await within(new Promise((resolve) => {
            consumer.sendSealed('realm', 'bob', 'uak', 'blob', 'm3', (err) => resolve(err));
        }), 1000);
        assert.ok(timeoutErr instanceof Error, 'expected an Error on timeout');
        assert.match(timeoutErr.message, /timed out/);

        // (b) disconnect mid-wait reaches the err-first callback
        let disconnectErr = null;
        consumer.requestSenderCert('alice', 'identity-key-b64', 1, (err) => { disconnectErr = err; });
        socket.disconnect();
        assert.ok(disconnectErr instanceof Error, 'expected an Error on disconnect');
        assert.match(disconnectErr.message, /disconnected/);
    } finally {
        Subscriber.EMIT_ACK_TIMEOUT_MS = originalTimeout;
    }
});

test('sealedSubscribe: uses the larger EMIT_DRAIN_TIMEOUT_MS (ack-mode drains legitimately outlast 15s) and still resolves on ack', async () => {
    const { consumer, socket } = makeSealedConsumer('sealed-drain-timeout-test');

    const pending = consumer.sealedSubscribe('alice');
    const call = socket.emits.find((e) => e.event === 'SEALED_SUBSCRIBE');
    assert.ok(call, 'expected a SEALED_SUBSCRIBE emit');
    assert.strictEqual(call.payload.identity, 'alice');
    assert.strictEqual(call.payload.ack, true);
    assert.strictEqual(call.timeoutMs, Subscriber.EMIT_DRAIN_TIMEOUT_MS,
        'sealedSubscribe must use the drain timeout, not EMIT_ACK_TIMEOUT_MS');
    assert.ok(Subscriber.EMIT_DRAIN_TIMEOUT_MS > Subscriber.EMIT_ACK_TIMEOUT_MS);

    call.ack({ ok: true, replayed: 0, dead: 0, pending: 0, more: false });
    const response = await within(pending, 1000);
    assert.strictEqual(response.ok, true);
});

run();
