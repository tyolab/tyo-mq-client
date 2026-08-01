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

// NOTE: subscribeAll() / the no-event-name "subscribe to everything from a
// producer" path is NOT covered here. lib/subscriber.js line 12 does
// `const { constants } = require('buffer')`, which shadows the file's own
// `Constants` (tyo-mq-protocol's, imported capitalised on line 8) for the
// one lowercase use at line 101 (`eventStr = constants.EVENT_ALL`). That
// resolves to Node's buffer.constants.EVENT_ALL, which is undefined, so
// eventStr comes out undefined and events.toConsumerEvent() throws "Unknown
// event object" — i.e. subscribeAll()/subscribe(who, cb) is currently
// broken for every caller. This was discovered while writing this suite;
// it is a real lib/subscriber.js bug, not a test issue, and is out of scope
// for this test-only task — flagged in the task report instead of silently
// fixed or silently swept under an incorrect passing assertion.

run();
