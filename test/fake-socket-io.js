/**
 * @file fake-socket-io.js
 *
 * A minimal stand-in for `socket.io-client`, used to unit-test tyo-mq-client
 * without a live broker. `lib/socket.js` does:
 *
 *     this.io = require('socket.io-client');
 *     ...
 *     this.socket = this.io.connect(connectString, args);
 *
 * so the fake only needs to implement `.connect(url, args)` returning an
 * object with the handful of socket.io-client Socket methods the client
 * actually calls: on/once/off/emit/listeners/removeAllListeners/flush, plus
 * a `.connected` flag and `.id`.
 *
 * installFakeIo() swaps the require-cache entry for 'socket.io-client' with
 * this fake *before* any of the client's lib/ files are first required, so
 * every `require('socket.io-client')` call anywhere in lib/ transparently
 * resolves to the fake. No production code is modified.
 */

'use strict';

function FakeSocket() {
    this.connected = false;
    this.id = 'fake-socket-' + Math.random().toString(36).slice(2);
    this._handlers = {}; // event -> [fn]
    this.emits = [];     // recorded {event, payload, ack}
}

FakeSocket.prototype.on = function (event, fn) {
    (this._handlers[event] = this._handlers[event] || []).push(fn);
    return this;
};

FakeSocket.prototype.once = function (event, fn) {
    var self = this;
    function wrapper() {
        self.off(event, wrapper);
        fn.apply(this, arguments);
    }
    return this.on(event, wrapper);
};

// Matches both call shapes the client uses: off(event) removes every
// listener for that event (Socket.prototype.off in lib/socket.js), and
// off(event, fn) removes just that one listener (authenticate() in
// lib/socket.js, which talks to the real socket.io Socket directly).
FakeSocket.prototype.off = function (event, fn) {
    if (!event) {
        this._handlers = {};
        return this;
    }
    if (!fn) {
        delete this._handlers[event];
        return this;
    }
    var list = this._handlers[event];
    if (list)
        this._handlers[event] = list.filter(function (h) { return h !== fn; });
    return this;
};

FakeSocket.prototype.listeners = function (event) {
    return this._handlers[event] || [];
};

FakeSocket.prototype.removeAllListeners = function () {
    this._handlers = {};
    return this;
};

FakeSocket.prototype.emit = function (event, payload, ack) {
    this.emits.push({ event: event, payload: payload, ack: ack });
    return this;
};

// socket.io-client >= 4.4's `socket.timeout(ms).emit(ev, payload, cb)`: cb is
// invoked `(err)` when no ack arrives within ms, `(null, response)` when the
// server acks — note the different callback shape from plain emit. The
// recorded emit keeps the plain server-side ack shape `ack(response)` so
// tests drive it exactly like a broker answering, and records `timeoutMs`
// for assertions. Deliberately does NOT replicate real socket.io's
// _clearAcks-on-disconnect behaviour, so the client's own disconnect guard
// (not socket.io's) is what disconnect tests exercise.
FakeSocket.prototype.timeout = function (ms) {
    var self = this;
    return {
        emit: function (event, payload, cb) {
            var settled = false;
            var timer = setTimeout(function () {
                if (settled) return;
                settled = true;
                cb(new Error('operation has timed out'));
            }, ms);
            self.emits.push({
                event: event,
                payload: payload,
                timeoutMs: ms,
                ack: function (response) {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    cb(null, response);
                }
            });
            return self;
        }
    };
};

FakeSocket.prototype.flush = function () {};

FakeSocket.prototype.disconnect = function () {
    this.connected = false;
    this._trigger('disconnect');
};

// Simulate the server pushing an event down to this socket.
FakeSocket.prototype._trigger = function (event, data) {
    (this._handlers[event] || []).slice().forEach(function (fn) { fn(data); });
};

// Simulate a successful socket.io connection: real socket.io sets
// socket.connected = true just before firing 'connect' — client code
// (sendMessage) checks socket.connected synchronously inside the 'connect'
// handler chain, so order matters here.
FakeSocket.prototype._simulateConnect = function () {
    this.connected = true;
    this._trigger('connect');
};

function FakeIo() {
    this.connections = []; // every FakeSocket created via .connect()
}

FakeIo.prototype.connect = function (url, args) {
    var socket = new FakeSocket();
    socket.url = url;
    socket.args = args;
    this.connections.push(socket);
    return socket;
};

// io(url) is also a valid socket.io-client entry point; not used by
// lib/socket.js today (it calls this.io.connect(...)) but wired up for
// completeness/future-proofing.
FakeIo.prototype.io = FakeIo.prototype.connect;

/**
 * Replace the cached 'socket.io-client' module with a fresh FakeIo instance
 * and return it. Must be called before the first `require('./lib/socket')`
 * (directly or transitively via factory/subscriber/publisher) in a process.
 */
function installFakeIo() {
    var fake = new FakeIo();
    var resolved = require.resolve('socket.io-client');
    require.cache[resolved] = {
        id: resolved,
        filename: resolved,
        loaded: true,
        exports: fake
    };
    return fake;
}

module.exports = { installFakeIo: installFakeIo, FakeSocket: FakeSocket, FakeIo: FakeIo };
