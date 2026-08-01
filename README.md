# tyo-mq-client

The tyo-mq pub/sub client for Node & the browser. **Apache-2.0.**

> **Building an app on tyo-mq? This is the package you want.** Apache-2.0,
> no AGPL, no server dependencies — just a client that talks to a tyo-mq
> broker over the network.

## Installation

    npm install tyo-mq-client

## Usage

```javascript
const { Factory } = require('tyo-mq-client');

const mq = new Factory({ host: 'localhost', port: 8080 });

// producer
mq.createProducer('testevent').then((producer) => {
    // produce a default event with data {data: 'test'}
    producer.produce('test text from default event');

    // produce a different kind of event
    producer.produce('event2', { data: 'test text from event2' });
});

// consumer
mq.createConsumer().then((consumer) => {
    consumer.subscribe('event2', (data) => {
        console.log(data);
    });

    consumer.subscribe('testevent', (data) => {
        console.log(data);
    });
});
```

`Factory` also has `createSubscriber` (alias of `createConsumer`) and
callback-style overloads if you'd rather not use promises. Consumers and
producers support durable delivery with ACK/retry, topic wildcards,
consumer groups, and broadcast — see the
[tyo-mq README](https://github.com/tyolab/tyo-mq#readme) and the
[tyo-mq-samples](https://github.com/tyolab/tyo-mq-samples) repo for the
full feature set and runnable examples.

This package also exports `Authorization` for the client side of the
token authorization-request flow, and `Publisher`/`Subscriber` if you want
to construct them directly instead of going through `Factory`.

Talks to a tyo-mq broker (the server; AGPL — see
[tyo-mq](https://github.com/tyolab/tyo-mq)).

## License

Apache-2.0
