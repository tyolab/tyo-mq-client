'use strict';

const Factory = require('./lib/factory');

module.exports = {
    Factory: Factory,
    Publisher: require('./lib/publisher'),
    Subscriber: require('./lib/subscriber'),
    Authorization: require('./lib/authorization'),

    // @deprecated
    MessageQueue: Factory
};
