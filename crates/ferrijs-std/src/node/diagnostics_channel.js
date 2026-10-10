// Adapted from Node.js v24 lib/diagnostics_channel.js.
//
// Copyright Node.js contributors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// The module loads on a realm's first import, after scripts have run, so
// the built-ins it calls on a hot path are captured here rather than read
// off prototypes a script may have replaced by then.
const ReflectApply = Reflect.apply;
const ObjectSetPrototypeOf = Object.setPrototypeOf;
const ObjectGetPrototypeOf = Object.getPrototypeOf;
const ObjectDefineProperty = Object.defineProperty;
const NativePromise = Promise;
const PromiseResolve = Promise.resolve.bind(Promise);
const PromiseReject = Promise.reject.bind(Promise);
const PromiseThen = Promise.prototype.then;
const MapPrototype = Map.prototype;
const MapGet = MapPrototype.get;
const MapSet = MapPrototype.set;
const MapHas = MapPrototype.has;
const MapDelete = MapPrototype.delete;
const MapEntries = MapPrototype.entries;
const sizeGetter = Object.getOwnPropertyDescriptor(MapPrototype, 'size').get;
const mapSize = (map) => ReflectApply(sizeGetter, map, []);
const ArraySlice = Array.prototype.slice;
const ArrayIndexOf = Array.prototype.indexOf;
const ArrayConcat = Array.prototype.concat;
const ArrayAt = Array.prototype.at;
const ArraySplice = Array.prototype.splice;
const nextTick = globalThis.process?.nextTick ?? globalThis.queueMicrotask;

// Node's `determineSpecificType`, which ends every ERR_INVALID_ARG_TYPE
// message.
function received(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  switch (typeof value) {
    case 'bigint':
      return `type bigint (${value}n)`;
    case 'number':
      if (value === 0) return 1 / value === -Infinity ? 'type number (-0)' : 'type number (0)';
      return `type number (${value})`;
    case 'boolean':
      return `type boolean (${value})`;
    case 'symbol':
      return `type symbol (${String(value)})`;
    case 'function':
      return `function ${value.name}`;
    case 'object':
      if (value.constructor && 'name' in value.constructor) return `an instance of ${value.constructor.name}`;
      return Object.prototype.toString.call(value);
    case 'string': {
      const shown = value.length > 28 ? `${value.slice(0, 25)}...` : value;
      return shown.indexOf("'") === -1 ? `type string ('${shown}')` : `type string (${JSON.stringify(shown)})`;
    }
    default:
      return String(value);
  }
}

function invalidArgType(name, expected, value) {
  const kind = name.includes('.') ? 'property' : 'argument';
  const error = new TypeError(`The "${name}" ${kind} must be ${expected}. Received ${received(value)}`);
  error.code = 'ERR_INVALID_ARG_TYPE';
  return error;
}

function validateFunction(value, name) {
  if (typeof value !== 'function') throw invalidArgType(name, 'of type function', value);
}

// Node reports a subscriber's exception as uncaught on a later tick, so
// one failing subscriber neither stops the others nor reaches the
// publisher.
function reportUncaught(err) {
  nextTick(() => {
    throw err;
  });
}

// Node's `internal/util` WeakReference: weak until the first incRef,
// strong while the count is above zero.
class WeakReference {
  #weak;
  #strong = null;
  #count = 0;

  constructor(object) {
    this.#weak = new WeakRef(object);
  }

  incRef() {
    this.#count++;
    if (this.#count === 1) this.#strong = this.#weak.deref();
    return this.#count;
  }

  decRef() {
    this.#count--;
    if (this.#count === 0) this.#strong = null;
    return this.#count;
  }

  get() {
    return this.#weak.deref();
  }
}

// A channel lives while something holds it or subscribes to it; only the
// collector may drop a name, since a count of zero can rise again.
class WeakRefMap {
  #map = new Map();
  #finalizers = new FinalizationRegistry((key) => {
    if (!this.has(key)) ReflectApply(MapDelete, this.#map, [key]);
  });

  set(key, value) {
    this.#finalizers.register(value, key);
    ReflectApply(MapSet, this.#map, [key, new WeakReference(value)]);
  }

  get(key) {
    return ReflectApply(MapGet, this.#map, [key])?.get();
  }

  has(key) {
    return !!this.get(key);
  }

  incRef(key) {
    return ReflectApply(MapGet, this.#map, [key])?.incRef();
  }

  decRef(key) {
    return ReflectApply(MapGet, this.#map, [key])?.decRef();
  }
}

function markActive(channel) {
  ObjectSetPrototypeOf(channel, ActiveChannel.prototype);
  channel._subscribers = [];
  channel._stores = new Map();
}

function maybeMarkInactive(channel) {
  if (!channel._subscribers.length && !mapSize(channel._stores)) {
    ObjectSetPrototypeOf(channel, Channel.prototype);
    channel._subscribers = undefined;
    channel._stores = undefined;
  }
}

function defaultTransform(data) {
  return data;
}

function wrapStoreRun(store, data, next, transform = defaultTransform) {
  return () => {
    let context;
    try {
      context = transform(data);
    } catch (err) {
      reportUncaught(err);
      return next();
    }

    return store.run(context, next);
  };
}

class ActiveChannel {
  subscribe(subscription) {
    validateFunction(subscription, 'subscription');
    this._subscribers = ReflectApply(ArrayConcat, this._subscribers, [[subscription]]);
    channels.incRef(this.name);
  }

  unsubscribe(subscription) {
    const index = ReflectApply(ArrayIndexOf, this._subscribers, [subscription]);
    if (index === -1) return false;

    const before = ReflectApply(ArraySlice, this._subscribers, [0, index]);
    const after = ReflectApply(ArraySlice, this._subscribers, [index + 1]);
    this._subscribers = ReflectApply(ArrayConcat, before, [after]);

    channels.decRef(this.name);
    maybeMarkInactive(this);

    return true;
  }

  bindStore(store, transform) {
    const replacing = ReflectApply(MapHas, this._stores, [store]);
    if (!replacing) {
      channels.incRef(this.name);
    }
    ReflectApply(MapSet, this._stores, [store, transform]);
  }

  unbindStore(store) {
    if (!ReflectApply(MapHas, this._stores, [store])) {
      return false;
    }

    ReflectApply(MapDelete, this._stores, [store]);

    channels.decRef(this.name);
    maybeMarkInactive(this);

    return true;
  }

  get hasSubscribers() {
    return true;
  }

  publish(data) {
    const subscribers = this._subscribers;
    for (let i = 0; i < (subscribers?.length || 0); i++) {
      try {
        const onMessage = subscribers[i];
        onMessage(data, this.name);
      } catch (err) {
        reportUncaught(err);
      }
    }
  }

  runStores(data, fn, thisArg, ...args) {
    let run = () => {
      this.publish(data);
      return ReflectApply(fn, thisArg, args);
    };

    for (const [store, transform] of ReflectApply(MapEntries, this._stores, [])) {
      run = wrapStoreRun(store, data, run, transform);
    }

    return run();
  }
}

class Channel {
  constructor(name) {
    this._subscribers = undefined;
    this._stores = undefined;
    this.name = name;
    this._index = undefined;

    channels.set(name, this);
  }

  static [Symbol.hasInstance](instance) {
    const prototype = ObjectGetPrototypeOf(instance);
    return prototype === Channel.prototype || prototype === ActiveChannel.prototype;
  }

  subscribe(subscription) {
    validateFunction(subscription, 'subscription');
    markActive(this);
    this.subscribe(subscription);
  }

  unsubscribe() {
    return false;
  }

  bindStore(store, transform) {
    markActive(this);
    this.bindStore(store, transform);
  }

  unbindStore() {
    return false;
  }

  get hasSubscribers() {
    return false;
  }

  publish() {}

  runStores(data, fn, thisArg, ...args) {
    return ReflectApply(fn, thisArg, args);
  }
}

const channels = new WeakRefMap();

function channel(name) {
  const channel = channels.get(name);
  if (channel) return channel;

  if (typeof name !== 'string' && typeof name !== 'symbol') {
    throw invalidArgType('channel', 'one of type string or symbol', name);
  }

  return new Channel(name);
}

function subscribe(name, subscription) {
  return channel(name).subscribe(subscription);
}

function unsubscribe(name, subscription) {
  return channel(name).unsubscribe(subscription);
}

function hasSubscribers(name) {
  const channel = channels.get(name);
  if (!channel) return false;

  return channel.hasSubscribers;
}

const traceEvents = ['start', 'end', 'asyncStart', 'asyncEnd', 'error'];

function assertChannel(value, name) {
  if (!(value instanceof Channel)) {
    throw invalidArgType(name, 'an instance of Channel', value);
  }
}

function tracingChannelFrom(nameOrChannels, name) {
  if (typeof nameOrChannels === 'string') {
    return channel(`tracing:${nameOrChannels}:${name}`);
  }

  if (typeof nameOrChannels === 'object' && nameOrChannels !== null) {
    const channel = nameOrChannels[name];
    assertChannel(channel, `nameOrChannels.${name}`);
    return channel;
  }

  throw invalidArgType(
    'nameOrChannels',
    'of type string or an instance of TracingChannel or Object',
    nameOrChannels,
  );
}

class TracingChannel {
  constructor(nameOrChannels) {
    for (let i = 0; i < traceEvents.length; ++i) {
      const eventName = traceEvents[i];
      ObjectDefineProperty(this, eventName, {
        __proto__: null,
        value: tracingChannelFrom(nameOrChannels, eventName),
      });
    }
  }

  get hasSubscribers() {
    return (
      this.start?.hasSubscribers ||
      this.end?.hasSubscribers ||
      this.asyncStart?.hasSubscribers ||
      this.asyncEnd?.hasSubscribers ||
      this.error?.hasSubscribers
    );
  }

  subscribe(handlers) {
    for (let i = 0; i < traceEvents.length; ++i) {
      const name = traceEvents[i];
      if (!handlers[name]) continue;

      this[name]?.subscribe(handlers[name]);
    }
  }

  unsubscribe(handlers) {
    let done = true;

    for (let i = 0; i < traceEvents.length; ++i) {
      const name = traceEvents[i];
      if (!handlers[name]) continue;

      if (!this[name]?.unsubscribe(handlers[name])) {
        done = false;
      }
    }

    return done;
  }

  traceSync(fn, context = {}, thisArg, ...args) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { start, end, error } = this;

    return start.runStores(context, () => {
      try {
        const result = ReflectApply(fn, thisArg, args);
        context.result = result;
        return result;
      } catch (err) {
        context.error = err;
        error.publish(context);
        throw err;
      } finally {
        end.publish(context);
      }
    });
  }

  tracePromise(fn, context = {}, thisArg, ...args) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { start, end, asyncStart, asyncEnd, error } = this;

    function reject(err) {
      context.error = err;
      error.publish(context);
      asyncStart.publish(context);
      asyncEnd.publish(context);
      return PromiseReject(err);
    }

    function resolve(result) {
      context.result = result;
      asyncStart.publish(context);
      asyncEnd.publish(context);
      return result;
    }

    return start.runStores(context, () => {
      try {
        let promise = ReflectApply(fn, thisArg, args);
        if (!(promise instanceof NativePromise)) {
          promise = PromiseResolve(promise);
        }
        return ReflectApply(PromiseThen, promise, [resolve, reject]);
      } catch (err) {
        context.error = err;
        error.publish(context);
        throw err;
      } finally {
        end.publish(context);
      }
    });
  }

  traceCallback(fn, position = -1, context = {}, thisArg, ...args) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { start, end, asyncStart, asyncEnd, error } = this;

    function wrappedCallback(err, res) {
      if (err) {
        context.error = err;
        error.publish(context);
      } else {
        context.result = res;
      }

      asyncStart.runStores(context, () => {
        try {
          return ReflectApply(callback, this, arguments);
        } finally {
          asyncEnd.publish(context);
        }
      });
    }

    const callback = ReflectApply(ArrayAt, args, [position]);
    validateFunction(callback, 'callback');
    ReflectApply(ArraySplice, args, [position, 1, wrappedCallback]);

    return start.runStores(context, () => {
      try {
        return ReflectApply(fn, thisArg, args);
      } catch (err) {
        context.error = err;
        error.publish(context);
        throw err;
      } finally {
        end.publish(context);
      }
    });
  }
}

function tracingChannel(nameOrChannels) {
  return new TracingChannel(nameOrChannels);
}

export default {
  channel,
  hasSubscribers,
  subscribe,
  tracingChannel,
  unsubscribe,
  Channel,
};
