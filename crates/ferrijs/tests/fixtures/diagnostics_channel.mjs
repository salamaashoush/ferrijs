import dc, { channel, hasSubscribers, subscribe, unsubscribe, tracingChannel, Channel } from 'node:diagnostics_channel';
const results = [];
const scenario = async (name, fn) => {
  const log = [];
  try {
    await fn(log);
  } catch (e) {
    log.push(['threw', e && e.name, e && e.code, e && e.message]);
  }
  results.push([name, log]);
};
const caught = (fn) => {
  try {
    return ['returned', fn()];
  } catch (e) {
    return ['threw', e.name, e.code, e.message];
  }
};
const state = (ch) => [ch.hasSubscribers, Object.getPrototypeOf(ch) === Channel.prototype, ch instanceof Channel];

await scenario('exports', (log) => {
  log.push(Object.keys(dc));
  log.push(Object.getOwnPropertyNames(Channel.prototype));
  log.push(Object.getOwnPropertyNames(Object.getPrototypeOf(tracingChannel('exports'))));
  log.push([dc.channel === channel, dc.Channel === Channel]);
});

await scenario('channel identity and names', (log) => {
  const a = channel('identity');
  log.push([a === channel('identity'), a.name, a instanceof Channel]);
  const sym = Symbol('identity');
  const s = channel(sym);
  log.push([s === channel(sym), s.name === sym, s === channel('identity')]);
  const direct = new Channel('direct');
  log.push([direct === channel('direct'), direct instanceof Channel]);
  log.push([({}) instanceof Channel, Object.create(Channel.prototype) instanceof Channel]);
});

await scenario('invalid channel names', (log) => {
  for (const name of [1, 0, -0, NaN, null, undefined, true, 10n, {}, [], () => {}, function named() {}, new Map()]) {
    log.push(caught(() => channel(name)));
  }
});

await scenario('invalid subscriptions', (log) => {
  for (const value of [undefined, null, 'fn', 'it\'s', 'a string longer than twenty-eight chars', 42, {}]) {
    log.push(caught(() => subscribe('invalid-sub', value)));
    log.push(caught(() => channel('invalid-sub-direct').subscribe(value)));
  }
  log.push(state(channel('invalid-sub')));
});

await scenario('subscribe, publish, unsubscribe', (log) => {
  const ch = channel('pubsub');
  log.push(state(ch));
  log.push(hasSubscribers('pubsub'), hasSubscribers('never-made'));
  const one = (data, name) => log.push(['one', data, name]);
  const two = (data, name) => log.push(['two', data, name]);
  log.push(['subscribe returns', ch.subscribe(one)]);
  log.push(state(ch));
  log.push(['module subscribe returns', subscribe('pubsub', two)]);
  log.push(hasSubscribers('pubsub'));
  ch.publish({ n: 1 });
  log.push(['unsubscribe one', ch.unsubscribe(one)]);
  log.push(['unsubscribe one again', ch.unsubscribe(one)]);
  ch.publish('second');
  log.push(['module unsubscribe two', unsubscribe('pubsub', two)]);
  log.push(['unsubscribe unknown', unsubscribe('pubsub', two), unsubscribe('unknown-name', two)]);
  log.push(state(ch));
  ch.publish('nobody');
  log.push([ch._subscribers, ch._stores]);
});

await scenario('same subscriber twice', (log) => {
  const ch = channel('twice');
  const fn = (data) => log.push(['got', data]);
  ch.subscribe(fn);
  ch.subscribe(fn);
  ch.publish(1);
  log.push(ch.unsubscribe(fn), ch.hasSubscribers);
  ch.publish(2);
  log.push(ch.unsubscribe(fn), ch.hasSubscribers);
});

await scenario('changes during publish', (log) => {
  const ch = channel('during');
  const late = (data) => log.push(['late', data]);
  const second = (data) => log.push(['second', data]);
  const first = (data) => {
    log.push(['first', data]);
    ch.unsubscribe(second);
    ch.subscribe(late);
  };
  ch.subscribe(first);
  ch.subscribe(second);
  ch.publish('a');
  ch.publish('b');
});

await scenario('stores', (log) => {
  const ch = channel('stores');
  const store = (label) => ({
    run(context, fn, ...rest) {
      log.push(['run', label, context, rest.length]);
      const out = fn();
      log.push(['ran', label]);
      return out;
    },
  });
  const a = store('a');
  const b = store('b');
  log.push(['bind returns', ch.bindStore(a)]);
  log.push(state(ch));
  ch.bindStore(b, (data) => ({ wrapped: data }));
  ch.subscribe((data) => log.push(['subscriber', data]));
  const out = ch.runStores({ v: 1 }, function (x, y) {
    log.push(['fn', this.tag, x, y]);
    return 'result';
  }, { tag: 'this' }, 'x', 'y');
  log.push(['out', out]);
  ch.bindStore(a, (data) => 'replaced');
  ch.runStores('again', () => log.push(['fn again']));
  log.push(['unbind a', ch.unbindStore(a), ch.unbindStore(a)]);
  log.push(['unbind b', ch.unbindStore(b)]);
  log.push(state(ch));
  const inactive = channel('stores-inactive');
  log.push(['inactive runStores', inactive.runStores('d', (p) => p * 2, null, 21)]);
  log.push(['inactive unbind', inactive.unbindStore(a), inactive.unsubscribe(() => {})]);
});

await scenario('stores keep the channel active', (log) => {
  const ch = channel('store-only');
  const store = { run: (ctx, fn) => fn() };
  ch.bindStore(store);
  const fn = () => {};
  ch.subscribe(fn);
  ch.unsubscribe(fn);
  log.push(state(ch));
  ch.unbindStore(store);
  log.push(state(ch));
});

await scenario('tracing channel names', (log) => {
  const tc = tracingChannel('names');
  log.push(['start', 'end', 'asyncStart', 'asyncEnd', 'error'].map((k) => tc[k].name));
  log.push(['start', 'end', 'asyncStart', 'asyncEnd', 'error'].map((k) => tc[k] === channel(`tracing:names:${k}`)));
  log.push(Object.getOwnPropertyDescriptor(tc, 'start').writable, Object.keys(tc));
  log.push(tc.hasSubscribers);
});

await scenario('tracing channel from channels', (log) => {
  const parts = {
    start: channel('o:start'),
    end: channel('o:end'),
    asyncStart: channel('o:asyncStart'),
    asyncEnd: channel('o:asyncEnd'),
    error: channel('o:error'),
  };
  const tc = tracingChannel(parts);
  log.push(tc.start === parts.start, tc.error === parts.error);
  log.push(caught(() => tracingChannel({ ...parts, asyncEnd: 'nope' })));
  // Node's own TypeError from reading the prototype of undefined; the
  // engines word it differently.
  log.push(caught(() => tracingChannel({})).slice(0, 2));
  for (const bad of [1, null, undefined, true, () => {}]) {
    log.push(caught(() => tracingChannel(bad)));
  }
});

const record = (log, prefix) => {
  const handlers = {};
  for (const event of ['start', 'end', 'asyncStart', 'asyncEnd', 'error']) {
    handlers[event] = (ctx, name) => {
      log.push([prefix + event, typeof name === 'string' ? name : String(name), { ...ctx, error: ctx.error && ctx.error.message }]);
    };
  }
  return handlers;
};

await scenario('traceSync', (log) => {
  const tc = tracingChannel('sync');
  log.push(['no subscribers', tc.traceSync(function (a) { return [this?.t, a]; }, {}, { t: 1 }, 'arg')]);
  const handlers = record(log, '');
  log.push(['subscribe returns', tc.subscribe(handlers)]);
  log.push(tc.hasSubscribers);
  log.push(['ok', tc.traceSync((a, b) => a + b, { id: 1 }, null, 2, 3)]);
  log.push(caught(() => tc.traceSync(() => { throw new Error('sync boom'); }, { id: 2 })));
  log.push(['default context', tc.traceSync(() => 'x')]);
  log.push(['unsubscribe returns', tc.unsubscribe(handlers), tc.unsubscribe(handlers)]);
  log.push(tc.hasSubscribers);
});

await scenario('tracePromise', async (log) => {
  const tc = tracingChannel('promise');
  const handlers = record(log, '');
  tc.subscribe(handlers);
  const ok = tc.tracePromise(async (v) => v * 2, { id: 1 }, null, 21);
  log.push(['returned a promise', ok instanceof Promise]);
  log.push(['ok', await ok]);
  try {
    await tc.tracePromise(async () => { throw new Error('async boom'); }, { id: 2 });
  } catch (e) {
    log.push(['rejected', e.message]);
  }
  const thenable = tc.tracePromise(() => ({ then(r) { r('from thenable'); } }), { id: 3 });
  log.push(['thenable', await thenable]);
  log.push(['plain value', await tc.tracePromise(() => 7, { id: 4 })]);
  log.push(caught(() => tc.tracePromise(() => { throw new Error('sync in promise'); }, { id: 5 })));
  tc.unsubscribe(handlers);
  log.push(['no subscribers', tc.tracePromise(() => 'raw', { id: 6 })]);
});

await scenario('traceCallback', async (log) => {
  const tc = tracingChannel('callback');
  const handlers = record(log, '');
  tc.subscribe(handlers);
  const fn = function (a, cb, b) {
    log.push(['fn', a, b, typeof cb, this && this.t]);
    cb(null, a + b);
    return 'sync';
  };
  log.push(['returns', tc.traceCallback(fn, 1, { id: 1 }, { t: 'this' }, 1, function (err, res) {
    log.push(['cb', err, res, this && this.t]);
  }, 2)]);
  const failing = (cb) => cb(new Error('cb boom'));
  tc.traceCallback(failing, 0, { id: 2 }, null, (err) => log.push(['cb err', err.message]));
  tc.traceCallback((x, cb) => cb(null, x), undefined, { id: 3 }, null, 'last', (err, res) => log.push(['default position', res]));
  log.push(caught(() => tc.traceCallback((cb) => cb(), 0, {}, null, 'not a function')));
  log.push(caught(() => tc.traceCallback(() => { throw new Error('throws before cb'); }, -1, { id: 4 }, null, () => {})));
  tc.unsubscribe(handlers);
  log.push(['no subscribers', tc.traceCallback((cb) => typeof cb, 0, {}, null, 'not checked')]);
});

await scenario('partial tracing subscribers', (log) => {
  const tc = tracingChannel('partial');
  const end = (ctx) => log.push(['end only', ctx.result]);
  tc.subscribe({ end });
  log.push(tc.hasSubscribers, tc.start.hasSubscribers);
  tc.traceSync(() => 'value', {});
  log.push(['unsubscribe end and missing', tc.unsubscribe({ end, start: () => {} })]);
  log.push(['unsubscribe end', tc.unsubscribe({ end })]);
});

export default results;
