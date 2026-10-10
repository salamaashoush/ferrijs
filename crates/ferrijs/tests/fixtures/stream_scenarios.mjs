import { Readable, Writable, Duplex, Transform, PassThrough, pipeline, finished, addAbortSignal } from 'node:stream';
import * as promises from 'node:stream/promises';
const results = [];
const scenario = async (name, fn) => {
  const log = [];
  try {
    await Promise.race([fn(log), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))]);
  } catch (e) {
    log.push(['threw', e && e.message]);
  }
  results.push([name, log]);
};
const settle = () => new Promise((r) => setTimeout(r, 20));

await scenario('readable events', async (log) => {
  const r = new Readable({ read() {} });
  r.on('data', (c) => log.push(['data', c.toString()]));
  r.on('end', () => log.push(['end']));
  r.on('close', () => log.push(['close']));
  r.push('a'); r.push('b'); r.push(null);
  await settle();
});
await scenario('paused read()', async (log) => {
  const r = new Readable({ read() {} });
  r.push('xy'); r.push('z'); r.push(null);
  r.on('readable', () => { let c; while ((c = r.read(1)) !== null) log.push(['read', c.toString()]); });
  r.on('end', () => log.push(['end']));
  await settle();
});
await scenario('writable backpressure', async (log) => {
  const w = new Writable({ highWaterMark: 4, write(c, _e, cb) { log.push(['write', c.toString()]); setTimeout(cb, 1); } });
  log.push(['ok1', w.write('ab')]); log.push(['ok2', w.write('cd')]); log.push(['len', w.writableLength]);
  w.on('drain', () => log.push(['drain']));
  w.on('finish', () => log.push(['finish']));
  await settle(); w.end('e'); await settle();
});
await scenario('object mode', async (log) => {
  const r = Readable.from([{ a: 1 }, { b: 2 }]);
  for await (const o of r) log.push(['obj', JSON.stringify(o)]);
});
await scenario('transform flush', async (log) => {
  const t = new Transform({
    transform(c, _e, cb) { cb(null, c.toString() + '!'); },
    flush(cb) { this.push('done'); cb(); },
  });
  t.on('data', (c) => log.push(['data', c.toString()]));
  t.on('end', () => log.push(['end']));
  t.write('x'); t.end('y');
  await settle();
});
await scenario('pipeline ok', async (log) => {
  const out = [];
  await new Promise((resolve) => pipeline(Readable.from(['1', '2']), new PassThrough(), new Writable({ write(c, _e, cb) { out.push(c.toString()); cb(); } }), (err) => { log.push(['cb', err ? err.message : null]); resolve(); }));
  log.push(['out', out.join(',')]);
});
await scenario('pipeline error', async (log) => {
  const bad = new Transform({ transform(_c, _e, cb) { cb(new Error('nope')); } });
  await new Promise((resolve) => pipeline(Readable.from(['1']), bad, new PassThrough(), (err) => { log.push(['cb', err && err.message]); resolve(); }));
  log.push(['destroyed', bad.destroyed]);
});
await scenario('promises pipeline error', async (log) => {
  try {
    await promises.pipeline(Readable.from(['a']), new Writable({ write(_c, _e, cb) { cb(new Error('write failed')); } }));
    log.push(['resolved']);
  } catch (e) { log.push(['rejected', e.message]); }
});
await scenario('finished', async (log) => {
  const r = Readable.from(['a']);
  finished(r, (err) => log.push(['finished', err ? err.message : null]));
  r.resume();
  await settle();
});
await scenario('promises finished', async (log) => {
  const w = new Writable({ write(_c, _e, cb) { cb(); } });
  const p = promises.finished(w).then(() => log.push(['done']));
  w.end('x'); await p;
});
await scenario('destroy with error', async (log) => {
  const r = new Readable({ read() {} });
  r.on('error', (e) => log.push(['error', e.message]));
  r.on('close', () => log.push(['close', r.destroyed]));
  r.destroy(new Error('boom'));
  await settle();
});
await scenario('setEncoding split utf8', async (log) => {
  const r = new Readable({ read() {} });
  r.setEncoding('utf8');
  r.on('data', (c) => log.push(['data', c]));
  const bytes = Buffer.from('h€y');
  r.push(bytes.subarray(0, 2)); r.push(bytes.subarray(2)); r.push(null);
  await settle();
});
await scenario('duplex', async (log) => {
  const d = new Duplex({ read() { this.push('from-read'); this.push(null); }, write(c, _e, cb) { log.push(['wrote', c.toString()]); cb(); } });
  d.on('data', (c) => log.push(['data', c.toString()]));
  d.write('in'); d.end();
  await settle();
});
await scenario('pipe', async (log) => {
  const src = Readable.from(['p', 'q']);
  const dst = new Writable({ write(c, _e, cb) { log.push(['got', c.toString()]); cb(); } });
  dst.on('finish', () => log.push(['finish']));
  src.pipe(dst);
  await settle();
});
await scenario('async iterator early break', async (log) => {
  const r = Readable.from(['1', '2', '3']);
  for await (const c of r) { log.push(['c', c]); break; }
  log.push(['destroyed', r.destroyed]);
});
await scenario('abort signal', async (log) => {
  const ac = new AbortController();
  const r = addAbortSignal(ac.signal, new Readable({ read() {} }));
  r.on('error', (e) => log.push(['error', e.name]));
  ac.abort();
  await settle();
});
await scenario('readable operators', async (log) => {
  const arr = await Readable.from([1, 2, 3, 4]).filter((x) => x % 2 === 0).map((x) => x * 10).toArray();
  log.push(['arr', arr.join(',')]);
});
await scenario('highWaterMark default', async (log) => {
  log.push(['r', new Readable().readableHighWaterMark]);
  log.push(['w', new Writable().writableHighWaterMark]);
  log.push(['o', new Readable({ objectMode: true }).readableHighWaterMark]);
});
await scenario('write after end', async (log) => {
  const w = new Writable({ write(_c, _e, cb) { cb(); } });
  w.on('error', (e) => log.push(['error', e.code]));
  w.end(); w.write('late');
  await settle();
});
export default results;
