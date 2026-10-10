const out = [];
const attempt = (label, fn) => {
  try {
    const v = fn();
    out.push([label, v instanceof Uint8Array ? ['bytes', Array.from(v)] : v]);
  } catch (e) {
    out.push([label, ['throw', e.name, e.code ?? null]]);
  }
};
const hay = [Buffer.from(''), Buffer.from('a'), Buffer.from('abcabcabc'), Buffer.from('a,b,,c'), Buffer.from('héllo wörld'), Buffer.from('aaaa'), Buffer.from('abcabc', 'utf16le'), Buffer.from([0, 1, 2, 255, 1, 2])];
const needles = ['', 'a', 'abc', 'c', ',', ',,', 'ö', 'zz', 'abcabcabcabc', 97, 98, 256 + 97, -1, 1.9, 255, Buffer.from('bc'), Buffer.from(''), new Uint8Array([1, 2]), 'b'];
const offsets = [undefined, 0, 1, 2, 5, -1, -3, -100, 100, 2.7, -2.5, NaN, null, '3', 'utf8', 'hex', 'ucs2', 'latin1'];
const encodings = [undefined, 'utf8', 'hex', 'ucs2', 'latin1', 'base64', 'bogus'];
hay.forEach((h, hi) => needles.forEach((n, ni) => offsets.forEach((o, oi) => {
  const label = `${hi}/${ni}/${oi}`;
  attempt('indexOf ' + label, () => h.indexOf(n, o));
  attempt('lastIndexOf ' + label, () => h.lastIndexOf(n, o));
  attempt('includes ' + label, () => h.includes(n, o));
})));
hay.forEach((h, hi) => ['abc', 'ab', '61', 'YQ==', 'ö', 'b', ''].forEach((n, ni) => encodings.forEach((e, ei) => {
  attempt(`enc indexOf ${hi}/${ni}/${ei}`, () => h.indexOf(n, 0, e));
  attempt(`enc lastIndexOf ${hi}/${ni}/${ei}`, () => h.lastIndexOf(n, undefined, e));
})));
attempt('bad value', () => Buffer.from('abc').indexOf({}));
attempt('bad this', () => Buffer.prototype.indexOf.call([1, 2], 1));
const fills = [
  ['a'], ['abc'], [''], ['ö'], ['é', 'latin1'], ['é', 'utf8'], ['61', 'hex'], ['zz', 'hex'], ['YWI=', 'base64'], ['ab', 'ucs2'],
  [0], [257], [-1], [1.9], [NaN], [true], [Buffer.from('xy')], [new Uint8Array(0)], [{}],
  ['ab', 1], ['ab', 1, 4], ['ab', 1, 'hex'], ['ab', 'utf8'], ['ab', 2, 2], ['ab', 4, 2], ['ab', -1], ['ab', 1.5], ['ab', 0, 99], ['ab', '1'],
  [7, 2, 5], [7, 9], [7, 3, 3], ['ab', 0, 6, 'bogus'], ['ab', 0, 6, 5],
];
fills.forEach((args, i) => attempt('fill ' + i, () => Buffer.alloc(6).fill(...args)));
const a = Buffer.from('abcd'), b = Buffer.from('abce'), c = Buffer.from('abc');
attempt('Buffer.compare ab', () => Buffer.compare(a, b));
attempt('Buffer.compare ba', () => Buffer.compare(b, a));
attempt('Buffer.compare aa', () => Buffer.compare(a, Buffer.from('abcd')));
attempt('Buffer.compare ac', () => Buffer.compare(a, c));
attempt('Buffer.compare bad', () => Buffer.compare(a, 'abcd'));
attempt('sort', () => [b, c, a].sort(Buffer.compare).map((x) => x.toString()));
const ranges = [[], [0], [1], [0, 2], [1, 3, 1, 3], [0, 4, 0, 2], [2, 2], [0, 4, 3, 3], [5], [0, 5], [0, 4, 0, 5], [1.5], [-1], [undefined, undefined, 1]];
ranges.forEach((r, i) => attempt('compare ' + i, () => a.compare(b, ...r)));
attempt('compare bad', () => a.compare('x'));
for (const n of [2, 4, 8]) {
  attempt('swap ok ' + n, () => Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])['swap' + n * 8]());
  attempt('swap bad ' + n, () => Buffer.from([1, 2, 3])['swap' + n * 8]());
}
attempt('swap empty', () => Buffer.alloc(0).swap16());
return out;
