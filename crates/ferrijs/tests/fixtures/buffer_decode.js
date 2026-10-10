const out = [];
const hex = ['', 'a', 'ab', 'abc', 'abcd', 'zz', 'a1zz22', 'A1b2', ' ab', 'ab ', '0x1f', 'ff00ff', 'gg11', '1', 'deadbeef1'];
const b64 = ['', 'Y', 'YQ', 'YQ=', 'YQ==', 'YWI', 'YWJj', 'YWJjZA', 'YWJjZA==', 'Y Q = =', 'Y!Q', 'YQ==YQ==', '-_-_', '+/+/', 'YW Jj\nZA', '====', 'Y=Q', 'aGVsbG8gd29ybGQ', 'aGVsbG8*d29ybGQ=', '\tYWJj\r\n'];
for (const s of hex) {
  try { out.push(['hex', s, Array.from(Buffer.from(s, 'hex')), Buffer.byteLength(s, 'hex')]); } catch (e) { out.push(['hex', s, 'throw ' + e.name]); }
}
for (const s of b64) {
  for (const enc of ['base64', 'base64url']) {
    try { out.push([enc, s, Array.from(Buffer.from(s, enc))]); } catch (e) { out.push([enc, s, 'throw ' + e.name]); }
  }
}
const w = Buffer.alloc(8);
out.push(['write hex', w.write('a1zz', 'hex'), Array.from(w)]);
out.push(['write b64', w.write('Y!Q', 0, 'base64'), Array.from(w)]);
return out;
