import crypto from 'node:crypto';
import * as named from 'node:crypto';
const FIXTURE = {
  "jwks": {
    "rsa": {
      "kty": "RSA",
      "n": "lqFv76IVqhB9-JqcOS7vRXElUfO_h3VmNEK-qMjSYoV-j2yS7F2ZUbs_K97gCyCWvdMR236RJmXweLBxwdGrEQhMdMPKxueNPe0ZyZrOr_s5sQc4mN2n4lyhKkEgF-0DCeqnGcJ8w1u-hRbzD4DDedyxqqFlqGKNAqs5154kBvKKnY8q4AOUO3w-tRhIZBfcKfRq3SKP5ZfuSeK-Ftscvk1THX7srupon7IFgdSaFSAjwQJVdzxN6f4TZo3C5KzspXP_554d_0UIrCHqY8nhCGFHGAa-D2k2JfjLebHRecXX5tjtVOYjyH1pR3wrtUBkFykBmmgv2rrhNZ8iB1ygaw",
      "e": "AQAB",
      "d": "BluwIY8CQm3JyMmgmIVTp5G8FTZ9uiu0HGFI3PpabxAwJGuyfp8AzsNhn5TGeOcaQHmoAk-DCaTkk_jsBFYOVidh2s087PfEgtL-81SWhDUi3UcZwNIdDmAB6Ypa3sesCNTKfZAzu1H5u8fD4L6lrFTVfFytsYA0xY0RYaQ_jw9zNRiT_nId1MC9Z-YgaqHWAs1eiOHEkr0xUst1stDsNG8UC9O4a1MXNQ9gca-ebSmn_o0KWJbge8mr_0er-0P64knjf7jOs4jdXp_JdyXflAJlCESRi_szCsEgZyN5xgsAnEsMScG4MCGiDNzVguitIxvJjo7OsV727cR3KjJoCQ",
      "p": "1QGS-_F3BbjeVWE_7qGIkC-7v33q54rRDesbq4yKzRZ-OTx5zuPYVG-q7s8_f-nUX49HGvEm3GtBE6cwJ7wHtCa2y0zS3uTaoctSlQ2CiREgEmD9uZuxahthwx7GErtnPEbXvGypGi6-3j7El8oLreQjN3Uzg-OF1sDOvUXZJfc",
      "q": "tQjNePZviOh7mEOR_XT8nv1VJBWOsmUKLdQUDU01uBIc2l-jVtNKWz7PpACWwe-Rf0M_0aWmipLtwd9qYii90qTbNWGLUrC2Q4NUJxKJuJb7w-hVwFJVhBw4CjZY87DhF6JB2r0NQq51kqtKvtnSVgm5sKI55H3q02tG0mMJrC0",
      "dp": "VgxTv3m1VldvYdhuhk01KOJPmzUX7z-x4kiHHg8hh2Y9yYt3va9nlfyideS9R0RD6fKsi-K9iy-8016n4nVgO1OkZo57ZVXYSKIlk1co04xag3IxLYkK681x-ev1ol2Yf84ymsjeq1gU_R0oOBWEEFRoMaAkFnSUfcPYALg119M",
      "dq": "omfANRkXXAH8Bs_vYyqVCmiH_fQc7Ks6I3zTdE9ktroBCmKr3NN2LD8_9YfVtyudIkcJNKFfs4c2Jiuwe1jDWfos8UmNvGPtTsm9L8QwqtlACTMf4oW6U-cg2wCAcjWm6RXV8E6TW9O4hBiI2If-atMUs4IFX5camAnwIgNZBQ0",
      "qi": "SOo5c3v3rPtpX-PqMKkWizvx7vrDoVw1h7eJJXpLOSBLGL7Pqwb4dJD_vmvPsohKxr4P7hXFin1SWKYUD5DUYOAqZPXOhOA9hHFSbSH4Cbt-R_l_dJUUiAuylEu7RssF5y9eGo6-_jXMWzR-zugL-BOoZ2FUNHNQes1CnSgcgLE"
    },
    "p256": {
      "kty": "EC",
      "x": "nMsm1Zm4An16UGqU9ua8VxS1BIxkonsBbpbbx6lcJn0",
      "y": "NHLG4Y8MjUbxom4gRRivppEV8MqT01gaYOIWre8f_9A",
      "crv": "P-256",
      "d": "1fSn9472b3wOgfFnpByIOTZWsj-lb0tSWk1tGfNF-Bc"
    },
    "p384": {
      "kty": "EC",
      "x": "2QXVcO4RTLnvlO7K7VOSTDMhr1lAML96f_fpeNsPpGvIV__xmNI3tOeIJ7mcrnHb",
      "y": "PryQR3lGu8E74qNFM18zy-_P2OrHf0t_aArKi7J2kChy6Gs7K-RMh4_A-xLXZB0_",
      "crv": "P-384",
      "d": "WgaGQDqHV5nFMNTuSDDdH239k89K4vLueTvczsd9mZdiGZHgR2hRjmJLbBOjwnKE"
    },
    "p521": {
      "kty": "EC",
      "x": "AWB2h2rR2sw4v1iv_4fHbqMjeHT6_ExHFJgiSLvkwJKdOPp-gVUA095eP0TjdgnL9Q8ntNgzfh4qnda7gbmauNt6",
      "y": "AfxRXfhLHl-mKGmYNtr7Y11PpQK0jwM32Lt2KaPTpuf8LVIGrEJ3qM01ZEkRhGtUeD6VKNyUDTt5JOQ7VZpjlPQQ",
      "crv": "P-521",
      "d": "ATdZjHdCGvECnXnASVCbIWWam7UROIM0dRqmBsOgTgln9RGTivfgtCyKyEgr94wh4rlIg3L-26BGlQCv_riDwo8r"
    },
    "ed25519": {
      "crv": "Ed25519",
      "d": "WZ4SL5L6Pg3LZAZ019V5nfY4PcWLCD_pBg1aJ1m-4cQ",
      "x": "DP0n15XzqVImNjA-taTBEhEptpVHDTZkNHR-HFJ8FXg",
      "kty": "OKP"
    }
  },
  "signatures": {
    "p256_der": "MEUCIE63xCCkHsk+7a0fgHePWWsMYEubZqqQDybfRVmvpiZVAiEAgw0Zv+cki5Vc5FCxUMGMTsQlAgsBR1P+YTdxj5jS78E=",
    "p256_p1363": "LypHpougJnbM79p5OrHghgEb157V/yXUyfbTHLYh/YLbi2DEhWfyC/pkwxT/Xqa43DEEux6zmzPdl5EZ4PBbnw==",
    "p384_der": "MGUCMAhZj8o5J4F573LUSv1GM9+iNmJ9FSKo/YTjKIK5NeynMT6YFdGjVK7r9k1n1naAPgIxAP2VD59e5b4BqQ+Q/GIsgBmbu+peBDWNGe8FoVISM6etrK8wE9CwDCtA7T+vZNyZJQ==",
    "p521_der": "MIGGAkFS7ZmtW18H7zAk1hOKbs8yfYzNH5KbqryIupMM/C7fWM43+avK/AiZcRQUe6DESvnJXWUj8AXnk+CNpepI4pi+YwJBGJPpYrbYt+jQ4cmSOGPPY3WagWPB2+3WSE+BBvmKXizEzeHpRRAHT8jWAAku+cWdMlMcemOTMJtqsz5D9ix9e8s=",
    "rsa_pss_digest": "SOkqZNXkIcpq607lsgWmR1GW5kIlbgS5lSxynWya54QSOEQ6ypM5/HHUDU6J2NbtSBj3v4CrYfgIzop/K6DbIQZrHpoJ2wGYO4FFbkcH+F8gPnjzYnB1V9nZ5GSzEzY5YOlMR02zLL3VkjR9BKrNXz+bfYJNZgaRDy7sZfYCuqcbD/nxqXoAKduM+wmSvW1UYD3HY6m4m5LM09RzuvL+F25hQ5OuJ9O9KLB5Lw2++chMwZyXBvr5fAKaOy5XOblYvkcA1GgN9MTD8FCqh4XSM2upgJUaykxrCosMZ93ZonkvuShLHMQm8Co+Z6IUptBMdFLVPaQ2Y40rwLIpN7oKmA==",
    "rsa_pss_max": "GrtxApw+tvnRgBmN4IIcO5X7TPxcXaJLK7hJwRDajmPsCkdkve2fBGWbl0r3Syr6rFTp/Ikhaokl8AD+UCZYxZI1niwxPxMowX6yQ3mskb1DCrmeGIyx/VjJltMgXMln2IldSh8qyB+bmFkjxpkqV7bNJiZK3+bo0YRhxzBIijuTaXDpQxGmmMsLxx2R2lFfiUjU5MSLDfw8JxyjWmHZz1xy7E/s9Sv4XqzLVZDpSkQqiwAuWC1Qd64UnTP4+TKgA0iyeyOjtmNlJcQ02HbPIEmcSaYEzjp9aDnpxUCd71WTw/AGnam60zUmoghB9wn5s0m19nBYGqDU0UB0AXITJA=="
  },
  "certificate": "-----BEGIN CERTIFICATE-----\nMIICqjCCAZICCQD12usbn9UmtjANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtl\neGFtcGxlLmNvbTAgFw0yNjEwMTAxMjM4MjBaGA8yMTI2MDkxNjEyMzgyMFowFjEU\nMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQCWoW/vohWqEH34mpw5Lu9FcSVR87+HdWY0Qr6oyNJihX6PbJLsXZlRuz8r\n3uALIJa90xHbfpEmZfB4sHHB0asRCEx0w8rG54097RnJms6v+zmxBziY3afiXKEq\nQSAX7QMJ6qcZwnzDW76FFvMPgMN53LGqoWWoYo0CqznXniQG8oqdjyrgA5Q7fD61\nGEhkF9wp9GrdIo/ll+5J4r4W2xy+TVMdfuyu6mifsgWB1JoVICPBAlV3PE3p/hNm\njcLkrOylc//nnh3/RQisIepjyeEIYUcYBr4PaTYl+Mt5sdF5xdfm2O1U5iPIfWlH\nfCu1QGQXKQGaaC/auuE1nyIHXKBrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA2d\n+PTrqoe8AUpS/0R31CZnCyT/aOXgxnH9o9cH7rZPNTAHq5skfhM6TwUbrQHhJImv\nFYj7E628gBx9AE06hoiFqBS7FrSsQZ4oSXCYIp3MjFYjNbiZQ2bh3X1X7Ey+fGQh\nMasA3L/3/VWRLQblgUDdS/IN4fuZDOZgiinEbEN2YdXC3afFVMaZhCd/lKeAqp2T\n4h5S604FPy9e66R6yKiABtRdj+ukf44gEFUhLuoGjCI8/9VTyBKW3xXGX15UMOqi\noF8CM8kIwC3xaUIjdLD31Z3hdAtCa/BuATgkpr4OvGQf3Gq8siMQd5ZmKSSwttGA\nEtZg2E/8zxK557B9fh0=\n-----END CERTIFICATE-----\n"
};
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
    const value = fn();
    return ['returned', typeof value === 'object' && value !== null ? Object.prototype.toString.call(value) : value];
  } catch (e) {
    return ['threw', e.name, e.code, e.message];
  }
};
const hex = (b) => Buffer.from(b).toString('hex');
const digest = (data) => crypto.createHash('sha256').update(data).digest('hex');
const message = Buffer.from('a message to sign');
const same = (a, b) =>
  a.type === b.type &&
  JSON.stringify(a.export({ format: 'jwk' })) === JSON.stringify(b.export({ format: 'jwk' }));
const plain = (o) => JSON.parse(JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? `${v}n` : v)));

const privateKeys = {};
const publicKeys = {};
for (const [name, jwk] of Object.entries(FIXTURE.jwks)) {
  privateKeys[name] = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  publicKeys[name] = crypto.createPublicKey(privateKeys[name]);
}

await scenario('exports', (log) => {
  for (const name of ['KeyObject', 'createSecretKey', 'createPublicKey', 'createPrivateKey', 'generateKeyPair',
    'generateKeyPairSync', 'Sign', 'Verify', 'createSign', 'createVerify', 'sign', 'verify', 'timingSafeEqual',
    'createHmac', 'createHash']) {
    log.push([name, typeof crypto[name], typeof named[name], crypto[name] === named[name]]);
  }
  log.push(crypto.subtle === globalThis.crypto.subtle);
  log.push(Object.entries(crypto.constants).filter(([k]) => k.startsWith('RSA_') || k.startsWith('POINT_')));
});

for (const name of Object.keys(FIXTURE.jwks)) {
  await scenario(`key ${name}`, (log) => {
    const priv = privateKeys[name];
    const pub = publicKeys[name];
    for (const key of [priv, pub]) {
      log.push([key.type, key.asymmetricKeyType, plain(key.asymmetricKeyDetails), key.symmetricKeySize,
        Object.prototype.toString.call(key), key.constructor.name, key instanceof crypto.KeyObject]);
    }
    log.push(plain(priv.export({ format: 'jwk' })), plain(pub.export({ format: 'jwk' })));
    const privateTypes = name === 'rsa' ? ['pkcs8', 'pkcs1'] : name === 'ed25519' ? ['pkcs8'] : ['pkcs8', 'sec1'];
    const publicTypes = name === 'rsa' ? ['spki', 'pkcs1'] : ['spki'];
    for (const type of privateTypes) {
      const pem = priv.export({ type, format: 'pem' });
      const der = priv.export({ type, format: 'der' });
      // Digests rather than the keys, so the recording holds no private
      // key, and still pins every byte.
      log.push([type, pem.slice(11, pem.indexOf('-----', 11)), digest(pem), digest(der)]);
      log.push([
        same(crypto.createPrivateKey(pem), priv),
        same(crypto.createPrivateKey({ key: der, format: 'der', type }), priv),
        same(crypto.createPublicKey(pem), pub),
        same(crypto.createPublicKey({ key: der, format: 'der', type }), pub),
      ]);
    }
    for (const type of publicTypes) {
      const pem = pub.export({ type, format: 'pem' });
      const der = pub.export({ type, format: 'der' });
      log.push([type, pem, hex(der)]);
      log.push([
        crypto.createPublicKey(pem).equals(pub),
        crypto.createPublicKey({ key: der, format: 'der', type }).equals(pub),
        crypto.createPublicKey(Buffer.from(pem)).equals(pub),
      ]);
    }
    log.push(crypto.createPublicKey({ key: pub.export({ format: 'jwk' }), format: 'jwk' }).equals(pub));
    log.push([priv.equals(pub), pub.equals(priv), priv.equals(privateKeys[name])]);
  });
}

await scenario('deterministic signatures', (log) => {
  for (const digest of ['sha256', 'sha384', 'sha512', 'RSA-SHA256', 'SHA256', 'sha256WithRSAEncryption']) {
    const signature = crypto.createSign(digest).update(message).sign(privateKeys.rsa);
    log.push([digest, hex(signature)]);
    log.push(crypto.createVerify(digest).update(message).verify(publicKeys.rsa, signature));
    log.push(crypto.verify(digest, message, publicKeys.rsa, signature));
  }
  const streamed = crypto.createSign('sha256');
  streamed.update('a message ').update(Buffer.from('to ')).update('7369676e', 'hex');
  log.push(streamed.sign(privateKeys.rsa, 'base64'));
  log.push(hex(crypto.sign(null, message, privateKeys.rsa)));
  log.push(hex(crypto.sign(undefined, message, privateKeys.ed25519)));
  log.push(crypto.verify(null, message, publicKeys.ed25519, crypto.sign(null, message, privateKeys.ed25519)));
  log.push(crypto.verify(null, Buffer.from('another'), publicKeys.ed25519,
    crypto.sign(null, message, privateKeys.ed25519)));
  const tampered = crypto.sign('sha256', message, privateKeys.rsa);
  tampered[0] ^= 1;
  log.push(crypto.verify('sha256', message, publicKeys.rsa, tampered));
  const pem = privateKeys.rsa.export({ type: 'pkcs1', format: 'pem' });
  log.push(hex(crypto.createSign('sha256').update(message).sign(pem)));
  log.push(hex(crypto.createSign('sha256').update(message).sign({ key: pem })));
  log.push(crypto.createVerify('sha256').update(message).verify(
    publicKeys.rsa.export({ type: 'spki', format: 'pem' }),
    crypto.sign('sha256', message, privateKeys.rsa).toString('hex'),
    'hex',
  ));
  log.push(crypto.verify('sha256', message, privateKeys.rsa, crypto.sign('sha256', message, privateKeys.rsa)));
});

await scenario('signatures Node made', (log) => {
  const s = (name) => Buffer.from(FIXTURE.signatures[name], 'base64');
  log.push(crypto.verify('sha256', message, publicKeys.p256, s('p256_der')));
  log.push(crypto.verify('sha256', message, { key: publicKeys.p256, dsaEncoding: 'ieee-p1363' }, s('p256_p1363')));
  log.push(crypto.verify('sha256', message, publicKeys.p256, s('p256_p1363')));
  log.push(crypto.verify('sha384', message, publicKeys.p384, s('p384_der')));
  log.push(crypto.verify('sha512', message, publicKeys.p521, s('p521_der')));
  log.push(crypto.createVerify('sha512').update(message).verify(publicKeys.p521, s('p521_der')));
  log.push(crypto.verify('sha256', message, { key: publicKeys.rsa, padding: 6, saltLength: -1 }, s('rsa_pss_digest')));
  log.push(crypto.verify('sha256', message, { key: publicKeys.rsa, padding: 6 }, s('rsa_pss_digest')));
  log.push(crypto.verify('sha256', message, publicKeys.rsa, s('rsa_pss_digest')));
});

await scenario('randomised signatures round-trip', (log) => {
  for (const [name, digest] of [['p256', 'sha256'], ['p384', 'sha384'], ['p521', 'sha512']]) {
    const der = crypto.sign(digest, message, privateKeys[name]);
    const p1363 = crypto.sign(digest, message, { key: privateKeys[name], dsaEncoding: 'ieee-p1363' });
    log.push([name, der[0], p1363.length]);
    log.push(crypto.verify(digest, message, publicKeys[name], der));
    log.push(crypto.verify(digest, message, { key: publicKeys[name], dsaEncoding: 'ieee-p1363' }, p1363));
    log.push(crypto.verify(digest, Buffer.from('other'), publicKeys[name], der));
  }
  const pss = crypto.sign('sha256', message, { key: privateKeys.rsa, padding: 6, saltLength: -1 });
  log.push(pss.length, crypto.verify('sha256', message, { key: publicKeys.rsa, padding: 6, saltLength: 32 }, pss));
  const viaConstants = crypto.createSign('RSA-SHA256').update(message).sign({
    key: privateKeys.rsa,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }, 'base64');
  log.push(crypto.createVerify('RSA-SHA256').update(message).verify({
    key: publicKeys.rsa,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }, viaConstants, 'base64'));
});

await scenario('certificate', (log) => {
  const key = crypto.createPublicKey(FIXTURE.certificate);
  log.push(key.type, key.asymmetricKeyType, key.equals(publicKeys.rsa));
  log.push(key.export({ type: 'spki', format: 'pem' }));
  log.push(crypto.verify('sha256', message, FIXTURE.certificate, crypto.sign('sha256', message, privateKeys.rsa)));
});

await scenario('secret keys', (log) => {
  const fromString = crypto.createSecretKey('a secret', 'utf8');
  const fromHex = crypto.createSecretKey('61207365637265', 'hex');
  const fromView = crypto.createSecretKey(new Uint8Array([1, 2, 3]));
  const fromBuffer = crypto.createSecretKey(new Uint8Array([9, 8, 7, 6]).buffer);
  for (const key of [fromString, fromHex, fromView, fromBuffer]) {
    log.push([key.type, key.symmetricKeySize, key.asymmetricKeyType, key.asymmetricKeyDetails, hex(key.export()),
      key.export({ format: 'jwk' }), hex(key.export({ format: 'buffer' })), key.constructor.name]);
  }
  log.push(fromString.equals(crypto.createSecretKey(Buffer.from('a secret'))), fromString.equals(fromHex));
  log.push(crypto.createHmac('sha256', fromString).update('data').digest('hex'));
  log.push(crypto.createHmac('sha256', 'a secret').update('data').digest('hex'));
});

await scenario('timingSafeEqual', (log) => {
  log.push(crypto.timingSafeEqual(Buffer.from('abc'), Buffer.from('abc')));
  log.push(crypto.timingSafeEqual(Buffer.from('abc'), Buffer.from('abd')));
  log.push(crypto.timingSafeEqual(new Uint8Array([1, 2]), new Uint16Array([0x0201]).buffer));
  log.push(caught(() => crypto.timingSafeEqual(Buffer.from('a'), Buffer.from('ab'))));
  log.push(caught(() => crypto.timingSafeEqual('a', Buffer.from('a'))));
  log.push(caught(() => crypto.timingSafeEqual(Buffer.from('a'), 1)));
});

await scenario('generated pairs', async (log) => {
  const encoded = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  log.push(typeof encoded.publicKey, encoded.publicKey.split('\n')[0], Buffer.isBuffer(encoded.privateKey));
  const signature = crypto.sign('sha256', message, { key: encoded.privateKey, format: 'der', type: 'pkcs8' });
  log.push(crypto.verify('sha256', message, encoded.publicKey, signature));
  for (const [type, options] of [['rsa', { modulusLength: 2048 }], ['ec', { namedCurve: 'secp384r1' }], ['ed25519']]) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync(type, options);
    log.push([type, publicKey.type, privateKey.type, publicKey.asymmetricKeyType,
      plain({ ...privateKey.asymmetricKeyDetails, publicExponent: undefined })]);
    const digest = { rsa: 'sha256', ec: 'sha384', ed25519: null }[type];
    log.push(crypto.verify(digest, message, publicKey, crypto.sign(digest, message, privateKey)));
  }
  await new Promise((resolve) => {
    crypto.generateKeyPair('ed25519', (error, publicKey, privateKey) => {
      log.push(['callback', error, publicKey.type, privateKey.type]);
      resolve();
    });
  });
});

await scenario('errors', (log) => {
  const rsa = privateKeys.rsa;
  const cases = [
    () => crypto.createSign('nope'),
    () => crypto.createSign(1),
    () => crypto.createSign('sha256').update('x').sign(privateKeys.ed25519),
    () => crypto.createSign('sha256').update('x').sign(crypto.createSecretKey(Buffer.from('k'))),
    () => crypto.createSign('sha256').update('x').sign(publicKeys.rsa),
    () => crypto.createSign('sha256').update('x').sign(),
    () => crypto.createSign('sha256').update(1),
    () => crypto.createSign('sha256').update('x').sign({ key: rsa, padding: 1.5 }),
    () => crypto.createSign('sha256').update('x').sign({ key: privateKeys.p256, dsaEncoding: 'nope' }),
    () => crypto.createVerify('sha256').update('x').verify(crypto.createSecretKey(Buffer.from('k')), Buffer.alloc(1)),
    () => crypto.createVerify('sha256').update('x').verify(publicKeys.rsa, 5),
    () => crypto.createSecretKey(1),
    () => crypto.createSecretKey(null),
    () => crypto.createPublicKey(publicKeys.rsa),
    () => crypto.createPublicKey(123),
    () => crypto.createPublicKey({ key: 123 }),
    () => crypto.createPublicKey({ key: 'x', format: 'nope' }),
    () => crypto.createPublicKey({ key: Buffer.alloc(1), format: 'der' }),
    () => crypto.createPublicKey({ key: Buffer.alloc(1), format: 'der', type: 'nope' }),
    () => crypto.createPrivateKey(publicKeys.rsa),
    () => crypto.createPrivateKey(rsa),
    () => crypto.createPrivateKey({ key: Buffer.alloc(1), format: 'der', type: 'spki' }),
    () => crypto.createPrivateKey(123),
    () => new crypto.KeyObject('secret', {}),
    () => new crypto.KeyObject('nope', {}),
    () => rsa.equals({}),
    () => publicKeys.rsa.export(),
    () => rsa.export(),
    () => rsa.export({ format: 'nope', type: 'pkcs8' }),
    () => rsa.export({ format: 'pem', type: 'spki' }),
    () => rsa.export({ format: 'pem', type: 'sec1' }),
    () => publicKeys.rsa.export({ format: 'pem', type: 'pkcs8' }),
    () => publicKeys.p256.export({ format: 'pem', type: 'pkcs1' }),
    () => privateKeys.p256.export({ format: 'pem', type: 'pkcs1' }),
    () => rsa.export({ format: 'jwk', passphrase: 'x' }),
    () => crypto.createSecretKey(Buffer.from('k')).export({ format: 'pem' }),
    () => crypto.createSecretKey(Buffer.from('k')).export('nope'),
    () => crypto.createHmac('sha256', publicKeys.rsa),
    () => crypto.sign('sha256', message),
    () => crypto.sign('sha256', 5, rsa),
    () => crypto.sign(5, message, rsa),
    () => crypto.sign('sha256', message, rsa, 'nope'),
    () => crypto.generateKeyPairSync('nope', {}),
    () => crypto.generateKeyPairSync('rsa', {}),
    () => crypto.generateKeyPairSync('rsa'),
    () => crypto.generateKeyPairSync('ec', {}),
    () => crypto.generateKeyPairSync(1),
  ];
  for (const fn of cases) log.push(caught(fn));
});

// Last: Node's `equals` across key types leaves an error on OpenSSL's
// queue, which the next key it decodes then reports as its own failure.
await scenario('equals across key types', (log) => {
  log.push(publicKeys.rsa.equals(publicKeys.p256), privateKeys.p256.equals(privateKeys.p384));
  log.push(privateKeys.ed25519.equals(crypto.createSecretKey(Buffer.alloc(32))));
});

export default results;
