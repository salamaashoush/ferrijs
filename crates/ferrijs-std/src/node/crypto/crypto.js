// The `KeyObject` classes and signing functions of `node:crypto`, shaped
// after Node's lib/internal/crypto/keys.js and sig.js. Key material and
// every cryptographic operation stay native; this is the argument
// handling and the class structure Node scripts rely on.
//
// `load` runs the first time a realm uses one of these members, and
// answers them for `mod.rs` to forward to.

export default function load(native, crypto) {
  const { Buffer } = globalThis;
  const ReflectApply = Reflect.apply;
  const isView = ArrayBuffer.isView;
  const isArrayBuffer = (value) =>
    value instanceof ArrayBuffer || (typeof SharedArrayBuffer === 'function' && value instanceof SharedArrayBuffer);
  const baseCreateHash = crypto.createHash;
  const baseCreateHmac = crypto.createHmac;
  const defer = globalThis.queueMicrotask;

  // Node's internal/errors message builders, for the codes used here.
  const kTypes = ['string', 'function', 'number', 'object', 'Function', 'Object', 'boolean', 'bigint', 'symbol'];
  const classRegExp = /^([A-Z][a-z0-9]*)+$/;

  function formatList(array, type = 'and') {
    return array.length < 3
      ? array.join(` ${type} `)
      : `${array.slice(0, -1).join(', ')}, ${type} ${array[array.length - 1]}`;
  }

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
      default: {
        const shown = value.length > 28 ? `${value.slice(0, 25)}...` : value;
        return shown.indexOf("'") === -1 ? `type string ('${shown}')` : `type string (${JSON.stringify(shown)})`;
      }
    }
  }

  function inspect(value) {
    switch (typeof value) {
      case 'string':
        return value.indexOf("'") === -1 ? `'${value}'` : JSON.stringify(value);
      case 'bigint':
        return `${value}n`;
      case 'number':
        return Object.is(value, -0) ? '-0' : String(value);
      case 'function':
        return `[Function: ${value.name || '(anonymous)'}]`;
      case 'object':
        if (value === null) return 'null';
        try {
          return JSON.stringify(value);
        } catch {
          return Object.prototype.toString.call(value);
        }
      default:
        return String(value);
    }
  }

  function coded(Kind, code, message) {
    const error = new Kind(message);
    error.code = code;
    return error;
  }

  function invalidArgType(name, expected, actual) {
    const kind = name.includes('.') ? 'property' : 'argument';
    let message = `The "${name}" ${kind} must be `;
    const types = [];
    const instances = [];
    const other = [];
    for (const value of expected) {
      if (kTypes.includes(value)) types.push(value.toLowerCase());
      else if (classRegExp.test(value)) instances.push(value);
      else other.push(value);
    }
    if (instances.length > 0) {
      const position = types.indexOf('object');
      if (position !== -1) {
        types.splice(position, 1);
        instances.push('Object');
      }
    }
    if (types.length > 0) {
      message += `${types.length > 1 ? 'one of type' : 'of type'} ${formatList(types, 'or')}`;
      if (instances.length > 0 || other.length > 0) message += ' or ';
    }
    if (instances.length > 0) {
      message += `an instance of ${formatList(instances, 'or')}`;
      if (other.length > 0) message += ' or ';
    }
    if (other.length > 0) {
      if (other.length > 1) message += `one of ${formatList(other, 'or')}`;
      else message += `${other[0].toLowerCase() !== other[0] ? 'an ' : ''}${other[0]}`;
    }
    return coded(TypeError, 'ERR_INVALID_ARG_TYPE', `${message}. Received ${received(actual)}`);
  }

  function invalidArgValue(name, value, reason = 'is invalid') {
    const kind = name.includes('.') ? 'property' : 'argument';
    return coded(TypeError, 'ERR_INVALID_ARG_VALUE', `The ${kind} '${name}' ${reason}. Received ${inspect(value)}`);
  }

  function invalidKeyObjectType(actual, expected) {
    return coded(
      TypeError,
      'ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE',
      `Invalid key object type ${actual}, expected ${expected}.`,
    );
  }

  function incompatibleKeyOptions(first, second) {
    return coded(Error, 'ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS', `The selected key encoding ${first} ${second}.`);
  }

  function unsupported(message) {
    return coded(Error, 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM', message);
  }

  function validateObject(value, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw invalidArgType(name, ['object'], value);
    }
  }

  function validateString(value, name) {
    if (typeof value !== 'string') throw invalidArgType(name, ['string'], value);
  }

  function validateFunction(value, name) {
    if (typeof value !== 'function') throw invalidArgType(name, ['Function'], value);
  }

  function validateOneOf(value, name, oneOf) {
    if (!oneOf.includes(value)) {
      const allowed = oneOf.map((v) => (typeof v === 'string' ? `'${v}'` : String(v))).join(', ');
      throw invalidArgValue(name, value, `must be one of: ${allowed}`);
    }
  }

  const bufferTypes = ['ArrayBuffer', 'Buffer', 'TypedArray', 'DataView'];

  function toBuffer(value, name, encoding) {
    if (typeof value === 'string') return Buffer.from(value, encoding === 'buffer' ? 'utf8' : encoding);
    if (isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    if (isArrayBuffer(value)) return Buffer.from(value);
    throw invalidArgType(name, ['string', ...bufferTypes], value);
  }

  function isStringOrBuffer(value) {
    return typeof value === 'string' || isView(value) || isArrayBuffer(value);
  }

  let handleOf;
  let isKeyObject;

  class KeyObject {
    #handle;

    constructor(type, handle) {
      if (type !== 'secret' && type !== 'public' && type !== 'private') throw invalidArgValue('type', type);
      if (typeof handle !== 'object' || handle === null || !native.isHandle(handle)) {
        throw invalidArgType('handle', ['object'], handle);
      }
      this.#handle = handle;
    }

    get type() {
      return native.describe(this.#handle)[0];
    }

    equals(otherKeyObject) {
      if (!isKeyObject(otherKeyObject)) throw invalidArgType('otherKeyObject', ['KeyObject'], otherKeyObject);
      return native.equals(this.#handle, otherKeyObject.#handle);
    }

    static {
      handleOf = (key) => key.#handle;
      isKeyObject = (value) => value !== null && typeof value === 'object' && #handle in value;
    }
  }

  Object.defineProperty(KeyObject.prototype, Symbol.toStringTag, {
    __proto__: null,
    configurable: true,
    value: 'KeyObject',
  });

  class SecretKeyObject extends KeyObject {
    constructor(handle) {
      super('secret', handle);
    }

    get symmetricKeySize() {
      return native.describe(handleOf(this))[2];
    }

    export(options) {
      if (options !== undefined) {
        validateObject(options, 'options');
        validateOneOf(options.format, 'options.format', [undefined, 'buffer', 'jwk']);
        if (options.format === 'jwk') return native.exportJwk(handleOf(this));
      }
      return native.secretBytes(handleOf(this));
    }
  }

  class AsymmetricKeyObject extends KeyObject {
    get asymmetricKeyType() {
      return native.describe(handleOf(this))[1];
    }

    get asymmetricKeyDetails() {
      return { ...native.details(handleOf(this)) };
    }
  }

  // Node's parseKeyFormatAndType for an output encoding.
  function exportEncoding(options, keyType, isPublic) {
    validateObject(options, 'options');
    const { format, type } = options;
    if (format !== 'pem' && format !== 'der') throw invalidArgValue('options.format', format);
    if (type === 'pkcs1') {
      if (keyType !== 'rsa') throw incompatibleKeyOptions('pkcs1', 'can only be used for RSA keys');
    } else if (type === 'sec1' && !isPublic) {
      if (keyType !== 'ec') throw incompatibleKeyOptions('sec1', 'can only be used for EC keys');
    } else if (!((type === 'spki' && isPublic) || (type === 'pkcs8' && !isPublic))) {
      throw invalidArgValue('options.type', type);
    }
    return { format, type };
  }

  class PublicKeyObject extends AsymmetricKeyObject {
    constructor(handle) {
      super('public', handle);
    }

    export(options) {
      if (options?.format === 'jwk') return native.exportJwk(handleOf(this));
      const { format, type } = exportEncoding(options, this.asymmetricKeyType, true);
      return native.exportDer(handleOf(this), type, format === 'pem');
    }
  }

  class PrivateKeyObject extends AsymmetricKeyObject {
    constructor(handle) {
      super('private', handle);
    }

    export(options) {
      if (options?.passphrase !== undefined && options.format !== 'pem' && options.format !== 'der') {
        throw coded(
          Error,
          'ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS',
          `The selected key encoding ${options.format} does not support encryption.`,
        );
      }
      if (options?.format === 'jwk') return native.exportJwk(handleOf(this));
      const { format, type } = exportEncoding(options, this.asymmetricKeyType, false);
      if (options.cipher != null) throw unsupported('Encrypting a private key on export is not supported');
      if (options.passphrase !== undefined) {
        throw invalidArgValue('options.cipher', options.cipher, 'is required when a passphrase is specified');
      }
      return native.exportDer(handleOf(this), type, format === 'pem');
    }
  }

  function wrap(handle) {
    switch (native.describe(handle)[0]) {
      case 'secret':
        return new SecretKeyObject(handle);
      case 'public':
        return new PublicKeyObject(handle);
      default:
        return new PrivateKeyObject(handle);
    }
  }

  const kConsumePublic = 0;
  const kConsumePrivate = 1;
  const kCreatePublic = 2;
  const kCreatePrivate = 3;

  function keyTypes(allowKeyObject, allowURL) {
    return [
      ...bufferTypes,
      'string',
      ...(allowKeyObject ? ['KeyObject', 'CryptoKey'] : []),
      ...(allowURL ? ['URL'] : []),
    ];
  }

  function validateAsymmetricKeyType(type, context, key) {
    if (context === kCreatePrivate) throw invalidArgType('key', keyTypes(false, true), key);
    if (type !== 'private') {
      if (context === kConsumePrivate || context === kCreatePublic) throw invalidKeyObjectType(type, 'private');
      if (type !== 'public') throw invalidKeyObjectType(type, 'private or public');
    }
  }

  // Node's prepareAsymmetricKey: a native handle for `key` in `context`.
  function prepareAsymmetricKey(key, context, name = 'key') {
    const wantPrivate = context === kConsumePrivate || context === kCreatePrivate;
    if (isKeyObject(key)) {
      validateAsymmetricKeyType(key.type, context, key);
      return handleOf(key);
    }
    if (isStringOrBuffer(key)) {
      return native.parse(typeof key === 'string' ? key : toBuffer(key, name), 'pem', undefined, wantPrivate);
    }
    if (typeof key === 'object' && key !== null) {
      const { key: data, encoding, format, type, passphrase } = key;
      if (isKeyObject(data)) {
        validateAsymmetricKeyType(data.type, context, data);
        return handleOf(data);
      }
      if (format === 'jwk') {
        validateObject(data, `${name}.key`);
        return native.parse(data, 'jwk', undefined, wantPrivate);
      }
      if (format === 'raw-public' || format === 'raw-private' || format === 'raw-seed') {
        throw unsupported(`The ${format} key format is not supported`);
      }
      if (!isStringOrBuffer(data)) {
        throw invalidArgType(`${name}.key`, keyTypes(context !== kCreatePrivate, wantPrivate), data);
      }
      const isPublic = wantPrivate ? false : undefined;
      if (format !== undefined && format !== 'pem' && format !== 'der') {
        throw invalidArgValue(`${name}.format`, format);
      }
      if (format === 'der') {
        if (
          !(type === 'pkcs1' || (type === 'spki' && isPublic !== false) || (type === 'pkcs8' && isPublic !== true) ||
            (type === 'sec1' && isPublic !== true))
        ) {
          throw invalidArgValue(`${name}.type`, type);
        }
      }
      if (passphrase !== undefined && !isStringOrBuffer(passphrase)) {
        throw invalidArgValue(`${name}.passphrase`, passphrase);
      }
      const bytes = toBuffer(data, `${name}.key`, encoding);
      if (format === 'der') {
        const derPrivate = type === 'pkcs8' || type === 'sec1' || (type === 'pkcs1' && wantPrivate);
        return native.parse(bytes, 'der', type, derPrivate);
      }
      return native.parse(bytes, 'pem', undefined, wantPrivate);
    }
    throw invalidArgType(name, keyTypes(context !== kCreatePrivate, wantPrivate), key);
  }

  function requirePrivate(handle) {
    if (native.describe(handle)[0] !== 'private') {
      throw coded(Error, 'ERR_OSSL_UNSUPPORTED', 'error:1E08010C:DECODER routines::unsupported');
    }
    return handle;
  }

  function createSecretKey(key, encoding) {
    if (typeof key !== 'string' && !isView(key) && !isArrayBuffer(key)) {
      throw invalidArgType('key', bufferTypes, key);
    }
    return new SecretKeyObject(native.secret(toBuffer(key, 'key', encoding)));
  }

  function createPublicKey(key) {
    const handle = prepareAsymmetricKey(key, kCreatePublic);
    return new PublicKeyObject(native.publicOf(handle));
  }

  function createPrivateKey(key) {
    return new PrivateKeyObject(requirePrivate(prepareAsymmetricKey(key, kCreatePrivate)));
  }

  // OpenSSL's digest names, as `createSign` and `crypto.sign` accept them.
  const digests = { md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512' };
  const knownElsewhere = new Set(['sha224', 'sha512-224', 'sha512-256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
    'shake128', 'shake256', 'ripemd160', 'sm3', 'md5-sha1', 'blake2b512', 'blake2s256']);

  function digestName(algorithm) {
    let name = algorithm.toLowerCase();
    if (name.startsWith('rsa-')) name = name.slice(4);
    else if (name.startsWith('ecdsa-with-')) name = name.slice(11);
    if (name.endsWith('withrsaencryption')) name = name.slice(0, -17);
    if (name.startsWith('sha2-')) name = `sha${name.slice(5)}`;
    if (name === 'sha-1' || name === 'sha-256' || name === 'sha-384' || name === 'sha-512') name = name.replace('-', '');
    if (name in digests) return digests[name];
    if (knownElsewhere.has(name)) throw unsupported(`The ${algorithm} digest is not supported for signatures`);
    throw coded(TypeError, 'ERR_CRYPTO_INVALID_DIGEST', 'Invalid digest');
  }

  function intOption(name, options) {
    const value = options[name];
    if (value !== undefined) {
      if (value === value >> 0) return value;
      throw invalidArgValue(`options.${name}`, value);
    }
    return undefined;
  }

  function signOptions(options) {
    if (typeof options !== 'object' || options === null) return [undefined, undefined, true];
    const padding = intOption('padding', options);
    const saltLength = intOption('saltLength', options);
    const { dsaEncoding = 'der' } = options;
    if (dsaEncoding !== 'der' && dsaEncoding !== 'ieee-p1363') {
      throw invalidArgValue('options.dsaEncoding', dsaEncoding);
    }
    return [padding, saltLength, dsaEncoding === 'der'];
  }

  const state = new WeakMap();

  function stateOf(self) {
    const found = state.get(self);
    if (found === undefined) throw coded(TypeError, 'ERR_INVALID_THIS', 'Value of "this" must be of type Sign');
    return found;
  }

  function init(self, algorithm) {
    validateString(algorithm, 'algorithm');
    const digest = digestName(algorithm);
    state.set(self, { digest, hash: baseCreateHash(digest) });
  }

  function update(data, encoding) {
    if (typeof data === 'string') data = Buffer.from(data, encoding === 'buffer' ? 'utf8' : encoding);
    else if (!isView(data)) throw invalidArgType('data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
    stateOf(this).hash.update(data);
    return this;
  }

  function Sign(algorithm, options) {
    if (!(this instanceof Sign)) return new Sign(algorithm, options);
    init(this, algorithm);
  }

  Sign.prototype.update = update;

  Sign.prototype.sign = function sign(privateKey, encoding) {
    if (!privateKey) throw coded(Error, 'ERR_CRYPTO_SIGN_KEY_REQUIRED', 'No key provided to sign');
    const handle = prepareAsymmetricKey(privateKey, kConsumePrivate, 'privateKey');
    const [padding, saltLength, dsaDer] = signOptions(privateKey);
    const { digest, hash } = stateOf(this);
    const signature = native.signDigest(handle, digest, hash.digest(), padding, saltLength, dsaDer);
    if (encoding && encoding !== 'buffer') return signature.toString(encoding);
    return signature;
  };

  function Verify(algorithm, options) {
    if (!(this instanceof Verify)) return new Verify(algorithm, options);
    init(this, algorithm);
  }

  Verify.prototype.update = update;

  Verify.prototype.verify = function verify(key, signature, sigEncoding) {
    const handle = prepareAsymmetricKey(key, kConsumePublic, 'key');
    const [padding, saltLength, dsaDer] = signOptions(key);
    signature = toBuffer(signature, 'signature', sigEncoding);
    const { digest, hash } = stateOf(this);
    return native.verifyDigest(handle, digest, hash.digest(), signature, padding, saltLength, dsaDer);
  };

  function createSign(algorithm, options) {
    return new Sign(algorithm, options);
  }

  function createVerify(algorithm, options) {
    return new Verify(algorithm, options);
  }

  function settle(callback, run) {
    if (callback === undefined) return run();
    let result;
    let failure = null;
    try {
      result = run();
    } catch (error) {
      failure = error;
    }
    defer(() => (failure ? callback(failure) : callback(null, result)));
    return undefined;
  }

  function digestOf(algorithm, data) {
    const digest = digestName(algorithm ?? 'sha256');
    return [digest, baseCreateHash(digest).update(data).digest()];
  }

  function signOneShot(algorithm, data, key, callback) {
    if (algorithm != null) validateString(algorithm, 'algorithm');
    if (callback !== undefined) validateFunction(callback, 'callback');
    data = toBuffer(data, 'data');
    if (!key) throw coded(Error, 'ERR_CRYPTO_SIGN_KEY_REQUIRED', 'No key provided to sign');
    const [padding, saltLength, dsaDer] = signOptions(key);
    const handle = prepareAsymmetricKey(key, kConsumePrivate);
    return settle(callback, () => {
      if (native.describe(handle)[1] === 'ed25519') return native.signMessage(handle, data);
      const [digest, hashed] = digestOf(algorithm, data);
      return native.signDigest(handle, digest, hashed, padding, saltLength, dsaDer);
    });
  }

  function verifyOneShot(algorithm, data, key, signature, callback) {
    if (algorithm != null) validateString(algorithm, 'algorithm');
    if (callback !== undefined) validateFunction(callback, 'callback');
    data = toBuffer(data, 'data');
    const [padding, saltLength, dsaDer] = signOptions(key);
    signature = toBuffer(signature, 'signature');
    const handle = prepareAsymmetricKey(key, kConsumePublic);
    return settle(callback, () => {
      if (native.describe(handle)[1] === 'ed25519') return native.verifyMessage(handle, data, signature);
      const [digest, hashed] = digestOf(algorithm, data);
      return native.verifyDigest(handle, digest, hashed, signature, padding, saltLength, dsaDer);
    });
  }

  function timingSafeEqual(buf1, buf2) {
    for (const [name, value] of [['buf1', buf1], ['buf2', buf2]]) {
      if (!isView(value) && !isArrayBuffer(value)) {
        throw coded(
          TypeError,
          'ERR_INVALID_ARG_TYPE',
          `The "${name}" argument must be an instance of ArrayBuffer, Buffer, TypedArray, or DataView.`,
        );
      }
    }
    if (buf1.byteLength !== buf2.byteLength) {
      throw coded(RangeError, 'ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH', 'Input buffers must have the same byte length');
    }
    return native.timingSafeEqual(buf1, buf2);
  }

  function encodeKey(key, encoding, name) {
    if (encoding === undefined) return key;
    validateObject(encoding, name);
    if (encoding.format === 'jwk') return key.export({ format: 'jwk' });
    return key.export(encoding);
  }

  function generatePair(type, options) {
    validateString(type, 'type');
    let parameter;
    switch (type) {
      case 'rsa': {
        validateObject(options, 'options');
        const { modulusLength, publicExponent = 0x10001 } = options;
        if (typeof modulusLength !== 'number' || modulusLength !== modulusLength >>> 0) {
          throw invalidArgType('options.modulusLength', ['number'], modulusLength);
        }
        if (publicExponent !== 0x10001) throw unsupported('RSA keys can be generated with exponent 65537 only');
        parameter = modulusLength;
        break;
      }
      case 'ec': {
        validateObject(options, 'options');
        validateString(options.namedCurve, 'options.namedCurve');
        parameter = options.namedCurve;
        break;
      }
      case 'ed25519':
        if (options !== undefined) validateObject(options, 'options');
        break;
      case 'rsa-pss':
      case 'dsa':
      case 'ed448':
      case 'x25519':
      case 'x448':
      case 'dh':
        throw unsupported(`Generating ${type} keys is not supported`);
      default:
        throw invalidArgValue('type', type, 'must be a supported key type');
    }
    const [publicHandle, privateHandle] = native.generate(type, parameter);
    const publicKey = new PublicKeyObject(publicHandle);
    const privateKey = new PrivateKeyObject(privateHandle);
    return {
      publicKey: encodeKey(publicKey, options?.publicKeyEncoding, 'options.publicKeyEncoding'),
      privateKey: encodeKey(privateKey, options?.privateKeyEncoding, 'options.privateKeyEncoding'),
    };
  }

  function generateKeyPairSync(type, options) {
    return generatePair(type, options);
  }

  function generateKeyPair(type, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateFunction(callback, 'callback');
    let pair;
    let failure = null;
    try {
      pair = generatePair(type, options);
    } catch (error) {
      failure = error;
    }
    defer(() => (failure ? callback(failure) : callback(null, pair.publicKey, pair.privateKey)));
  }

  function createHmac(hmac, key, options) {
    if (isKeyObject(key)) {
      if (key.type !== 'secret') throw invalidKeyObjectType(key.type, 'secret');
      key = native.secretBytes(handleOf(key));
    }
    return ReflectApply(baseCreateHmac, this, [hmac, key, options]);
  }

  return {
    KeyObject,
    createSecretKey,
    createPublicKey,
    createPrivateKey,
    generateKeyPair,
    generateKeyPairSync,
    Sign,
    Verify,
    createSign,
    createVerify,
    sign: signOneShot,
    verify: verifyOneShot,
    timingSafeEqual,
    createHmac,
  };
}
