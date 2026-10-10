#![allow(clippy::expect_used, clippy::unwrap_used)]
//! `KeyObject`, signing and the rest of `node:crypto`'s key API, held to
//! Node: each scenario logs what it sees and the log must be what Node 24
//! logged for the same module. The keys are fixed JWKs and a certificate
//! made for one of them, so every encoding and every deterministic
//! signature is compared byte for byte; the ECDSA and RSA-PSS signatures
//! Node made are embedded and verified here.
//!
//! Recorded with:
//!
//! ```sh
//! node --input-type=module -e "import r from './crypto_keys.mjs'; console.log(JSON.stringify(r))" > crypto_keys.node.json
//! ```

use ferrijs::{RunOptions, Runtime};

async fn module(source: &str) -> serde_json::Value {
  let realm = Runtime::builder().build().await.expect("runtime");
  let run = realm
    .eval_module_source("entry.mjs", source, &[], RunOptions::default())
    .await;
  run.result.unwrap_or_else(|e| panic!("{e}\n{:?}", e.stack))
}

#[tokio::test]
async fn every_scenario_logs_what_node_logs() {
  let ours = module(include_str!("fixtures/crypto_keys.mjs")).await;
  let node: serde_json::Value = serde_json::from_str(include_str!("fixtures/crypto_keys.node.json")).unwrap();
  let (ours, node) = (ours.as_array().unwrap(), node.as_array().unwrap());
  assert_eq!(ours.len(), node.len());
  for (ours, node) in ours.iter().zip(node) {
    assert_eq!(ours, node);
  }
}

#[tokio::test]
async fn import_and_require_share_one_instance_with_the_vendored_members() {
  let out = module(
    "import crypto, { KeyObject, createHash, Md5, Crc32 } from 'node:crypto';
     import * as bare from 'crypto';
     const required = require('crypto');
     const key = required.createSecretKey(Buffer.from('k'));
     export default [
       required === crypto,
       bare.default === crypto,
       key instanceof KeyObject,
       required.createHash === createHash,
       typeof Md5,
       typeof Crc32,
       crypto.webcrypto === globalThis.crypto,
       typeof crypto.randomUUID(),
     ];",
  )
  .await;
  assert_eq!(
    out,
    serde_json::json!([true, true, true, true, "function", "function", true, "string"])
  );
}

/// What AWS-LC cannot do is refused with a code a caller can test for,
/// never answered with a different signature from the one asked for.
#[tokio::test]
async fn what_the_provider_cannot_sign_is_refused() {
  let out = module(
    "import crypto from 'node:crypto';
     const { privateKey: rsa } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
     const { privateKey: p384 } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
     const code = (fn) => { try { fn(); return 'done'; } catch (e) { return e.code; } };
     const label = 'ENCRYPTED PRIVATE KEY';
     const encrypted = `-----BEGIN ${label}-----\\nMAA=\\n-----END ${label}-----\\n`;
     export default [
       code(() => crypto.sign('sha256', Buffer.from('m'), { key: rsa, padding: 6 })),
       code(() => crypto.sign('sha256', Buffer.from('m'), { key: rsa, padding: 6, saltLength: 20 })),
       code(() => crypto.sign('sha256', Buffer.from('m'), { key: rsa, padding: 6, saltLength: 32 })),
       code(() => crypto.sign('sha1', Buffer.from('m'), rsa)),
       code(() => crypto.sign('sha256', Buffer.from('m'), p384)),
       code(() => crypto.createSign('sha224')),
       code(() => crypto.createPrivateKey({ key: encrypted, passphrase: 'x' })),
       code(() => crypto.generateKeyPairSync('rsa', { modulusLength: 1024 })),
     ];",
  )
  .await;
  let unavailable = "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM";
  assert_eq!(
    out,
    serde_json::json!([
      unavailable,
      unavailable,
      "done",
      unavailable,
      unavailable,
      unavailable,
      "ERR_OSSL_UNSUPPORTED",
      unavailable,
    ])
  );
}
