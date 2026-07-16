#!/usr/bin/env node
/**
 * Run all Node-PKCS11 samples except RSA private-key wrap.
 * Usage: node tools/run_all_except_privwrap.js <slot_label>
 *
 * Env: LUNA_PIN, LUNA_CU_PIN (for login_crypto_user), SAMPLE_PLAINTEXT, P11_LIB
 */
"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const root = path.join(__dirname, "..");
const slot = process.argv[2];
if (!slot) {
  console.error("Usage: node tools/run_all_except_privwrap.js <slot_label>");
  process.exit(1);
}

const tag = "NodeAll_" + Date.now().toString(36);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "luna-node-all-"));
const results = [];

process.env.SAMPLE_PLAINTEXT =
  process.env.SAMPLE_PLAINTEXT || "hello luna all-tests!";

const AES_KEK = tag + "_KEK";
const AES_DATA = tag + "_DATA";
const RSA_WRAP = tag + "_RSA";
const RSA2 = tag + "_RSA2";
const EC = tag + "_EC";
const ED = tag + "_ED";
const DES3 = tag + "_DES3";
const AES2 = tag + "_AES2";

const wAes = path.join(tmp, "aes.dat");
const wRsaPkcs1 = path.join(tmp, "rsa_pkcs1.dat");
const wRsaOaep1 = path.join(tmp, "rsa_oaep_sha1.dat");
const wRsaOaep256 = path.join(tmp, "rsa_oaep_sha256.dat");

/** @type {{ name: string, args: string[], opts?: object }[]} */
const tests = [
  // --- basics ---
  { name: "enumerate_slots.js", args: [] },
  { name: "list_mechanisms.js", args: [slot] },
  { name: "pqc_mechanism_probe.js", args: [slot] },
  { name: "get_mechanism_info.js", args: [slot, "AES_GCM"] },
  { name: "login_logout.js", args: [slot] },
  { name: "login_crypto_user.js", args: [slot] },
  { name: "list_objects.js", args: [slot, "-all"] },
  { name: "generate_random_data.js", args: [slot, "32"] },
  { name: "seed_random.js", args: [slot] },
  { name: "destroy_object.js", args: [slot] },
  { name: "create_data_object.js", args: [slot] },
  { name: "create_known_keys.js", args: [slot] },
  { name: "copy_object.js", args: [slot] },
  { name: "set_object_attribute.js", args: [slot] },
  { name: "get_object_attributes.js", args: [slot] },
  { name: "usage_limit_demo.js", args: [slot, "2"] },

  // --- digest / derive ---
  { name: "digest_using_sha256.js", args: [slot] },
  { name: "digest_using_sha3_256.js", args: [slot] },
  { name: "digest_using_shake_256.js", args: [slot, "50"] },
  { name: "derive_using_sha256.js", args: [slot] },
  { name: "derive_ecdh_shared_secret.js", args: [slot] },
  { name: "derive_using_pbkd2.js", args: [slot] },
  { name: "derive_using_nist_prf_kdf.js", args: [slot] },

  // --- keygen ---
  { name: "generate_aes_key.js", args: [slot, AES_KEK, "256"] },
  { name: "generate_aes_key.js", args: [slot, AES_DATA, "128"] },
  { name: "generate_aes_key2.js", args: [slot, AES2, "192"] },
  { name: "generate_des3_key.js", args: [slot, DES3] },
  { name: "generate_rsa_keypair.js", args: [slot, RSA_WRAP, "2048"] },
  { name: "generate_rsa_keypair2.js", args: [slot, RSA2, "2048"] },
  { name: "generate_ecdsa_keypair.js", args: [slot, EC, "secp256r1"] },
  { name: "generate_eddsa_keypair.js", args: [slot, ED] },
  { name: "generate_dsa_keypair.js", args: [slot, "2048"] },

  // --- encrypt ---
  { name: "encrypt_using_aes-cbc.js", args: [slot] },
  { name: "encrypt_using_aes-cbc-pad.js", args: [slot] },
  { name: "encrypt_using_aes-ecb.js", args: [slot] },
  { name: "encrypt_using_aes-ctr.js", args: [slot] },
  { name: "encrypt_using_aes-gcm.js", args: [slot] },
  { name: "encrypt_using_des3-cbc-pad.js", args: [slot] },
  { name: "encrypt_using_rsa_pkcs1.js", args: [slot] },
  { name: "encrypt_using_rsa_oaep.js", args: [slot] },
  { name: "encrypt_using_rsa_x509.js", args: [slot] },

  // --- sign / mac ---
  { name: "sign_using_aes_cmac.js", args: [slot] },
  { name: "sign_using_des3_cmac.js", args: [slot] },
  { name: "sign_using_hmac_sha1.js", args: [slot] },
  { name: "sign_using_hmac_sha256.js", args: [slot] },
  { name: "sign_using_rsa.js", args: [slot] },
  { name: "sign_using_rsa_pkcs1.js", args: [slot] },
  { name: "sign_using_rsa_sha256.js", args: [slot] },
  { name: "sign_using_rsa_pss.js", args: [slot] },
  { name: "sign_using_rsa_pss_sha256.js", args: [slot] },
  { name: "sign_using_rsa_x9_31.js", args: [slot] },
  { name: "sign_using_ecdsa.js", args: [slot] },
  { name: "sign_using_ecdsa_sha256.js", args: [slot] },
  { name: "sign_using_ecdsa_sha512.js", args: [slot] },
  { name: "sign_using_eddsa.js", args: [slot] },

  // --- wrap/unwrap secret keys (NOT private-key wrap) ---
  { name: "wrap_secret_key_using_aes_cbc_pad.js", args: [slot] },
  { name: "wrap_secret_key_using_des3_cbc_pad.js", args: [slot] },
  { name: "wrap_secret_key_using_aes_kw.js", args: [slot] },
  { name: "wrap_secret_key_using_aes.js", args: [slot, AES_KEK, AES_DATA, wAes] },
  {
    name: "unwrap_secret_key_using_aes.js",
    args: [slot, AES_KEK, tag + "_UNW_AES", wAes],
  },
  {
    name: "wrap_secret_key_using_rsa_pkcs1.js",
    args: [slot, RSA_WRAP, AES_DATA, wRsaPkcs1],
  },
  {
    name: "unwrap_secret_key_using_rsa_pkcs1.js",
    args: [slot, RSA_WRAP, tag + "_UNW_PKCS1", wRsaPkcs1],
  },
  {
    name: "wrap_secret_key_using_rsa_oaep_sha1.js",
    args: [slot, RSA_WRAP, AES_DATA, wRsaOaep1],
  },
  {
    name: "unwrap_secret_key_using_rsa_oaep_sha1.js",
    args: [slot, RSA_WRAP, tag + "_UNW_OAEP1", wRsaOaep1],
  },
  {
    name: "wrap_secret_key_using_rsa_oaep_sha256.js",
    args: [slot, RSA_WRAP, AES_DATA, wRsaOaep256],
  },
  {
    name: "unwrap_secret_key_using_rsa_oaep_sha256.js",
    args: [slot, RSA_WRAP, tag + "_UNW_OAEP256", wRsaOaep256],
  },

  // --- multi-thread (longer) ---
  {
    name: "multi_thread_signing.js",
    args: [slot, "3", "5"],
    opts: { timeout: 300000 },
  },
];

const total = tests.length;
console.log(`Running ${total} samples against slot "${slot}" (tag=${tag})`);
console.log(`Skipped: wrap_rsa_private_key_using_aes.js (private-key wrap)\n`);

let failed = 0;
for (let i = 0; i < tests.length; i++) {
  const { name, args, opts = {} } = tests[i];
  const n = i + 1;
  const allowExit = opts.allowExit || [0];
  console.log(`\n########## [${n}/${total}] ${name} ##########`);
  const r = spawnSync(process.execPath, [path.join(root, name), ...args], {
    cwd: root,
    env: process.env,
    encoding: "utf8",
    timeout: opts.timeout || 180000,
  });
  const code = r.status == null ? 1 : r.status;
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  const ok = allowExit.includes(code);
  results.push({ n, name, args, code, ok });
  if (!ok) failed++;
  const passedSoFar = results.filter((x) => x.ok).length;
  console.log(
    ok
      ? `>>> PASS (${code})  [${n}/${total}]  running total ${passedSoFar}/${n}`
      : `>>> FAIL (${code})  [${n}/${total}]  running total ${passedSoFar}/${n}`
  );
}

console.log("\n========== SUMMARY ==========");
console.log("Temp dir:", tmp);
for (const r of results) {
  console.log(
    `${r.ok ? "PASS" : "FAIL"}  [${String(r.n).padStart(2)}/${total}]  ${r.name}  exit=${r.code}`
  );
}
const pass = results.filter((r) => r.ok).length;
console.log(`\n${pass}/${total} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
