#!/usr/bin/env node
/**
 * Run all Node-PKCS11 samples except RSA private-key wrap.
 * Usage: node tools/run_all_except_privwrap.js <slot_label>
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

function run(name, args, opts = {}) {
  const allowExit = opts.allowExit || [0];
  console.log("\n########## " + name + " ##########");
  const r = spawnSync(process.execPath, [path.join(root, name), ...args], {
    cwd: root,
    env: process.env,
    encoding: "utf8",
    timeout: opts.timeout || 120000,
  });
  const code = r.status == null ? 1 : r.status;
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  const ok = allowExit.includes(code);
  results.push({ name, args, code, ok });
  console.log(ok ? `>>> PASS (${code})` : `>>> FAIL (${code})`);
  return ok;
}

process.env.SAMPLE_PLAINTEXT =
  process.env.SAMPLE_PLAINTEXT || "hello luna all-tests!";

const AES_KEK = tag + "_KEK";
const AES_DATA = tag + "_DATA";
const AES_DATA2 = tag + "_DATA2";
const AES_DATA3 = tag + "_DATA3";
const AES_DATA4 = tag + "_DATA4";
const RSA_WRAP = tag + "_RSA";
const RSA2 = tag + "_RSA2";
const EC = tag + "_EC";
const DES3 = tag + "_DES3";
const AES2 = tag + "_AES2";

let failed = 0;

function must(name, args, opts) {
  if (!run(name, args, opts)) failed++;
}

// --- basics ---
must("enumerate_slots.js", []);
must("list_mechanisms.js", [slot]);
must("pqc_mechanism_probe.js", [slot], { allowExit: [0, 2] });
must("login_logout.js", [slot]);
must("list_objects.js", [slot, "-all"]);
must("generate_random_data.js", [slot, "32"]);
must("destroy_object.js", [slot]);
must("digest_using_sha256.js", [slot]);
must("derive_ecdh_shared_secret.js", [slot]);

// --- keygen ---
must("generate_aes_key.js", [slot, AES_KEK, "256"]);
must("generate_aes_key.js", [slot, AES_DATA, "128"]);
must("generate_aes_key2.js", [slot, AES2, "192"]);
must("generate_des3_key.js", [slot, DES3]);
must("generate_rsa_keypair.js", [slot, RSA_WRAP, "2048"]);
must("generate_rsa_keypair2.js", [slot, RSA2, "2048"]);
must("generate_ecdsa_keypair.js", [slot, EC, "secp256r1"]);

// --- encrypt ---
must("encrypt_using_aes-cbc.js", [slot]);
must("encrypt_using_aes-cbc-pad.js", [slot]);
must("encrypt_using_aes-ecb.js", [slot]);
must("encrypt_using_aes-ctr.js", [slot]);
must("encrypt_using_aes-gcm.js", [slot]);
must("encrypt_using_des3-cbc-pad.js", [slot]);
must("encrypt_using_rsa_pkcs1.js", [slot]);
must("encrypt_using_rsa_oaep.js", [slot]);

// --- sign / mac ---
must("sign_using_aes_cmac.js", [slot]);
must("sign_using_hmac_sha256.js", [slot]);
must("sign_using_rsa.js", [slot]);
must("sign_using_rsa_pkcs1.js", [slot]);
must("sign_using_rsa_sha256.js", [slot]);
must("sign_using_rsa_pss.js", [slot]);
must("sign_using_rsa_pss_sha256.js", [slot]);
must("sign_using_ecdsa_sha256.js", [slot]);
must("sign_using_ecdsa_sha512.js", [slot]);

// --- wrap/unwrap secret keys (NOT private-key wrap) ---
const wAes = path.join(tmp, "aes.dat");
const wRsaPkcs1 = path.join(tmp, "rsa_pkcs1.dat");
const wRsaOaep1 = path.join(tmp, "rsa_oaep_sha1.dat");
const wRsaOaep256 = path.join(tmp, "rsa_oaep_sha256.dat");

must("wrap_secret_key_using_aes.js", [slot, AES_KEK, AES_DATA, wAes]);
must("unwrap_secret_key_using_aes.js", [
  slot,
  AES_KEK,
  tag + "_UNW_AES",
  wAes,
]);

must("wrap_secret_key_using_rsa_pkcs1.js", [
  slot,
  RSA_WRAP,
  AES_DATA,
  wRsaPkcs1,
]);
must("unwrap_secret_key_using_rsa_pkcs1.js", [
  slot,
  RSA_WRAP,
  tag + "_UNW_PKCS1",
  wRsaPkcs1,
]);

must("wrap_secret_key_using_rsa_oaep_sha1.js", [
  slot,
  RSA_WRAP,
  AES_DATA,
  wRsaOaep1,
]);
must("unwrap_secret_key_using_rsa_oaep_sha1.js", [
  slot,
  RSA_WRAP,
  tag + "_UNW_OAEP1",
  wRsaOaep1,
]);

must("wrap_secret_key_using_rsa_oaep_sha256.js", [
  slot,
  RSA_WRAP,
  AES_DATA,
  wRsaOaep256,
]);
must("unwrap_secret_key_using_rsa_oaep_sha256.js", [
  slot,
  RSA_WRAP,
  tag + "_UNW_OAEP256",
  wRsaOaep256,
]);

console.log("\n========== SUMMARY ==========");
console.log("Skipped: wrap_rsa_private_key_using_aes.js (per request)");
console.log("Temp dir:", tmp);
for (const r of results) {
  console.log((r.ok ? "PASS" : "FAIL") + "  " + r.name + "  exit=" + r.code);
}
const pass = results.filter((r) => r.ok).length;
console.log(`\n${pass}/${results.length} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
