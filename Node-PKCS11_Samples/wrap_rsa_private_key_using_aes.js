#!/usr/bin/env node
/*********************************************************************************
 *                                                                                *
 * Ported from ThalesGroup/luna-samples. The original project is provided under   *
 * the MIT license (https://mit-license.org/).                                    *
 *                                                                                *
 * Copyright © 2025 Thales Group (original samples)                               *
 *                                                                                *
 *********************************************************************************

 * OBJECTIVE:
 * - Demonstrate wrapping an RSA private key with AES-256 using Luna CKM_AES_KWP.
 * - Mirrors C CKM_AES_KWP_demo / Java WrapUnwrapPrivateKeyUsing_AES_KWP:
 *     generate session keys with CKA_EXTRACTABLE=true on the private key, then wrap.
 * - Prerequisites:
 *     1) Private key generated with CKA_EXTRACTABLE = true (set at key-gen time).
 *     2) Partition policy 1 "Allow private key wrapping" = ON (Key Export).
 *        Capability alone is not enough — check: lunacm :> partition showPolicies
 */

"use strict";
const fs = require("fs");
const path = require("path");
const os = require("os");
const {
  graphene,
  CKM_AES_KWP,
  withSession,
  usageAndExit,
  findKeyByLabel,
} = require("./lib/helper");

console.log("\nwrap_rsa_private_key_using_aes.js\n");

/**
 * Modes:
 *   A) Self-contained demo (like C/Java): generate extractable RSA + AES KEK, wrap
 *      node wrap_rsa_private_key_using_aes.js <slot_label> [output_file]
 *
 *   B) Wrap existing token objects by label (like Python sample):
 *      node wrap_rsa_private_key_using_aes.js <slot_label> <wrapping_key_label> <key_to_wrap_label> <output_file>
 */
const argc = process.argv.length;
if (argc !== 3 && argc !== 4 && argc !== 6) {
  usageAndExit([
    "Usage (demo — generates wrappable session keys):",
    "  node wrap_rsa_private_key_using_aes.js <slot_label> [output_file]",
    "",
    "Usage (wrap existing labeled keys):",
    "  node wrap_rsa_private_key_using_aes.js <slot_label> <wrapping_key_label> <private_key_label> <output_file>",
    "",
    "Example:",
    "  node wrap_rsa_private_key_using_aes.js myPartition",
    "  node wrap_rsa_private_key_using_aes.js myPartition MasterKey MyPrivateKey private-key.dat\n",
  ]);
}

const slotLabel = process.argv[2];
const demoMode = argc < 6;
const outfile = demoMode
  ? process.argv[3] || path.join(os.tmpdir(), "rsa_priv_kwp.dat")
  : process.argv[5];
const wrappingKeyLabel = demoMode ? null : process.argv[3];
const keyToWrapLabel = demoMode ? null : process.argv[4];

/** Luna AES-KWP expects a 4-byte IV (same as C/Java samples). */
const KWP_IV = Buffer.from([0x01, 0x02, 0x03, 0x03]);

function generateWrappableRsaPrivate(session) {
  // Match C CKM_AES_KWP_demo private template — CKA_EXTRACTABLE must be true at gen time
  const keys = session.generateKeyPair(
    graphene.KeyGenMechanism.RSA,
    {
      keyType: graphene.KeyType.RSA,
      modulusBits: 2048,
      publicExponent: Buffer.from([0x01, 0x00, 0x01]),
      token: false,
      private: false,
      encrypt: true,
      verify: true,
    },
    {
      keyType: graphene.KeyType.RSA,
      token: false,
      private: true,
      sensitive: true,
      extractable: true, // required for C_WrapKey
      modifiable: false,
      sign: true,
      decrypt: true,
    }
  );
  const extractable = keys.privateKey.get("extractable");
  console.log("RSA-2048 session keypair generated.");
  console.log("  --> Private CKA_EXTRACTABLE :", extractable);
  if (!extractable) {
    throw new Error(
      "Private key was created with CKA_EXTRACTABLE=false (partition may force this)."
    );
  }
  return keys.privateKey;
}

function generateWrappingKey(session) {
  const kek = session.generateKey(graphene.KeyGenMechanism.AES, {
    keyType: graphene.KeyType.AES,
    valueLen: 32,
    token: false,
    private: true,
    sensitive: true,
    extractable: false,
    modifiable: false,
    encrypt: false,
    decrypt: false,
    wrap: true,
    unwrap: true,
  });
  console.log("AES-256 wrapping key generated.");
  return kek;
}

function wrapPrivateKey(session, wrappingKey, privateKey) {
  return session.wrapKey(
    { name: CKM_AES_KWP, params: KWP_IV },
    wrappingKey,
    privateKey
  );
}

function explainNotWrappable(privateKey) {
  let extractable = null;
  try {
    extractable = privateKey.get("extractable");
  } catch (_) {
    /* ignore */
  }
  console.log("\n[ERROR] CKR_KEY_NOT_WRAPPABLE");
  console.log("  Private key CKA_EXTRACTABLE :", extractable);
  console.log("  Checklist:");
  console.log(
    "    1) Generate the private key with extractable: true (cannot be changed later)."
  );
  console.log(
    '    2) Partition policy 1 "Allow private key wrapping" must be 1 (ON).'
  );
  console.log("       lunacm:> role login -name Crypto Officer -password <pin>");
  console.log("       lunacm:> partition showPolicies");
  console.log(
    "       If policy 1 is 0, C_WrapKey returns CKR_KEY_NOT_WRAPPABLE even when CKA_EXTRACTABLE=true."
  );
  console.log(
    "       Enabling policy 1 is Off→On destructive; backup first / use PSO as required.\n"
  );
}

(async () => {
  await withSession(slotLabel, async (session) => {
    let wrappingKey;
    let privateKey;

    if (demoMode) {
      console.log("Mode: generate extractable session keys, then wrap (C/Java style).\n");
      wrappingKey = generateWrappingKey(session);
      privateKey = generateWrappableRsaPrivate(session);
    } else {
      console.log("Mode: wrap existing labeled keys.\n");
      wrappingKey = findKeyByLabel(
        session,
        wrappingKeyLabel,
        graphene.ObjectClass.SECRET_KEY
      );
      console.log("\t> Wrapping key found : ", wrappingKeyLabel);
      privateKey = findKeyByLabel(
        session,
        keyToWrapLabel,
        graphene.ObjectClass.PRIVATE_KEY
      );
      console.log("\t> Key to wrap found : ", keyToWrapLabel);
      console.log("\t> CKA_EXTRACTABLE   : ", privateKey.get("extractable"));
    }

    let wrapped;
    try {
      wrapped = wrapPrivateKey(session, wrappingKey, privateKey);
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      if (/CKR_KEY_NOT_WRAPPABLE|KEY_NOT_WRAPPABLE/i.test(msg)) {
        explainNotWrappable(privateKey);
      }
      throw err;
    }

    fs.writeFileSync(outfile, wrapped);
    console.log("Private key wrapped.");
    console.log("Wrapped key written to file ", outfile);
    console.log("  --> bytes :", wrapped.length, "\n");
  });
})();
