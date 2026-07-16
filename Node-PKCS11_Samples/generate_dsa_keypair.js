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
 * - Generate DSA domain parameters, then a DSA keypair, then sign/verify
 *   (mirrors JSP GenerateDSAKeyPair + C DSA mechs).
 * - Exit code 2 if domain/keypair generation is rejected by the partition.
 */

"use strict";
const pkcs11 = require("pkcs11js");
const {
  graphene,
  withSession,
  usageAndExit,
  getPlaintext,
  toHex,
  u32,
} = require("./lib/helper");

console.log("\ngenerate_dsa_keypair.js\n");
if (process.argv.length !== 3 && process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node generate_dsa_keypair.js <slot_label> [prime_bits]",
    "",
    "Example:",
    "node generate_dsa_keypair.js myPartition 1024\n",
  ]);
}
const slotLabel = process.argv[2];
const primeBits = parseInt(process.argv[3] || "1024", 10);

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ");
  await withSession(slotLabel, async (session) => {
    const no = Buffer.from([0]);
    const yes = Buffer.from([1]);
    let domain;
    try {
      domain = session.lib.C_GenerateKey(
        session.handle,
        { mechanism: pkcs11.CKM_DSA_PARAMETER_GEN, parameter: null },
        [
          { type: pkcs11.CKA_CLASS, value: u32(pkcs11.CKO_DOMAIN_PARAMETERS) },
          { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_DSA) },
          { type: pkcs11.CKA_TOKEN, value: no },
          { type: pkcs11.CKA_PRIME_BITS, value: u32(primeBits) },
        ]
      );
      console.log("DSA domain parameters generated (", primeBits, "bits).");
    } catch (err) {
      console.log(
        "DSA domain parameter generation failed:",
        err && err.message ? err.message : err
      );
      process.exitCode = 2;
      return;
    }

    const prime = Buffer.alloc(Math.max(primeBits / 8, 128) + 32);
    const subprime = Buffer.alloc(64);
    const base = Buffer.alloc(Math.max(primeBits / 8, 128) + 32);
    const pa = [{ type: pkcs11.CKA_PRIME, value: prime }];
    const sa = [{ type: pkcs11.CKA_SUBPRIME, value: subprime }];
    const ba = [{ type: pkcs11.CKA_BASE, value: base }];
    session.lib.C_GetAttributeValue(session.handle, domain, pa);
    session.lib.C_GetAttributeValue(session.handle, domain, sa);
    session.lib.C_GetAttributeValue(session.handle, domain, ba);

    try {
      const keys = session.generateKeyPair(
        pkcs11.CKM_DSA_KEY_PAIR_GEN,
        {
          keyType: graphene.KeyType.DSA,
          prime: pa[0].value,
          subprime: sa[0].value,
          base: ba[0].value,
          token: false,
          verify: true,
        },
        {
          keyType: graphene.KeyType.DSA,
          prime: pa[0].value,
          subprime: sa[0].value,
          base: ba[0].value,
          token: false,
          private: true,
          sensitive: true,
          sign: true,
        }
      );
      console.log("DSA keypair generated.");
      const signature = session
        .createSign(pkcs11.CKM_DSA_SHA256, keys.privateKey)
        .once(Buffer.from(plaintext, "utf8"));
      const ok = session
        .createVerify(pkcs11.CKM_DSA_SHA256, keys.publicKey)
        .once(Buffer.from(plaintext, "utf8"), signature);
      console.log(ok ? "Signature verified.\n" : "Signature verification failed.\n");
      console.log("Plain text\t: ", plaintext);
      console.log("Signature\t: ", toHex(signature));
      console.log();
    } catch (err) {
      // Fallback: raw C_GenerateKeyPair
      try {
        const pub = [
          { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_DSA) },
          { type: pkcs11.CKA_TOKEN, value: no },
          { type: pkcs11.CKA_VERIFY, value: yes },
          { type: pkcs11.CKA_PRIME, value: pa[0].value },
          { type: pkcs11.CKA_SUBPRIME, value: sa[0].value },
          { type: pkcs11.CKA_BASE, value: ba[0].value },
        ];
        const pri = [
          { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_DSA) },
          { type: pkcs11.CKA_TOKEN, value: no },
          { type: pkcs11.CKA_PRIVATE, value: yes },
          { type: pkcs11.CKA_SENSITIVE, value: yes },
          { type: pkcs11.CKA_SIGN, value: yes },
          { type: pkcs11.CKA_PRIME, value: pa[0].value },
          { type: pkcs11.CKA_SUBPRIME, value: sa[0].value },
          { type: pkcs11.CKA_BASE, value: ba[0].value },
        ];
        const kp = session.lib.C_GenerateKeyPair(
          session.handle,
          { mechanism: pkcs11.CKM_DSA_KEY_PAIR_GEN, parameter: null },
          pub,
          pri
        );
        console.log("DSA keypair generated (raw).");
        session.lib.C_SignInit(
          session.handle,
          { mechanism: pkcs11.CKM_DSA_SHA256, parameter: null },
          kp.privateKey
        );
        const signature = session.lib.C_Sign(
          session.handle,
          Buffer.from(plaintext, "utf8"),
          Buffer.alloc(256)
        );
        console.log("Signature\t: ", toHex(signature));
        console.log();
      } catch (err2) {
        console.log(
          "DSA keypair generation failed:",
          err2 && err2.message ? err2.message : err2
        );
        console.log(
          "(Domain params succeeded; some partitions still reject DSA keygen.)\n"
        );
        process.exitCode = 2;
      }
    }
  });
})();
