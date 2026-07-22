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
 *   (mirrors JSP GenerateDSAKeyPair, which uses DSA-2048).
 * - Domain parameters (prime/subprime/base) belong in the PUBLIC key template
 *   only; PKCS#11 rejects them in the private template.
 */

"use strict";
const pkcs11 = require("pkcs11js");
const {
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
    "node generate_dsa_keypair.js myPartition 2048\n",
  ]);
}
const slotLabel = process.argv[2];
const primeBits = parseInt(process.argv[3] || "2048", 10);
const subprimeBits = primeBits > 1024 ? 256 : 160;

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ");
  await withSession(slotLabel, async (session) => {
    const no = Buffer.from([0]);
    const yes = Buffer.from([1]);

    const domainTemplate = [
      { type: pkcs11.CKA_CLASS, value: u32(pkcs11.CKO_DOMAIN_PARAMETERS) },
      { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_DSA) },
      { type: pkcs11.CKA_TOKEN, value: no },
      { type: pkcs11.CKA_PRIME_BITS, value: u32(primeBits) },
    ];
    if (primeBits > 1024) {
      domainTemplate.push({
        type: pkcs11.CKA_SUBPRIME_BITS,
        value: u32(subprimeBits),
      });
    }
    const domain = session.lib.C_GenerateKey(
      session.handle,
      { mechanism: pkcs11.CKM_DSA_PARAMETER_GEN, parameter: null },
      domainTemplate
    );
    console.log("DSA domain parameters generated (", primeBits, "bits).");

    const params = session.lib.C_GetAttributeValue(session.handle, domain, [
      { type: pkcs11.CKA_PRIME },
      { type: pkcs11.CKA_SUBPRIME },
      { type: pkcs11.CKA_BASE },
    ]);
    const [prime, subprime, base] = params.map((a) => a.value);

    const keys = session.lib.C_GenerateKeyPair(
      session.handle,
      { mechanism: pkcs11.CKM_DSA_KEY_PAIR_GEN, parameter: null },
      [
        { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_DSA) },
        { type: pkcs11.CKA_TOKEN, value: no },
        { type: pkcs11.CKA_VERIFY, value: yes },
        { type: pkcs11.CKA_PRIME, value: prime },
        { type: pkcs11.CKA_SUBPRIME, value: subprime },
        { type: pkcs11.CKA_BASE, value: base },
      ],
      [
        { type: pkcs11.CKA_KEY_TYPE, value: u32(pkcs11.CKK_DSA) },
        { type: pkcs11.CKA_TOKEN, value: no },
        { type: pkcs11.CKA_PRIVATE, value: yes },
        { type: pkcs11.CKA_SENSITIVE, value: yes },
        { type: pkcs11.CKA_SIGN, value: yes },
      ]
    );
    console.log("DSA keypair generated.");

    const data = Buffer.from(plaintext, "utf8");
    session.lib.C_SignInit(
      session.handle,
      { mechanism: pkcs11.CKM_DSA_SHA256, parameter: null },
      keys.privateKey
    );
    const signature = session.lib.C_Sign(
      session.handle,
      data,
      Buffer.alloc(256)
    );

    session.lib.C_VerifyInit(
      session.handle,
      { mechanism: pkcs11.CKM_DSA_SHA256, parameter: null },
      keys.publicKey
    );
    const ok = session.lib.C_Verify(session.handle, data, signature);
    console.log(ok ? "Signature verified.\n" : "Signature verification failed.\n");
    console.log("Plain text\t: ", plaintext);
    console.log("Signature\t: ", toHex(signature));
    console.log();

    session.lib.C_DestroyObject(session.handle, keys.privateKey);
    session.lib.C_DestroyObject(session.handle, keys.publicKey);
    session.lib.C_DestroyObject(session.handle, domain);
  });
})();
