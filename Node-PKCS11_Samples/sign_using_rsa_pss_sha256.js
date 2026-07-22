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
 * - This sample code demonstrates how to generate an RSA keypair and use it for signing.
 * - It uses SHA256_RSA_PKCS_PSS mechanism for signing.
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_rsa_pss_sha256.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_rsa_pss_sha256.js <slot_label>",
    "",
    "Example:",
    "node sign_using_rsa_pss_sha256.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ", 245);
  await withSession(slotLabel, async (session) => {
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.RSA,
      {
        keyType: graphene.KeyType.RSA,
        modulusBits: 2048,
        publicExponent: Buffer.from([0x01, 0x00, 0x01]),
        token: false,
        verify: true,
      },
      {
        keyType: graphene.KeyType.RSA,
        token: false,
        private: true,
        sign: true,
      }
    );
    console.log("RSA-2048 keypair generated.");

    const alg = {
      name: graphene.MechanismEnum.SHA256_RSA_PKCS_PSS,
      params: new graphene.RsaPssParams(
        graphene.MechanismEnum.SHA256,
        graphene.RsaMgf.MGF1_SHA256,
        32
      ),
    };

    const sign = session.createSign(alg, keys.privateKey);
    const signature = sign.once(Buffer.from(plaintext, "utf8"));
    console.log("Plaintext signed.");

    const verify = session.createVerify(alg, keys.publicKey);
    const ok = verify.once(Buffer.from(plaintext, "utf8"), signature);
    console.log(ok ? "Signature verified.\n" : "Signature verification failed.\n");

    console.log("Plain text\t: ", plaintext);
    console.log("Plain text (hex): ", Buffer.from(plaintext, "utf8").toString("hex"));
    console.log("Signature\t: ", toHex(signature));
    console.log();
  });
})();

