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
 * - This sample code demonstrates use of an ECDSA keypair to digitally sign text.
 * - Text is signed using ECDSA_SHA256 mechanism.
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_ecdsa_sha256.js\n");

if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_ecdsa_sha256.js <slot_label>",
    "",
    "Example:",
    "node sign_using_ecdsa_sha256.js myPartition\n",
  ]);
}

const slotLabel = process.argv[2];
const curveId = "secp384r1";

(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ");
  await withSession(slotLabel, async (session) => {
    const curve = graphene.NamedCurve.getByName(curveId);
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.ECDSA,
      {
        keyType: graphene.KeyType.EC,
        paramsEC: curve.value,
        token: false,
        verify: true,
      },
      {
        keyType: graphene.KeyType.EC,
        token: false,
        private: true,
        sign: true,
      }
    );
    console.log("ECDSA key pair generated.");

    const sign = session.createSign(graphene.MechanismEnum.ECDSA_SHA256, keys.privateKey);
    const signature = sign.once(Buffer.from(plaintext, "utf8"));
    console.log("Plaintext signed.");

    const verify = session.createVerify(graphene.MechanismEnum.ECDSA_SHA256, keys.publicKey);
    const ok = verify.once(Buffer.from(plaintext, "utf8"), signature);
    console.log(ok ? "Signature verified." : "Signature verification failed.");
    console.log();
    console.log("Plain text \t: ", plaintext);
    console.log("Plain text (Hex): ", Buffer.from(plaintext, "utf8").toString("hex"));
    console.log("Signature\t: ", toHex(signature));
    console.log();
  });
})();

