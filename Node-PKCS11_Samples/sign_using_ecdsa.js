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
 * - Sign/verify with CKM_ECDSA over a SHA-256 digest (mirrors C CKM_ECDSA_demo).
 */

"use strict";
const { graphene, withSession, usageAndExit, getPlaintext, toHex } = require("./lib/helper");

console.log("\nsign_using_ecdsa.js\n");
if (process.argv.length !== 3) {
  usageAndExit([
    "Usage:",
    "node sign_using_ecdsa.js <slot_label>",
    "",
    "Example:",
    "node sign_using_ecdsa.js myPartition\n",
  ]);
}
const slotLabel = process.argv[2];
(async () => {
  const plaintext = await getPlaintext("Enter plaintext to sign : ");
  await withSession(slotLabel, async (session) => {
    const curve = graphene.NamedCurve.getByName("secp256r1");
    const keys = session.generateKeyPair(
      graphene.KeyGenMechanism.EC,
      { keyType: graphene.KeyType.EC, paramsEC: curve.value, token: false, verify: true },
      { keyType: graphene.KeyType.EC, token: false, private: true, sign: true }
    );
    console.log("ECDSA secp256r1 keypair generated.");
    const hash = session
      .createDigest(graphene.MechanismEnum.SHA256)
      .once(Buffer.from(plaintext, "utf8"));
    const signature = session
      .createSign(graphene.MechanismEnum.ECDSA, keys.privateKey)
      .once(hash);
    console.log("Digest signed (CKM_ECDSA).");
    const ok = session
      .createVerify(graphene.MechanismEnum.ECDSA, keys.publicKey)
      .once(hash, signature);
    console.log(ok ? "Signature verified.\n" : "Signature verification failed.\n");
    console.log("Plain text\t:", plaintext);
    console.log("Digest\t\t:", toHex(hash));
    console.log("Signature\t:", toHex(signature));
    console.log();
  });
})();
