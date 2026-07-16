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
 * - This sample demonstrates how to wrap a secret key using an RSA public key.
 * - Mechanism: CKM_RSA_PKCS_OAEP with MGF-SHA256
 * - The target is an AES key.
 */

"use strict";
const fs = require("fs");
const { graphene, withSession, usageAndExit, findKeyByLabel } = require("./lib/helper");

console.log("\nwrap_secret_key_using_rsa_oaep_sha256.js\n");

if (process.argv.length !== 6) {
  usageAndExit([
    "Usage:",
    "node wrap_secret_key_using_rsa_oaep_sha256.js <slot_label> <rsa_public_key_label> <aes_key_label> <output_filename>",
    "",
    "Example:",
    "node wrap_secret_key_using_rsa_oaep_sha256.js myPartition aws-public-key BYOK-AES BYOK.dat\n",
  ]);
}

const [slotLabel, publicKeyLabel, aesKeyLabel, outfile] = process.argv.slice(2);

(async () => {
  await withSession(slotLabel, async (session) => {
    const wrappingKey = findKeyByLabel(
      session,
      publicKeyLabel,
      graphene.ObjectClass.PUBLIC_KEY
    );
    console.log("\t> Public key found : ", publicKeyLabel);

    const keyToWrap = findKeyByLabel(
      session,
      aesKeyLabel,
      graphene.ObjectClass.SECRET_KEY
    );
    console.log("\t> Key to wrap found : ", aesKeyLabel);

    const alg = {
      name: graphene.MechanismEnum.RSA_PKCS_OAEP,
      params: new graphene.RsaOaepParams(
        graphene.MechanismEnum.SHA256,
        graphene.RsaMgf.MGF1_SHA256,
        null
      ),
    };

    const wrapped = session.wrapKey(alg, wrappingKey, keyToWrap);
    fs.writeFileSync(outfile, wrapped);
    console.log("Wrapped key written to file ", outfile, "\n");
  });
})();

