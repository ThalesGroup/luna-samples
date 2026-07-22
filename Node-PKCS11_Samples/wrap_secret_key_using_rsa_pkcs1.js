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
 * - Mechanism: CKM_RSA_PKCS.
 */

"use strict";
const fs = require("fs");
const { graphene, withSession, usageAndExit, findKeyByLabel } = require("./lib/helper");

console.log("\nwrap_secret_key_using_rsa_pkcs1.js\n");

if (process.argv.length !== 6) {
  usageAndExit([
    "Usage:",
    "node wrap_secret_key_using_rsa_pkcs1.js <slot_label> <rsa_public_key_label> <aes_key_label> <output_filename>",
    "",
    "Example:",
    "node wrap_secret_key_using_rsa_pkcs1.js myPartition rsa-pub BYOK-AES BYOK.dat\n",
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

    const wrapped = session.wrapKey(
      graphene.MechanismEnum.RSA_PKCS,
      wrappingKey,
      keyToWrap
    );
    fs.writeFileSync(outfile, wrapped);
    console.log("Wrapped key written to file ", outfile, "\n");
  });
})();

