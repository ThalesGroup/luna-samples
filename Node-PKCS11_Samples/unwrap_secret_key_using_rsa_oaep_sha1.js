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
 * - This sample demonstrates how to unwrap a secret key using an RSA private key.
 * - Mechanism: CKM_RSA_PKCS_OAEP with MGF-SHA1
 */

"use strict";
const fs = require("fs");
const { graphene, withSession, usageAndExit, findKeyByLabel } = require("./lib/helper");

console.log("\nunwrap_secret_key_using_rsa_oaep_sha1.js\n");

if (process.argv.length !== 6) {
  usageAndExit([
    "Usage:",
    "node unwrap_secret_key_using_rsa_oaep_sha1.js <slot_label> <rsa_private_key_label> <unwrapped_key_label> <wrapped_key_file>",
    "",
    "Example:",
    "node unwrap_secret_key_using_rsa_oaep_sha1.js myPartition rsa-pri unwrappedAES BYOK.dat\n",
  ]);
}

const [slotLabel, privateKeyLabel, unwrappedKeyLabel, wrappedKeyFile] =
  process.argv.slice(2);

(async () => {
  await withSession(slotLabel, async (session) => {
    const unwrappingKey = findKeyByLabel(
      session,
      privateKeyLabel,
      graphene.ObjectClass.PRIVATE_KEY
    );
    console.log("\t> Private key found : ", privateKeyLabel);

    const wrapped = fs.readFileSync(wrappedKeyFile);
    const alg = {
      name: graphene.MechanismEnum.RSA_PKCS_OAEP,
      params: new graphene.RsaOaepParams(
        graphene.MechanismEnum.SHA1,
        graphene.RsaMgf.MGF1_SHA1,
        null
      ),
    };

    // Do not set CKA_VALUE_LEN — Luna derives AES length from the unwrapped key material.
    session.unwrapKey(alg, unwrappingKey, wrapped, {
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.AES,
      label: unwrappedKeyLabel,
      token: true,
      private: true,
      sensitive: true,
      encrypt: true,
      decrypt: true,
      extractable: true,
    });
    console.log("Key unwrapped successfully.\n");
  });
})();

