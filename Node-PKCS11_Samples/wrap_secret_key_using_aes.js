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
 * - This sample demonstrates how to wrap a secret key using another wrapping key (AES).
 * - The encrypted key bytes are written to a file.
 */

"use strict";
const fs = require("fs");
const { graphene, withSession, usageAndExit, findKeyByLabel } = require("./lib/helper");

console.log("\nwrap_secret_key_using_aes.js\n");

if (process.argv.length !== 6) {
  usageAndExit([
    "Usage:",
    "node wrap_secret_key_using_aes.js <slot_label> <wrapping_key_label> <key_to_wrap_label> <output_file_name>",
    "",
    "Example:",
    "node wrap_secret_key_using_aes.js myPartition MasterKey DataKey DataKey.dat\n",
  ]);
}

const [slotLabel, wrappingKeyLabel, keyToWrapLabel, outfile] = process.argv.slice(2);

(async () => {
  await withSession(slotLabel, async (session) => {
    const wrappingKey = findKeyByLabel(
      session,
      wrappingKeyLabel,
      graphene.ObjectClass.SECRET_KEY
    );
    console.log("\t> Wrapping key found : ", wrappingKeyLabel);

    const keyToWrap = findKeyByLabel(
      session,
      keyToWrapLabel,
      graphene.ObjectClass.SECRET_KEY
    );
    console.log("\t> Key to wrap found : ", keyToWrapLabel);

    const wrapped = session.wrapKey(
      graphene.MechanismEnum.AES_KEY_WRAP,
      wrappingKey,
      keyToWrap
    );
    fs.writeFileSync(outfile, wrapped);
    console.log("Wrapped key written to file ", outfile, "\n");
  });
})();

