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
 * - This sample code demonstrates how to list objects from a slot.
 * - Options: certificates, public keys, private keys, secret keys, or all.
 */

"use strict";
const { graphene, withSession, usageAndExit } = require("./lib/helper");

console.log("\nlist_objects.js\n");

if (process.argv.length !== 4) {
  usageAndExit([
    "Usage:",
    "node list_objects.js <slot_label> -<OBJECT_TYPE>",
    "",
    "-<OBJECT_TYPE> :",
    "  -secret  : lists all secret keys",
    "  -private : lists private keys",
    "  -public  : lists public keys",
    "  -cert    : lists all certificates",
    "  -all     : lists all token objects",
    "",
    "Example:",
    "node list_objects.js myPartition -secret\n",
  ]);
}

const slotLabel = process.argv[2];
const objectType = process.argv[3];

(async () => {
  await withSession(slotLabel, async (session) => {
    let template;
    let title;
    if (objectType === "-cert") {
      title = "Certificates:";
      template = { class: graphene.ObjectClass.CERTIFICATE };
    } else if (objectType === "-public") {
      title = "Public Keys:";
      template = { class: graphene.ObjectClass.PUBLIC_KEY };
    } else if (objectType === "-private") {
      title = "Private Keys:";
      template = { class: graphene.ObjectClass.PRIVATE_KEY };
    } else if (objectType === "-secret") {
      title = "Secret Keys:";
      template = { class: graphene.ObjectClass.SECRET_KEY };
    } else if (objectType === "-all") {
      title = "All objects:";
      template = { token: true };
    } else {
      console.log("Invalid search option used.\n");
      return;
    }

    console.log(title);
    const objs = session.find(template);
    for (let i = 0; i < objs.length; i++) {
      const o = objs.items(i);
      let label;
      try {
        label = o.get("label");
      } catch (_) {
        label = "(no label)";
      }
      console.log("  - ", label);
    }
    console.log();
  });
})();

