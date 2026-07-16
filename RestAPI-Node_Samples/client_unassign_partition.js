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
 * - Revoke a partition assignment from an NTLS client
 *   (DELETE /api/lunasa/ntls/clients/{client}/links/{linkid}).
 * - Link id is typically the partition serial/id. Only that link is removed.
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  prompt,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node client_unassign_partition.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");
  const session = await openSession(hostname, username, password);
  try {
    const clientId = await prompt("Client ID : ");
    const linkId = await prompt("Partition / link id to revoke : ");

    const confirmation = await prompt(
      "Type 'unassign' to revoke this client-partition link : "
    );
    if (confirmation !== "unassign") {
      console.log("\nNo changes were made, exiting now...");
      process.exit(0);
    }

    const res = await restFetch(
      baseUrl(hostname) +
        "/api/lunasa/ntls/clients/" +
        encodeURIComponent(clientId) +
        "/links/" +
        encodeURIComponent(linkId),
      { method: "DELETE", headers: session.headers }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 204) {
      console.log("Unassign failed. HTTP", res.status);
      if (res.text) console.log(res.text);
      process.exit(1);
    }
    console.log(
      "\nLink",
      linkId,
      "revoked from client '" + clientId + "'."
    );
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
