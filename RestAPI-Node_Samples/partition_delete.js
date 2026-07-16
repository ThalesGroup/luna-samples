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
 * - This code demonstrates how to delete a partition using Luna RestAPI.
 */

"use strict";
const {
  getAppliancePassword,
  getSoPassword,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  prompt,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "Usage :-",
    "node partition_delete.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const hsmSerial = await getHsmSerial(hostname, session.headers);
    const hsmInfo = await restFetch(
      baseUrl(hostname) + "/api/lunasa/hsms/" + hsmSerial,
      { method: "GET", headers: session.headers }
    );
    const soLoginsLeft = hsmInfo.json.soLoginsLeft;
    if (soLoginsLeft === 1) {
      console.log("*** WARNING ***");
      console.log("- You have only one SO login attempt remaining.");
      console.log("- This script will not proceed further.");
      process.exit(1);
    }

    console.log("\nPlease enter the security officer password to proceed.");
    console.log("SO Login Attempts left : ", soLoginsLeft, "\n");
    const soPassword = await getSoPassword();
    const login = await restFetch(
      baseUrl(hostname) + "/api/lunasa/hsms/" + hsmSerial + "/login",
      {
        method: "POST",
        headers: session.headers,
        body: JSON.stringify({ ped: "0", password: soPassword, role: "so" }),
      }
    );
    if (login.status !== 204) {
      console.log("Unable to login as SO. Response code: ", login.status);
      process.exit(1);
    }
    console.log("SO Login successful.\n");

    const partitionId = await prompt("Partition serial / id to delete : ");
    const confirm = await prompt("Type 'delete-partition' to confirm : ");
    if (confirm !== "delete-partition") {
      console.log("No changes were made, exiting now...");
      process.exit(0);
    }

    const del = await restFetch(
      baseUrl(hostname) +
        "/api/lunasa/hsms/" +
        hsmSerial +
        "/partitions/" +
        partitionId,
      { method: "DELETE", headers: session.headers }
    );
    if (del.status === 204) console.log("Partition deleted successfully.\n");
    else console.log("Delete failed. Response code:", del.status);

    await restFetch(
      baseUrl(hostname) + "/api/lunasa/hsms/" + hsmSerial + "/logout",
      { method: "POST", headers: session.headers }
    );
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

