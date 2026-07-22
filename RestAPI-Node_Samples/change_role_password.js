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
 * - This code demonstrates how to change password for SO, PSO, CO, and CU roles.
 * - Tested pattern matches password-based Network HSM samples.
 * - CAUTION: incorrect passwords may cause lockout or zeroization.
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  prompt,
  promptSecret,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "Usage :-",
    "node change_role_password.js <HSM_IP_OR_HOST> <appliance username>",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  const session = await openSession(hostname, username, password);
  try {
    const hsmSerial = await getHsmSerial(hostname, session.headers);
    console.log("HSM serial:", hsmSerial);

    const role = (await prompt("Role (so|co|cu|pso) : ")).toLowerCase();
    const partitionId =
      role === "so"
        ? null
        : await prompt("Partition serial/id (required for co/cu/pso) : ");

    const oldPassword = await promptSecret("  Current " + role + " Password : ");
    const newPassword = await promptSecret("  New " + role + " Password : ");
    const confirm = await promptSecret("  Confirm " + role + " Password : ");
    if (newPassword !== confirm) {
      console.log("ERROR : Passwords do not match.");
      process.exit(1);
    }

    let url;
    if (role === "so") {
      url =
        baseUrl(hostname) +
        "/api/lunasa/hsms/" +
        hsmSerial +
        "/roles/so/password";
    } else {
      url =
        baseUrl(hostname) +
        "/api/lunasa/hsms/" +
        hsmSerial +
        "/partitions/" +
        partitionId +
        "/roles/" +
        role +
        "/password";
    }

    const res = await restFetch(url, {
      method: "PUT",
      headers: session.headers,
      body: JSON.stringify({
        oldPassword,
        newPassword,
        ped: "0",
      }),
    });
    if (res.status === 204) console.log("Password changed successfully.\n");
    else {
      console.log("Password change failed. HTTP", res.status);
      if (res.text) console.log(res.text);
    }
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

