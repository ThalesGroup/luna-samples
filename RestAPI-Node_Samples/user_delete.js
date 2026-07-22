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
 * - This code demonstrates how to delete a user account from a Luna Network HSM.
 */

"use strict";
const {
  getAppliancePassword,
  authHeaders,
  baseUrl,
  restFetch,
  prompt,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node user_delete.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  const headers = authHeaders(username, password);

  const userName = await prompt("\nUSER-ID : ");
  const confirmation = await prompt(
    "Are you sure you want to delete this user? Type 'delete-this-user' to confirm : "
  );
  if (confirmation !== "delete-this-user") {
    console.log("\nNo changes were made, exiting now...");
    process.exit(0);
  }

  const res = await restFetch(baseUrl(hostname) + "/users/" + userName, {
    method: "DELETE",
    headers,
  });
  if (res.status === 401) {
    console.log("Login failed.");
    process.exit(1);
  }
  if (res.status !== 204) {
    console.log("Response code :", res.status);
    process.exit(1);
  }
  console.log("\nUsername:", userName, "deleted successfully.");
  console.log();
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

