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
 * - Clear an appliance user's role (POST /users/{userid}/actions/roleClear).
 * - After roleClear the user has no role until you PATCH/PUT a role again
 *   (see user_update.js).
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
    "node user_clear_role.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const userId = await prompt("USER-ID : ");
    const confirmation = await prompt(
      "Type 'clear-role' to remove this user's role : "
    );
    if (confirmation !== "clear-role") {
      console.log("\nNo changes were made, exiting now...");
      process.exit(0);
    }

    const res = await restFetch(
      baseUrl(hostname) +
        "/users/" +
        encodeURIComponent(userId) +
        "/actions/roleClear",
      {
        method: "POST",
        headers: session.headers,
        body: "{}",
      }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 204) {
      console.log("roleClear failed. HTTP", res.status);
      if (res.text) console.log(res.text);
      process.exit(1);
    }
    console.log("\nRole cleared for user '" + userId + "'.");
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
