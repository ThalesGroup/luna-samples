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
 * - Partially update an appliance user (PATCH /users/{userid}).
 * - Typical fields: role (admin|operator|monitor|audit), fullName, email.
 * - Leave a prompt blank to leave that field unchanged.
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
    "node user_update.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const role = await prompt("New role (blank = unchanged) : ");
    const fullName = await prompt("New full name (blank = unchanged) : ");
    const email = await prompt("New email (blank = unchanged) : ");

    const body = {};
    if (role.trim()) body.role = role.trim();
    if (fullName.trim()) body.fullName = fullName.trim();
    if (email.trim()) body.email = email.trim();
    if (Object.keys(body).length === 0) {
      console.log("\nNo fields provided; nothing to update.");
      process.exit(0);
    }

    const res = await restFetch(
      baseUrl(hostname) + "/users/" + encodeURIComponent(userId),
      {
        method: "PATCH",
        headers: session.headers,
        body: JSON.stringify(body),
      }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 204) {
      console.log("Update failed. HTTP", res.status);
      if (res.text) console.log(res.text);
      process.exit(1);
    }
    console.log("\nUser '" + userId + "' updated successfully.");
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
