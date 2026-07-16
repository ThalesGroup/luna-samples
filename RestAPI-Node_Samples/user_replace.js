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
 * - Replace appliance user fields (PUT /users/{userid}).
 * - Provide role, fullName, and email (appliance roles: admin|operator|monitor|audit).
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
    "node user_replace.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const role = await prompt("Role : ");
    const fullName = await prompt("Full name : ");
    const email = await prompt("Email : ");

    const res = await restFetch(
      baseUrl(hostname) + "/users/" + encodeURIComponent(userId),
      {
        method: "PUT",
        headers: session.headers,
        body: JSON.stringify({
          role,
          fullName,
          email,
        }),
      }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 204 && res.status !== 200) {
      console.log("Replace failed. HTTP", res.status);
      if (res.text) console.log(res.text);
      process.exit(1);
    }
    console.log("\nUser '" + userId + "' replaced successfully.");
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
