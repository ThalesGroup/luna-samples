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
 * - Show details for one appliance user (GET /users/{userid}).
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
    "node user_show.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const res = await restFetch(
      baseUrl(hostname) + "/users/" + encodeURIComponent(userId),
      { method: "GET", headers: session.headers }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 200) {
      console.log("Command failed. HTTP", res.status);
      process.exit(1);
    }
    const u = res.json;
    console.log("User ID   \t:", u.userId || u.id || userId);
    console.log("Full name \t:", u.fullName || "");
    console.log("Email     \t:", u.email || "");
    console.log("Role      \t:", u.role === "" ? "(none)" : u.role);
    console.log("Status    \t:", u.status || "");
    console.log("Changeable\t:", u.changeable);
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
