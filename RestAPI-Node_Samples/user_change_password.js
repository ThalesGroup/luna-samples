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
 * - Change an appliance user's password
 *   (POST /users/{userid}/actions/changePassword).
 * - This is for appliance accounts (admin/operator/...), not HSM roles (SO/CO/CU).
 *   For HSM role passwords see change_role_password.js.
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  prompt,
  promptSecret,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node user_change_password.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const newPassword = await promptSecret("New password : ");
    const confirm = await promptSecret("Confirm password : ");
    if (newPassword !== confirm) {
      console.log("ERROR : Passwords do not match.");
      process.exit(1);
    }
    const currentPassword = await promptSecret(
      "Current password (blank if admin reset) : "
    );

    const body = { password: newPassword };
    if (currentPassword) body.currentPassword = currentPassword;

    const res = await restFetch(
      baseUrl(hostname) +
        "/users/" +
        encodeURIComponent(userId) +
        "/actions/changePassword",
      {
        method: "POST",
        headers: session.headers,
        body: JSON.stringify(body),
      }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 204) {
      console.log("Password change failed. HTTP", res.status);
      if (res.text) console.log(res.text);
      process.exit(1);
    }
    console.log("\nPassword changed for user '" + userId + "'.");
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
