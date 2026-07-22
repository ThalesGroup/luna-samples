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
 * - This code demonstrates how to create a new user using Luna REST API.
 * - A temporary password is assigned to the user upon creation.
 */

"use strict";
const crypto = require("crypto");
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
    "node user_create.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];
const characters =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890/@#$?*-_+=";

(async () => {
  const password = await getAppliancePassword(username);
  const headers = authHeaders(username, password);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");

  const userName = await prompt("Username : ");
  const fullName = await prompt("Fullname : ");
  const emailAddress = await prompt("Email Address : ");
  const role = await prompt("Role : ");

  let userPassword = "";
  for (let i = 0; i < 16; i++) {
    userPassword += characters[crypto.randomInt(characters.length)];
  }

  const res = await restFetch(baseUrl(hostname) + "/users", {
    method: "POST",
    headers,
    body: JSON.stringify({
      userId: userName,
      fullName,
      email: emailAddress,
      role,
      password: userPassword,
    }),
  });
  if (res.status === 401) {
    console.log("Login failed.");
    process.exit(1);
  }
  if (res.status !== 204) {
    console.log("User creation failed. Response code :", res.status);
    process.exit(1);
  }
  console.log("\nUsername '", userName, "' created successfully.");
  console.log("TEMPORARY PASSWORD : ", userPassword);
  console.log();
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

