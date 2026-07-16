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
 * - This code displays a list of users in a Luna Network HSM using Rest API.
 */

"use strict";
const {
  getAppliancePassword,
  authHeaders,
  baseUrl,
  restFetch,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node user_list.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  const headers = authHeaders(username, password);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");

  const res = await restFetch(baseUrl(hostname) + "/users", {
    method: "GET",
    headers,
  });
  if (res.status === 401) {
    console.log("Login failed.");
    process.exit(1);
  }
  if (res.status !== 200) {
    console.log("Response code :", res.status);
    process.exit(1);
  }

  console.log(
    "USERNAME".padStart(10),
    "ROLE".padStart(10),
    "STATUS".padStart(15),
    "CHANGEABLE".padStart(15),
    "FULL NAME".padStart(25),
    "EMAIL ADDRESS".padStart(25)
  );
  console.log("-".repeat(95));

  for (const user of res.json.users) {
    const info = await restFetch(baseUrl(hostname) + "/users/" + user.id, {
      method: "GET",
      headers,
    });
    const d = info.json;
    console.log(
      String(d.userId).padStart(10),
      String(d.role).padStart(10),
      String(d.status).padStart(15),
      String(d.changeable).padStart(15),
      String(d.fullName).padStart(25),
      String(d.email).padStart(25)
    );
  }
  console.log();
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

