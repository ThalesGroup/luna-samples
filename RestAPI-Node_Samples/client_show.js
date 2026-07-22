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
 * - This code demonstrates how to read information about a client using Luna REST-API.
 */

"use strict";
const {
  getAppliancePassword,
  authHeaders,
  baseUrl,
  restFetch,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 5) {
  usageAndExit([
    "",
    "usage :-",
    "node client_show.js <HSM_IP_OR_HOSTNAME> <appliance_username> <clientName>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];
const clientName = process.argv[4];

(async () => {
  const password = await getAppliancePassword(username);
  const headers = authHeaders(username, password);
  console.log("Connecting to Luna HSM: [", hostname, "]\n");

  const res = await restFetch(
    baseUrl(hostname) + "/api/lunasa/ntls/clients/" + clientName,
    { method: "GET", headers }
  );
  if (res.status === 401) {
    console.log("Login failed.");
    process.exit(1);
  }
  if (res.status !== 200) {
    console.log("Command failed, Response code: ", res.status);
    process.exit(1);
  }

  const data = res.json;
  console.log("Client Name\t:", data.clientID);
  console.log("Hostname \t:", data.hostname === "" ? "NOT SET" : data.hostname);
  console.log("IP Address \t:", data.ip === "" ? "NOT SET" : data.ip);
  console.log("Partitions");
  const linksRes = await restFetch(baseUrl(hostname) + data.links, {
    method: "GET",
    headers,
  });
  const links = linksRes.json.links || [];
  if (links.length > 0) {
    for (const link of links) console.log("  -", link.id);
  } else {
    console.log("\tNone Assigned.");
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

