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
 * - This code demonstrates how to delete a client registered on a Luna Network HSM.
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

if (process.argv.length !== 5) {
  usageAndExit([
    "",
    "usage :-",
    "node client_delete.js <HSM_IP_OR_HOSTNAME> <appliance_username> <clientName>",
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
  if (res.status === 404) {
    console.log("Client not found, Response code: ", res.status);
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

  const choice = await prompt("\nType 'delete-it' to delete this client : ");
  if (choice === "delete-it") {
    const del = await restFetch(
      baseUrl(hostname) + "/api/lunasa/ntls/clients/" + data.clientID,
      { method: "DELETE", headers }
    );
    if (del.status === 204) console.log("client deleted successfully.\n");
    else console.log("Delete failed. Response code:", del.status);
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

