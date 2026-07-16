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
 * - This code demonstrates how to retrieve a list of all registered clients from a Luna Network HSM.
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
    "node client_list.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  const headers = authHeaders(username, password);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");

  const list = await restFetch(baseUrl(hostname) + "/api/lunasa/ntls/clients", {
    method: "GET",
    headers,
  });
  if (list.status === 401) {
    console.log("Login failed.");
    process.exit(1);
  }
  if (list.status !== 200) {
    console.log("Command failed, Response code: ", list.status);
    process.exit(1);
  }

  const allClients = list.json.clients;
  let maxLen = 10;
  for (const c of allClients) maxLen = Math.max(maxLen, c.clientID.length);

  console.log(
    "CLIENT ID".padEnd(maxLen),
    "HOSTNAME".padEnd(maxLen),
    "IP ADDRESS".padEnd(20),
    "PARTITIONS ASSIGNED"
  );

  for (const client of allClients) {
    const info = await restFetch(
      baseUrl(hostname) + "/api/lunasa/ntls/clients/" + client.clientID,
      { method: "GET", headers }
    );
    const d = info.json;
    let clientHostname = d.hostname || "--NONE--";
    let clientIp = d.ip || "--NONE--";
    if (!d.hostname) clientHostname = "--NONE--";
    if (!d.ip) clientIp = "--NONE--";

    const linksRes = await restFetch(baseUrl(hostname) + d.links, {
      method: "GET",
      headers,
    });
    const links = linksRes.json.links || [];
    const assigned =
      links.length === 0 ? "NONE" : links.length + " assigned.";
    console.log(
      String(d.clientID).padEnd(maxLen),
      String(clientHostname).padEnd(maxLen),
      String(clientIp).padEnd(20),
      assigned
    );
  }
  console.log();
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

