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
 * - This code demonstrates how to retrieve a list of all partitions from a Luna Network HSM using Luna RestAPI.
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node partition_list.js <HSM_IP_OR_HOST> <appliance_username>",
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
    const hsmSerial = await getHsmSerial(hostname, session.headers);
    const list = await restFetch(
      baseUrl(hostname) + "/api/lunasa/hsms/" + hsmSerial + "/partitions",
      { method: "GET", headers: session.headers }
    );
    const partitions = list.json.partitions || [];
    console.log(
      "SERIAL".padEnd(15),
      "NAME".padEnd(25),
      "STATE".padEnd(15),
      "VERSION"
    );
    for (const partition of partitions) {
      const info = await restFetch(baseUrl(hostname) + partition.url, {
        method: "GET",
        headers: session.headers,
      });
      const p = info.json;
      console.log(
        String(partition.id).padEnd(15),
        String(p.name).padEnd(25),
        String(p.state).padEnd(15),
        p.version
      );
    }
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

