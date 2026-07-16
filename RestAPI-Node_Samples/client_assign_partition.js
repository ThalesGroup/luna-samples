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
 * - Assign an existing partition to an existing NTLS client
 *   (POST /api/lunasa/ntls/clients/{client}/links).
 * - Does not create or delete partitions or clients. Does not require SO login.
 */

"use strict";
const {
  getAppliancePassword,
  baseUrl,
  restFetch,
  openSession,
  getHsmSerial,
  prompt,
  usageAndExit,
} = require("./lib/rest_helper");

if (process.argv.length !== 4) {
  usageAndExit([
    "",
    "usage :-",
    "node client_assign_partition.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

async function resolvePartition(hostname, headers, hsmId, ref) {
  const list = await restFetch(
    baseUrl(hostname) +
      "/api/lunasa/hsms/" +
      encodeURIComponent(hsmId) +
      "/partitions",
    { method: "GET", headers }
  );
  if (list.status !== 200) {
    throw new Error("Failed to list partitions. HTTP " + list.status);
  }
  const parts = list.json.partitions || [];
  for (const p of parts) {
    if (String(p.id) === String(ref)) {
      return { id: String(p.id), url: p.url };
    }
  }
  for (const p of parts) {
    const d = await restFetch(baseUrl(hostname) + p.url, {
      method: "GET",
      headers,
    });
    const name = d.json && String(d.json.name || "");
    const label = d.json && String(d.json.label || "");
    if (name === ref || label === ref) {
      return { id: String(p.id), url: p.url, name, label };
    }
  }
  throw new Error("Partition not found: " + ref);
}

(async () => {
  const password = await getAppliancePassword(username);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");
  const session = await openSession(hostname, username, password);
  try {
    const clientId = await prompt("Client ID : ");
    const partitionRef = await prompt("Partition id, name, or label : ");

    const clientShow = await restFetch(
      baseUrl(hostname) +
        "/api/lunasa/ntls/clients/" +
        encodeURIComponent(clientId),
      { method: "GET", headers: session.headers }
    );
    if (clientShow.status !== 200) {
      console.log("Client not found. HTTP", clientShow.status);
      process.exit(1);
    }

    const hsmId = await getHsmSerial(hostname, session.headers);
    const part = await resolvePartition(
      hostname,
      session.headers,
      hsmId,
      partitionRef
    );
    const partUrl =
      part.url ||
      "/api/lunasa/hsms/" +
        encodeURIComponent(hsmId) +
        "/partitions/" +
        encodeURIComponent(part.id);

    const res = await restFetch(
      baseUrl(hostname) +
        "/api/lunasa/ntls/clients/" +
        encodeURIComponent(clientId) +
        "/links",
      {
        method: "POST",
        headers: session.headers,
        body: JSON.stringify({ url: partUrl }),
      }
    );
    if (res.status === 401) {
      console.log("Login failed.");
      process.exit(1);
    }
    if (res.status !== 204 && res.status !== 201) {
      console.log("Assign failed. HTTP", res.status);
      if (res.text) console.log(res.text);
      process.exit(1);
    }
    console.log(
      "\nPartition",
      part.id,
      "assigned to client '" + clientId + "'."
    );
    console.log();
  } finally {
    await session.close();
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
