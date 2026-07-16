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
 * - This code demonstrates how to assign a certificate to a user account.
 * - For certificate-based authentication to work, a user must have a certificate assigned.
 */

"use strict";
const fs = require("fs");
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
    "node user_set_certificate.js <HSM_IP_OR_HOST> <appliance_username>",
    "",
  ]);
}

const hostname = process.argv[2];
const username = process.argv[3];

(async () => {
  const password = await getAppliancePassword(username);
  const headers = authHeaders(username, password);
  console.log("Connecting to Luna HSM : [", hostname, "]\n");

  const userId = await prompt("User ID : ");
  const certificateFileName = await prompt("Certificate filename : ");
  let certData = fs.readFileSync(certificateFileName, "utf8");
  certData = certData.replace(/\n/g, "");
  certData = certData.replace(
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\\n"
  );
  certData = certData.replace(
    "-----END CERTIFICATE-----",
    "\\n-----END CERTIFICATE-----"
  );

  const res = await restFetch(
    baseUrl(hostname) + "/users/" + userId + "/certificates",
    {
      method: "POST",
      headers,
      body: JSON.stringify({ certificate: certData }),
    }
  );
  if (res.status === 401) {
    console.log("\nLogin failed.");
    process.exit(1);
  }
  if (res.status !== 204) {
    console.log("\nAssigning certificate failed. Response code :", res.status);
    process.exit(1);
  }
  console.log("\nCertificate assigned to user :", userId);
  console.log();
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

