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
 * - This code demonstrates how to authenticate using certificate-based authentication.
 * - Assumes the user already has a certificate assigned.
 * - Uses Node crypto (RSA-PSS / SHA-256) for the challenge response.
 */

"use strict";
const fs = require("fs");
const crypto = require("crypto");
const { baseUrl, restFetch, usageAndExit } = require("./lib/rest_helper");

if (process.argv.length !== 6) {
  usageAndExit([
    "",
    "Usage:-",
    "node certificate_based_authentication.js <appliance username> <hsm_hostname_or_ip> <user_cert_file> <user_key_file>",
    "",
  ]);
}

const username = process.argv[2];
const hostname = process.argv[3];
const userCertFile = process.argv[4];
const userKeyFile = process.argv[5];

(async () => {
  const privateKeyPem = fs.readFileSync(userKeyFile);
  let certData = fs.readFileSync(userCertFile, "utf8");
  certData = certData.replace(/\n/g, "");
  certData = certData.replace(
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\\n"
  );
  certData = certData.replace(
    "-----END CERTIFICATE-----",
    "\\n-----END CERTIFICATE-----"
  );

  const headers = {
    "Content-type": "application/vnd.safenetinc.lunasa+json;version=",
  };

  const challenge = await restFetch(baseUrl(hostname) + "/auth/login/challenge", {
    method: "POST",
    headers,
    body: JSON.stringify({ username, certificate: certData }),
  });
  if (challenge.status !== 200) {
    console.log("Challenge request failed. HTTP", challenge.status);
    console.log(challenge.text);
    process.exit(1);
  }

  const challengeData = challenge.json.challenge || challenge.json;
  const toSign = Buffer.from(
    typeof challengeData === "string"
      ? challengeData
      : challenge.json.challenge,
    "base64"
  );

  const signature = crypto.sign("sha256", toSign, {
    key: privateKeyPem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });

  const login = await restFetch(baseUrl(hostname) + "/auth/login", {
    method: "POST",
    headers,
    body: JSON.stringify({
      username,
      challengeResponse: signature.toString("base64"),
    }),
  });

  if (login.status === 204 || login.status === 200) {
    console.log("Certificate-based authentication succeeded.\n");
  } else {
    console.log("Authentication failed. HTTP", login.status);
    console.log(login.text);
    process.exit(1);
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});

