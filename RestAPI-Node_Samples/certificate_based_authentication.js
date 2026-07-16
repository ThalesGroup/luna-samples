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
 * - It is assumed that the user you're trying to authenticate already has a certificate assigned.
 * - Flow matches the Python sample: decrypt challenge (RSA PKCS#1 v1.5), XOR with nonce,
 *   re-encrypt with the appliance server certificate, POST to /auth/login/basic.
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

  const challengeRes = await restFetch(
    baseUrl(hostname) + "/auth/login/challenge",
    {
      method: "POST",
      headers,
      body: JSON.stringify({ username, certificate: certData }),
    }
  );
  if (challengeRes.status !== 200) {
    console.log("Challenge request failed. HTTP", challengeRes.status);
    console.log(challengeRes.text);
    process.exit(1);
  }

  const data = challengeRes.json;
  if (!data.challenge || !data.nonce || !data.certificate) {
    console.log("Unexpected challenge response (missing challenge/nonce/certificate).");
    console.log(challengeRes.text);
    process.exit(1);
  }

  const challenge = Buffer.from(data.challenge, "base64");
  const nonce = Buffer.from(data.nonce, "base64");

  // Decrypt challenge with user private key (PKCS#1 v1.5), then XOR with nonce.
  const decryptedChallenge = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    challenge
  );
  if (decryptedChallenge.length !== nonce.length) {
    console.log(
      "Challenge/nonce length mismatch:",
      decryptedChallenge.length,
      "vs",
      nonce.length
    );
    process.exit(1);
  }
  const xored = Buffer.alloc(decryptedChallenge.length);
  for (let i = 0; i < decryptedChallenge.length; i++) {
    xored[i] = decryptedChallenge[i] ^ nonce[i];
  }

  // Encrypt xored result with the appliance server certificate public key.
  let serverCertPem = String(data.certificate).replace(/\\n/g, "\n");
  if (!serverCertPem.includes("BEGIN CERTIFICATE")) {
    serverCertPem =
      "-----BEGIN CERTIFICATE-----\n" +
      serverCertPem +
      "\n-----END CERTIFICATE-----";
  }
  const serverCert = new crypto.X509Certificate(serverCertPem);
  const encryptedChallenge = crypto.publicEncrypt(
    {
      key: serverCert.publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    xored
  );

  const login = await restFetch(baseUrl(hostname) + "/auth/login/basic", {
    method: "POST",
    headers,
    body: JSON.stringify({
      challengeResponse: encryptedChallenge.toString("base64"),
    }),
  });

  if (login.status !== 204) {
    console.log("Certificate based login failed!", login.status);
    if (login.text) console.log(login.text);
    process.exit(1);
  }
  console.log("Login successful.\n");

  // Capture session cookie from login response for a follow-up API call.
  const setCookie = login.raw.headers.getSetCookie
    ? login.raw.headers.getSetCookie()
    : [];
  let cookieHeader = setCookie.map((c) => c.split(";")[0]).join("; ");
  if (!cookieHeader) {
    const sc = login.raw.headers.get("set-cookie");
    if (sc) {
      cookieHeader = sc
        .split(",")
        .map((c) => c.split(";")[0].trim())
        .join("; ");
    }
  }
  const sessionHeaders = { ...headers };
  if (cookieHeader) sessionHeaders.Cookie = cookieHeader;

  const hsmInfo = await restFetch(baseUrl(hostname) + "/api/lunasa/", {
    method: "GET",
    headers: sessionHeaders,
  });
  if (hsmInfo.status === 200 && hsmInfo.json && hsmInfo.json.version) {
    console.log(
      "You're now connected to HSM with Software version :",
      hsmInfo.json.version
    );
  }

  await restFetch(baseUrl(hostname) + "/auth/session", {
    method: "DELETE",
    headers: sessionHeaders,
  });
  console.log("\nExiting...\n");
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
