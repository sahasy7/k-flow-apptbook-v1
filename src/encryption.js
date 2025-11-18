/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Encryption / decryption helpers for WhatsApp Flows endpoint.
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Default path where we created the key in the container
const DEFAULT_KEY_PATH = path.join(__dirname, "wa_private_key.pem");

export class FlowEndpointException extends Error {
  constructor(statusCode) {
    super();
    this.statusCode = statusCode;
  }
}

/**
 * Load the private key from file and create a Node crypto KeyObject.
 */
function loadPrivateKey() {
  const keyPath = process.env.PRIVATE_KEY_PATH || DEFAULT_KEY_PATH;

  let pem;
  try {
    pem = fs.readFileSync(keyPath, "utf8");
  } catch (e) {
    console.error("❌ Failed to read private key file:", keyPath, e);
    throw new Error("Could not read private key file");
  }

  // Normalize newlines and trim
  const rawKey = pem.replace(/\r/g, "").trim();
  const lines = rawKey.split("\n");

  console.log("🔐 PRIVATE_KEY from file:");
  console.log("  Path:", keyPath);
  console.log("  First line:", lines[0]);
  console.log("  Last line:", lines[lines.length - 1]);

  if (!rawKey.startsWith("-----BEGIN")) {
    throw new Error("PRIVATE KEY file is not a valid PEM");
  }

  // Detect type: PKCS8 vs PKCS1
  const keyType = rawKey.includes("BEGIN RSA PRIVATE KEY")
    ? "pkcs1"
    : "pkcs8";

  try {
    return crypto.createPrivateKey({
      key: rawKey,
      format: "pem",
      type: keyType,
      // key is unencrypted, so no passphrase
    });
  } catch (e) {
    console.error("❌ createPrivateKey failed:", e);
    throw e;
  }
}

/**
 * Decrypt incoming WhatsApp Flow request body.
 * Returns { aesKeyBuffer, initialVectorBuffer, decryptedBody }.
 */
export function decryptRequest(body) {
  const {
    encrypted_body,
    encrypted_key,
    initial_vector,
    authentication_tag,
  } = body;

  if (!encrypted_body || !encrypted_key || !initial_vector || !authentication_tag) {
    console.error("❌ Malformed request body for decryption:", body);
    throw new FlowEndpointException(400);
  }

  const privateKeyObject = loadPrivateKey();

  // 1) Decrypt AES key using our RSA private key
  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: privateKeyObject,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encrypted_key, "base64")
  );

  // 2) Decrypt payload with AES-256-GCM
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    decryptedAesKey,
    Buffer.from(initial_vector, "base64")
  );
  decipher.setAuthTag(Buffer.from(authentication_tag, "base64"));

  let decrypted = decipher.update(encrypted_body, "base64", "utf8");
  decrypted += decipher.final("utf8");

  const decryptedBody = JSON.parse(decrypted);

  return {
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer: Buffer.from(initial_vector, "base64"),
    decryptedBody,
  };
}

/**
 * Encrypt response JSON back to WhatsApp.
 */
export function encryptResponse(responseBody, aesKeyBuffer, initialVectorBuffer) {
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    aesKeyBuffer,
    initialVectorBuffer
  );

  const json = JSON.stringify(responseBody);

  let encrypted = cipher.update(json, "utf8", "base64");
  encrypted += cipher.final("base64");

  const authTag = cipher.getAuthTag().toString("base64");

  return {
    encrypted_body: encrypted,
    initial_vector: initialVectorBuffer.toString("base64"),
    authentication_tag: authTag,
  };
}
