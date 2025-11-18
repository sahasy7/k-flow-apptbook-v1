/**
 * Encryption / decryption helpers for WhatsApp Flows endpoint.
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Default path to your private key file
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

  const rawKey = pem.replace(/\r/g, "").trim();
  const lines = rawKey.split("\n");

  console.log("🔐 PRIVATE_KEY from file:");
  console.log("  Path:", keyPath);
  console.log("  First line:", lines[0]);
  console.log("  Last line:", lines[lines.length - 1]);

  if (!rawKey.startsWith("-----BEGIN")) {
    throw new Error("PRIVATE KEY file is not a valid PEM");
  }

  const keyType = rawKey.includes("BEGIN RSA PRIVATE KEY")
    ? "pkcs1"
    : "pkcs8";

  try {
    return crypto.createPrivateKey({
      key: rawKey,
      format: "pem",
      type: keyType,
    });
  } catch (e) {
    console.error("❌ createPrivateKey failed:", e);
    throw e;
  }
}

/**
 * Decrypt incoming WhatsApp Flow request body.
 * WhatsApp sends:
 *  - encrypted_flow_data (AES-256-CBC ciphertext, base64)
 *  - encrypted_aes_key   (RSA-encrypted AES key, base64)
 *  - initial_vector      (IV for AES, base64)
 */
export function decryptRequest(body) {
  const {
    encrypted_flow_data,
    encrypted_aes_key,
    initial_vector,
  } = body;

  if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
    console.error("❌ Malformed request body for decryption:", body);
    throw new FlowEndpointException(400);
  }

  const privateKeyObject = loadPrivateKey();

  // 1) Decrypt AES key using our RSA private key
  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: privateKeyObject,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      // oaepHash default (SHA1) matches Meta sample
    },
    Buffer.from(encrypted_aes_key, "base64")
  );

  // 2) Decrypt payload with AES-256-CBC
  const ivBuffer = Buffer.from(initial_vector, "base64");
  const decipher = crypto.createDecipheriv("aes-256-cbc", decryptedAesKey, ivBuffer);

  let decrypted = decipher.update(encrypted_flow_data, "base64", "utf8");
  decrypted += decipher.final("utf8");

  const decryptedBody = JSON.parse(decrypted);

  return {
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer: ivBuffer,
    decryptedBody,
  };
}

/**
 * Encrypt response JSON back to WhatsApp.
 * Response must contain:
 *  - encrypted_flow_data (AES-256-CBC ciphertext, base64)
 * WhatsApp already knows the AES key & IV, so we just reuse them.
 */
export function encryptResponse(responseBody, aesKeyBuffer, initialVectorBuffer) {
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    aesKeyBuffer,
    initialVectorBuffer
  );

  const json = JSON.stringify(responseBody);

  let encrypted = cipher.update(json, "utf8", "base64");
  encrypted += cipher.final("base64");

  return {
    encrypted_flow_data: encrypted,
  };
}
