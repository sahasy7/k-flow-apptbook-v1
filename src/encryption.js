/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Default path to your private key file
const DEFAULT_KEY_PATH = path.join(__dirname, "wa_private_key.pem");

/**
 * Load the private key from file and create a Node crypto KeyObject.
 */
function loadPrivateKey() {
  const keyPath = process.env.PRIVATE_KEY_PATH || DEFAULT_KEY_PATH;
  const passphrase = process.env.PRIVATE_KEY_PASSPHRASE || "";

  console.log("🔍 Loading private key...");
  console.log("  Expected path:", keyPath);
  console.log("  File exists:", fs.existsSync(keyPath));
  console.log("  Current directory:", process.cwd());
  console.log("  __dirname:", __dirname);

  let pem;
  try {
    pem = fs.readFileSync(keyPath, "utf8");
  } catch (e) {
    console.error("❌ Failed to read private key file:", keyPath, e);
    console.error("  Error code:", e.code);
    console.error("  Error message:", e.message);
    
    // Try to list files in the directory
    try {
      const dir = path.dirname(keyPath);
      const files = fs.readdirSync(dir);
      console.error("  Files in", dir, ":", files);
    } catch (listErr) {
      console.error("  Could not list directory:", listErr.message);
    }
    
    throw new FlowEndpointException(
      500,
      "Could not read private key file"
    );
  }

  console.log("📄 Key file loaded:");
  console.log("  Total length:", pem.length, "characters");
  console.log("  First line:", pem.split('\n')[0]);

  const rawKey = pem.replace(/\r/g, "").trim();

  try {
    return crypto.createPrivateKey({ 
      key: rawKey, 
      passphrase: passphrase || undefined 
    });
  } catch (e) {
    console.error("❌ createPrivateKey failed:", e);
    throw new FlowEndpointException(
      500,
      "Failed to create private key object: " + e.message
    );
  }
}

export const decryptRequest = (body) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
    console.error("❌ Malformed request body for decryption");
    throw new FlowEndpointException(400, "Malformed request body");
  }

  // Load private key from file
  const privateKey = loadPrivateKey();

  let decryptedAesKey = null;
  try {
    // decrypt AES key created by client
    decryptedAesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );
    console.log("✅ RSA decryption successful");
    console.log("🔑 Decrypted AES key length:", decryptedAesKey.length, "bytes");
  } catch (error) {
    console.error("❌ RSA decryption failed:", error);
    /*
    Failed to decrypt. Please verify your private key.
    If you change your public key. You need to return HTTP status code 421 to refresh the public key on the client
    */
    throw new FlowEndpointException(
      421,
      "Failed to decrypt the request. Please verify your private key."
    );
  }

  // decrypt flow data
  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");

  console.log("📊 Decryption info:");
  console.log("  Flow data length:", flowDataBuffer.length, "bytes");
  console.log("  IV length:", initialVectorBuffer.length, "bytes");

  const TAG_LENGTH = 16;
  const encrypted_flow_data_body = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encrypted_flow_data_tag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv(
    "aes-128-gcm",
    decryptedAesKey,
    initialVectorBuffer
  );
  decipher.setAuthTag(encrypted_flow_data_tag);

  try {
    const decryptedJSONString = Buffer.concat([
      decipher.update(encrypted_flow_data_body),
      decipher.final(),
    ]).toString("utf-8");

    console.log("✅ AES-GCM decryption successful");

    return {
      decryptedBody: JSON.parse(decryptedJSONString),
      aesKeyBuffer: decryptedAesKey,
      initialVectorBuffer,
    };
  } catch (error) {
    console.error("❌ AES-GCM decryption failed:", error);
    throw new FlowEndpointException(
      500,
      "Failed to decrypt flow data: " + error.message
    );
  }
};

export const encryptResponse = (
  response,
  aesKeyBuffer,
  initialVectorBuffer
) => {
  // flip initial vector
  const flipped_iv = [];
  for (const pair of initialVectorBuffer.entries()) {
    flipped_iv.push(~pair[1]);
  }

  // encrypt response data
  const cipher = crypto.createCipheriv(
    "aes-128-gcm",
    aesKeyBuffer,
    Buffer.from(flipped_iv)
  );
  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
};

export const FlowEndpointException = class FlowEndpointException extends Error {
  constructor (statusCode, message) {
    super(message)

    this.name = this.constructor.name
    this.statusCode = statusCode;
  }
}