/**
 * Encryption / decryption helpers for WhatsApp Flows endpoint.
 * Fixed for Node.js 20+ compatibility
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
 * Supports both encrypted PKCS#1 and unencrypted PKCS#8 formats.
 */
function loadPrivateKey() {
  const keyPath = process.env.PRIVATE_KEY_PATH || DEFAULT_KEY_PATH;
  const passphrase = process.env.PRIVATE_KEY_PASSPHRASE; // Add passphrase support

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

  // Detect key type and encryption
  const isEncrypted = rawKey.includes("Proc-Type: 4,ENCRYPTED");
  const keyType = rawKey.includes("BEGIN RSA PRIVATE KEY")
    ? "pkcs1"
    : "pkcs8";

  console.log("  Key type:", keyType);
  console.log("  Encrypted:", isEncrypted);

  try {
    const keyOptions = {
      key: rawKey,
      format: "pem",
      type: keyType,
    };

    // Add passphrase if key is encrypted
    if (isEncrypted) {
      if (!passphrase) {
        throw new Error(
          "Private key is encrypted but PRIVATE_KEY_PASSPHRASE environment variable is not set"
        );
      }
      keyOptions.passphrase = passphrase;
      console.log("  Using passphrase for encrypted key");
    }

    return crypto.createPrivateKey(keyOptions);
  } catch (e) {
    console.error("❌ createPrivateKey failed:", e);
    throw e;
  }
}

/**
 * Decide which AES-CBC algorithm to use based on key length.
 */
function getAesCbcAlgorithm(aesKeyBuffer) {
  const len = aesKeyBuffer.length; // bytes
  if (len === 16) return "aes-128-cbc";
  if (len === 24) return "aes-192-cbc";
  if (len === 32) return "aes-256-cbc";
  throw new Error(`Unsupported AES key length: ${len} bytes`);
}

/**
 * Try to decrypt the AES key using RSA OAEP.
 * First try SHA-256, then fallback to default OAEP (SHA-1).
 */
function rsaDecryptAesKey(privateKeyObject, encryptedAesKeyBase64) {
  const encryptedBuf = Buffer.from(encryptedAesKeyBase64, "base64");

  // Try OAEP + SHA-256 first
  try {
    return crypto.privateDecrypt(
      {
        key: privateKeyObject,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encryptedBuf
    );
  } catch (err) {
    if (err.code !== "ERR_OSSL_RSA_OAEP_DECODING_ERROR") {
      console.error("❌ RSA decrypt (SHA-256) failed with non-OAEP error:", err);
      throw err;
    }
    console.warn("⚠️ RSA decrypt with SHA-256 failed, trying default OAEP (SHA-1)...");
  }

  // Fallback: OAEP with default hash (SHA-1)
  try {
    return crypto.privateDecrypt(
      {
        key: privateKeyObject,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      encryptedBuf
    );
  } catch (err2) {
    console.error("❌ RSA decrypt failed with both SHA-256 and default OAEP:", err2);
    throw err2;
  }
}

/**
 * Decrypt incoming WhatsApp Flow request body.
 * WhatsApp sends:
 *  - encrypted_flow_data (AES-encrypted payload, base64)
 *  - encrypted_aes_key   (RSA-encrypted AES key, base64)
 *  - initial_vector      (IV for AES, base64)
 */
export function decryptRequest(body) {
  console.log("🔍 === DECRYPTION REQUEST STARTED ===");
  
  const {
    encrypted_flow_data,
    encrypted_aes_key,
    initial_vector,
  } = body;

  // Log incoming data (first 50 chars only for security)
  console.log("📥 Incoming data:");
  console.log("  encrypted_flow_data:", encrypted_flow_data?.substring(0, 50) + "...");
  console.log("  encrypted_aes_key:", encrypted_aes_key?.substring(0, 50) + "...");
  console.log("  initial_vector:", initial_vector?.substring(0, 50) + "...");

  if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
    console.error("❌ Malformed request body for decryption");
    throw new FlowEndpointException(400);
  }

  try {
    // Step 1: Load private key
    console.log("📋 Step 1: Loading private key...");
    const privateKeyObject = loadPrivateKey();
    console.log("✅ Private key loaded successfully");

    // Step 2: Decrypt AES key using RSA
    console.log("📋 Step 2: Decrypting AES key with RSA...");
    let decryptedAesKey;
    try {
      decryptedAesKey = rsaDecryptAesKey(privateKeyObject, encrypted_aes_key);
      console.log("✅ RSA decryption successful");
      console.log("🔑 Decrypted AES key length:", decryptedAesKey.length, "bytes");
      console.log("🔑 AES key (hex):", decryptedAesKey.toString('hex').substring(0, 32) + "...");
    } catch (rsaError) {
      console.error("❌ RSA decryption FAILED:", rsaError.message);
      console.error("This means the private key doesn't match the public key used by WhatsApp");
      throw rsaError;
    }

    // Step 3: Determine AES algorithm
    console.log("📋 Step 3: Determining AES algorithm...");
    const algo = getAesCbcAlgorithm(decryptedAesKey);
    console.log("✅ Using algorithm:", algo);

    // Step 4: Prepare buffers
    console.log("📋 Step 4: Preparing decryption buffers...");
    const ivBuffer = Buffer.from(initial_vector, "base64");
    const encryptedDataBuffer = Buffer.from(encrypted_flow_data, "base64");

    console.log("📊 Buffer information:");
    console.log("  IV length:", ivBuffer.length, "bytes (expected: 16)");
    console.log("  IV (hex):", ivBuffer.toString('hex'));
    console.log("  Encrypted data length:", encryptedDataBuffer.length, "bytes");
    console.log("  AES key length:", decryptedAesKey.length, "bytes");
    console.log("  Data is multiple of 16?", encryptedDataBuffer.length % 16 === 0);

    // Validate IV length
    if (ivBuffer.length !== 16) {
      throw new Error(`Invalid IV length: ${ivBuffer.length}, expected 16 bytes`);
    }

    // Validate encrypted data is multiple of block size
    if (encryptedDataBuffer.length % 16 !== 0) {
      console.error("⚠️ WARNING: Encrypted data length is NOT a multiple of 16!");
      console.error("  Length:", encryptedDataBuffer.length);
      console.error("  Remainder:", encryptedDataBuffer.length % 16);
      console.error("This will cause 'wrong final block length' error!");
      throw new Error("Encrypted data has invalid length - not a multiple of block size");
    }

    // Step 5: Perform AES-CBC decryption
    console.log("📋 Step 5: Performing AES-CBC decryption...");
    const decipher = crypto.createDecipheriv(algo, decryptedAesKey, ivBuffer);
    decipher.setAutoPadding(true);

    let decrypted;
    try {
      console.log("  Calling decipher.update()...");
      const part1 = decipher.update(encryptedDataBuffer);
      console.log("  ✅ decipher.update() successful, got", part1.length, "bytes");
      
      console.log("  Calling decipher.final()...");
      const part2 = decipher.final();
      console.log("  ✅ decipher.final() successful, got", part2.length, "bytes");
      
      const decryptedBuffer = Buffer.concat([part1, part2]);
      decrypted = decryptedBuffer.toString("utf8");
      console.log("✅ AES decryption successful, decrypted", decrypted.length, "chars");
    } catch (finalError) {
      console.error("❌ AES decipher.final() FAILED:", finalError.message);
      console.error("Error code:", finalError.code);
      console.error("");
      console.error("🔍 DEBUGGING INFO:");
      console.error("  1. Check if encrypted_flow_data is complete and not truncated");
      console.error("  2. Verify initial_vector is correct");
      console.error("  3. Confirm WhatsApp is using the correct public key");
      console.error("");
      
      // Try manual padding removal
      console.log("🔄 Attempting manual padding removal...");
      const decipher2 = crypto.createDecipheriv(algo, decryptedAesKey, ivBuffer);
      decipher2.setAutoPadding(false);
      
      try {
        const decryptedBuffer2 = Buffer.concat([
          decipher2.update(encryptedDataBuffer),
          decipher2.final()
        ]);
        
        console.log("  Decrypted buffer length:", decryptedBuffer2.length);
        console.log("  Last 5 bytes:", decryptedBuffer2.slice(-5).toString('hex'));
        
        // Manually remove PKCS7 padding
        const paddingLength = decryptedBuffer2[decryptedBuffer2.length - 1];
        console.log("  Detected padding length:", paddingLength);
        
        if (paddingLength > 0 && paddingLength <= 16) {
          const unpaddedBuffer = decryptedBuffer2.slice(0, -paddingLength);
          decrypted = unpaddedBuffer.toString("utf8");
          console.log("✅ Manual padding removal succeeded!");
        } else {
          throw new Error("Invalid padding length: " + paddingLength);
        }
      } catch (noPaddingError) {
        console.error("❌ Manual padding removal also failed:", noPaddingError.message);
        throw finalError;
      }
    }

    // Step 6: Parse JSON
    console.log("📋 Step 6: Parsing JSON...");
    const decryptedBody = JSON.parse(decrypted);
    console.log("✅ JSON parsed successfully");
    console.log("🔍 === DECRYPTION COMPLETED SUCCESSFULLY ===");

    return {
      aesKeyBuffer: decryptedAesKey,
      initialVectorBuffer: ivBuffer,
      decryptedBody,
    };
  } catch (error) {
    console.error("❌ === DECRYPTION FAILED ===");
    console.error("Error:", error.message);
    console.error("Stack:", error.stack);
    throw error;
  }
}

/**
 * Encrypt response JSON back to WhatsApp.
 * Response must contain:
 *  - encrypted_flow_data (AES-CBC ciphertext, base64)
 * WhatsApp already knows the AES key & IV, so we just reuse them.
 */
export function encryptResponse(responseBody, aesKeyBuffer, initialVectorBuffer) {
  try {
    const algo = getAesCbcAlgorithm(aesKeyBuffer);

    const cipher = crypto.createCipheriv(
      algo,
      aesKeyBuffer,
      initialVectorBuffer
    );

    const json = JSON.stringify(responseBody);

    // Use Buffer approach for consistency with decryption
    const encryptedBuffer = Buffer.concat([
      cipher.update(json, "utf8"),
      cipher.final()
    ]);

    const encrypted = encryptedBuffer.toString("base64");

    console.log("✅ Encryption successful");
    console.log("  Response length:", json.length, "bytes");
    console.log("  Encrypted length:", encrypted.length, "bytes");

    return {
      encrypted_flow_data: encrypted,
    };
  } catch (error) {
    console.error("❌ Error during encryptResponse:", error);
    throw error;
  }
}