/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

import express from "express";
import {
  decryptRequest,
  encryptResponse,
  FlowEndpointException,
} from "./encryption.js";
import { getNextScreen } from "./flow.js";
import crypto from "crypto";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();

// CRITICAL: Use strict JSON parsing with increased limit
app.use(
  express.json({
    limit: '50mb',
    strict: true,
    type: 'application/json',
    // store raw body for HMAC verification
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf?.toString(encoding || "utf8");
    },
  })
);

const { APP_SECRET, PORT = "3000" } = process.env;

app.post("/", async (req, res) => {
  console.log("📨 === INCOMING WEBHOOK REQUEST ===");
  console.log("Content-Type:", req.get("content-type"));
  console.log("Content-Length:", req.get("content-length"));
  console.log("User-Agent:", req.get("user-agent"));
  
  // Diagnostic: Log the incoming body structure
  console.log("\n📦 Request body structure:");
  console.log("  Keys:", Object.keys(req.body));
  
  if (req.body.encrypted_flow_data) {
    const flowData = req.body.encrypted_flow_data;
    console.log("\n📏 encrypted_flow_data:");
    console.log("  Type:", typeof flowData);
    console.log("  Length:", flowData.length, "characters");
    console.log("  First 30 chars:", flowData.substring(0, 30));
    console.log("  Last 30 chars:", flowData.substring(flowData.length - 30));
    
    // Check for invalid characters in base64
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    const isValidBase64Format = base64Regex.test(flowData);
    console.log("  Valid base64 format:", isValidBase64Format);
    
    if (!isValidBase64Format) {
      console.error("  ❌ Contains invalid base64 characters!");
      const invalidChars = flowData.match(/[^A-Za-z0-9+/=]/g);
      console.error("  Invalid characters found:", invalidChars);
    }
    
    // Try to decode to check length
    try {
      const decoded = Buffer.from(flowData, 'base64');
      console.log("  Decoded length:", decoded.length, "bytes");
      console.log("  Is multiple of 16:", decoded.length % 16 === 0);
    } catch (e) {
      console.error("  ❌ Failed to decode base64:", e.message);
    }
  }
  
  if (req.body.encrypted_aes_key) {
    console.log("\n📏 encrypted_aes_key:");
    console.log("  Length:", req.body.encrypted_aes_key.length, "characters");
  }
  
  if (req.body.initial_vector) {
    console.log("\n📏 initial_vector:");
    console.log("  Length:", req.body.initial_vector.length, "characters");
  }
  
  // 🔐 Signature validation (Meta HMAC)
  console.log("\n🔐 Validating HMAC signature...");
  if (!isRequestSignatureValid(req)) {
    console.error("❌ Invalid x-hub-signature-256");
    // 432 = endpoint signature validation failed (per docs)
    return res.status(432).send();
  }
  console.log("✅ HMAC signature valid");

  let decryptedRequest;
  try {
    console.log("\n🔓 Starting decryption...");
    decryptedRequest = decryptRequest(req.body);
  } catch (err) {
    console.error("\n❌ Error during decryptRequest:", err);
    console.error("Stack:", err.stack);
    if (err instanceof FlowEndpointException) {
      return res.status(err.statusCode).send();
    }
    return res.status(500).send();
  }

  const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
  console.log("💬 Decrypted Request:", JSON.stringify(decryptedBody, null, 2));

  // OPTIONAL: here you could validate flow_token if you want
  // if (!isValidFlowToken(decryptedBody.flow_token)) { ... }

  let screenResponse;
  try {
    screenResponse = await getNextScreen(decryptedBody);
  } catch (err) {
    console.error("❌ Error in getNextScreen:", err);
    return res.status(500).send();
  }

  console.log("👉 Response to Encrypt:", JSON.stringify(screenResponse, null, 2));

  const encryptedResponse = encryptResponse(
    screenResponse,
    aesKeyBuffer,
    initialVectorBuffer
  );

  res.send(encryptedResponse);
});

app.get("/", (req, res) => {
  res.send(`<pre>WhatsApp Flow endpoint is running.
Checkout README.md to start.</pre>`);
});

app.listen(PORT, () => {
  console.log(`🚀 Server is listening on port: ${PORT}`);
  console.log(`📍 Webhook endpoint: http://localhost:${PORT}/`);
  console.log(`🔐 APP_SECRET: ${APP_SECRET ? 'Set ✅' : 'Not set ⚠️'}`);
});

/**
 * Validate the x-hub-signature-256 header from Meta using APP_SECRET.
 */
function isRequestSignatureValid(req) {
  if (!APP_SECRET) {
    console.warn(
      "⚠️ APP_SECRET is not set. Skipping request signature validation."
    );
    return true;
  }

  const signatureHeader = req.get("x-hub-signature-256");
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) {
    console.error("❌ Missing or malformed x-hub-signature-256 header");
    return false;
  }

  const signatureBuffer = Buffer.from(
    signatureHeader.replace("sha256=", ""),
    "hex"
  );

  const hmac = crypto.createHmac("sha256", APP_SECRET);
  const digestString = hmac.update(req.rawBody || "").digest("hex");
  const digestBuffer = Buffer.from(digestString, "hex");

  if (
    signatureBuffer.length !== digestBuffer.length ||
    !crypto.timingSafeEqual(digestBuffer, signatureBuffer)
  ) {
    console.error("❌ HMAC signature mismatch");
    return false;
  }

  return true;
}