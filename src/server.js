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

app.use(
  express.json({
    // store raw body for HMAC verification
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf?.toString(encoding || "utf8");
    },
  })
);

const { APP_SECRET, PORT = "3000" } = process.env;

app.post("/", async (req, res) => {
  // 🔐 Signature validation (Meta HMAC)
  if (!isRequestSignatureValid(req)) {
    console.error("❌ Invalid x-hub-signature-256");
    // 432 = endpoint signature validation failed (per docs)
    return res.status(432).send();
  }

  let decryptedRequest;
  try {
    decryptedRequest = decryptRequest(req.body);
  } catch (err) {
    console.error("❌ Error during decryptRequest:", err);
    if (err instanceof FlowEndpointException) {
      return res.status(err.statusCode).send();
    }
    return res.status(500).send();
  }

  const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
  console.log("💬 Decrypted Request:", decryptedBody);

  // OPTIONAL: here you could validate flow_token if you want
  // if (!isValidFlowToken(decryptedBody.flow_token)) { ... }

  let screenResponse;
  try {
    screenResponse = await getNextScreen(decryptedBody);
  } catch (err) {
    console.error("❌ Error in getNextScreen:", err);
    return res.status(500).send();
  }

  console.log("👉 Response to Encrypt:", screenResponse);

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
