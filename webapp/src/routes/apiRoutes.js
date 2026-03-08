import express from "express";
import fs from "node:fs";
import path from "node:path";
import multer from "multer";
import { authenticateToken } from "../middleware/auth.js";
import { authorize } from "../middleware/rbac.js";
import { validateBody, paymentSchema } from "../middleware/validation.js";
import { writeAuditLog } from "../utils/logger.js";

// General non-auth API routes for health, uploads, simulations, and reports.
const router = express.Router();
const uploadDir = process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

// Multer storage policy with filename sanitization.
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const safeName = file.originalname.replace(/[^A-Za-z0-9._-]/g, "_");
    cb(null, `${Date.now()}_${safeName}`);
  }
});

// Upload gate with size/type restrictions.
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allow = ["application/pdf", "image/png", "image/jpeg", "text/plain"];
    if (!allow.includes(file.mimetype)) {
      cb(new Error("Unsupported file type"));
      return;
    }
    cb(null, true);
  }
});

// Liveness endpoint for probes and basic platform checks.
router.get("/health", (req, res) => {
  writeAuditLog({ req, event: "HEALTHCHECK", success: true });
  res.json({ status: "ok" });
});

// Authenticated single-file upload endpoint with audit metadata.
router.post("/upload", authenticateToken, upload.single("file"), (req, res) => {
  writeAuditLog({
    req,
    event: "FILE_UPLOAD",
    userId: req.user.sub,
    success: true,
    metadata: {
      filename: req.file?.filename,
      mimetype: req.file?.mimetype,
      size: req.file?.size
    }
  });

  res.status(201).json({ message: "File accepted", file: req.file?.filename });
});

// Simulated payment route to exercise validation and telemetry.
router.post("/payment/simulate", authenticateToken, authorize("admin", "analyst"), validateBody(paymentSchema), (req, res) => {
  const { amount, currency, recipient } = req.body;
  const txId = `tx_${Date.now()}`;

  writeAuditLog({
    req,
    event: "PAYMENT_SIMULATION",
    userId: req.user.sub,
    success: true,
    metadata: { txId, amount, currency, recipient }
  });

  res.json({ txId, status: "approved", amount, currency, recipient });
});

// Admin-only sample protected report endpoint.
router.get("/admin/secure-report", authenticateToken, authorize("admin"), (req, res) => {
  writeAuditLog({ req, event: "REPORT_ACCESS", userId: req.user.sub, success: true });
  res.json({ report: "Security report content" });
});

export default router;
