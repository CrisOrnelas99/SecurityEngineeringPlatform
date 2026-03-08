import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import csrf from "csurf";
import path from "node:path";
import { fileURLToPath } from "node:url";
import authRoutes from "./routes/authRoutes.js";
import apiRoutes from "./routes/apiRoutes.js";
import { writeAuditLog } from "./utils/logger.js";
import { blocklistGuard } from "./middleware/threatControls.js";

// Express app bootstrap and core runtime paths.
const app = express();
const port = Number(process.env.PORT || 3000);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "..", "public");

// Trust upstream proxy headers (needed behind nginx/waf in docker).
app.set("trust proxy", 1);

// Core middleware stack: headers, CORS, JSON parsing, cookie signing, blocklist, static UI.
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || "http://localhost:5173", credentials: true }));
app.use(express.json({ limit: "512kb" }));
app.use(cookieParser(process.env.CSRF_COOKIE_SECRET || "default-csrf-secret"));
app.use(blocklistGuard);
app.use(express.static(publicDir));

// Structured request-level audit log for every completed response.
app.use((req, res, next) => {
  const started = Date.now();
  res.on("finish", () => {
    const metadata = {
      statusCode: res.statusCode,
      durationMs: Date.now() - started,
      userAgent: req.get("user-agent"),
      contentType: req.get("content-type"),
      queryKeys: Object.keys(req.query || {}),
      bodyKeys: req.body && typeof req.body === "object" ? Object.keys(req.body) : []
    };
    writeAuditLog({
      req,
      event: "REQUEST_AUDIT",
      success: res.statusCode < 400,
      userId: req.user?.sub || null,
      errorType: res.statusCode >= 400 ? `HTTP_${res.statusCode}` : null,
      metadata
    });
  });
  next();
});

// Global request rate limiting for baseline abuse control.
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    writeAuditLog({ req, event: "RATE_LIMIT", success: false, errorType: "RateLimitExceeded" });
    res.status(429).json({ error: "Too many requests" });
  }
});

app.use(limiter);

// CSRF token issue endpoint and protected API mounting.
const csrfProtection = csrf({ cookie: { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production" } });
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  writeAuditLog({ req, event: "CSRF_TOKEN_ISSUED", success: true });
  res.json({ csrfToken: req.csrfToken() });
});

app.use("/api/auth", csrfProtection, authRoutes);
app.use("/api", csrfProtection, apiRoutes);

// Honeypot endpoints intentionally look sensitive and always return 404.
for (const endpoint of ["/admin-backup", "/.env", "/internal-debug"]) {
  app.all(endpoint, (req, res) => {
    writeAuditLog({
      req,
      event: "HONEYPOT_TRIGGER",
      success: false,
      errorType: "HoneypotAccess",
      metadata: { honeypotEndpoint: endpoint }
    });
    res.status(404).json({ error: "Not found" });
  });
}

// Unified error handler with security-focused audit logging.
app.use((err, req, res, _next) => {
  const status = err.code === "EBADCSRFTOKEN" ? 403 : 500;
  writeAuditLog({
    req,
    event: "API_ERROR",
    success: false,
    errorType: err.code || err.name,
    metadata: { message: err.message }
  });
  res.status(status).json({ error: status === 403 ? "CSRF token invalid" : "Internal server error" });
});

// Start HTTP server.
app.listen(port, () => {
  // Startup log keeps structured format for platform observability.
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), event: "WEBAPP_STARTED", port }));
});
