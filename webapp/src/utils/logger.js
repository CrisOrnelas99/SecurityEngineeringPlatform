import fs from "node:fs";
import path from "node:path";

const logPath = process.env.LOG_FILE || path.join(process.cwd(), "logs", "app.log");
fs.mkdirSync(path.dirname(logPath), { recursive: true });

export function writeAuditLog({ req, event, success, userId = null, errorType = null, metadata = {} }) {
  const entry = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userId,
    endpoint: req.originalUrl,
    method: req.method,
    event,
    success,
    errorType,
    metadata
  };

  fs.appendFileSync(logPath, `${JSON.stringify(entry)}\n`, { encoding: "utf8" });
}

export function requestAudit(event, metadataBuilder = () => ({})) {
  return (req, _res, next) => {
    req.auditEvent = event;
    req.auditMetadata = metadataBuilder(req);
    next();
  };
}
