import jwt from "jsonwebtoken";
import { writeAuditLog } from "../utils/logger.js";
import { isLockedUser } from "./threatControls.js";

// Verify bearer access token and attach decoded user claims to request context.
export function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;

  if (!token) {
    writeAuditLog({ req, event: "AUTH_MISSING", success: false, errorType: "MissingToken" });
    res.status(401).json({ error: "Access token required" });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const isAdmin = decoded?.role === "admin";
    if (isLockedUser(decoded.sub) && !isAdmin) {
      writeAuditLog({
        req,
        event: "LOCKED_USER_DENY",
        userId: decoded.sub,
        success: false,
        errorType: "LockedUser"
      });
      res.status(423).json({ error: "Account locked" });
      return;
    }
    if (isLockedUser(decoded.sub) && isAdmin) {
      writeAuditLog({
        req,
        event: "LOCKED_USER_BYPASS_ADMIN",
        userId: decoded.sub,
        success: true
      });
    }
    req.user = decoded;
    next();
  } catch (error) {
    writeAuditLog({ req, event: "AUTH_INVALID", success: false, errorType: error.name });
    res.status(401).json({ error: "Invalid access token" });
  }
}
