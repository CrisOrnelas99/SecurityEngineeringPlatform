import { writeAuditLog } from "../utils/logger.js";

export function authorize(...roles) {
  return (req, res, next) => {
    const userRole = req.user?.role;
    if (!userRole || !roles.includes(userRole)) {
      writeAuditLog({
        req,
        event: "AUTHZ_DENIED",
        userId: req.user?.sub || null,
        success: false,
        errorType: "RBACDenied",
        metadata: { requiredRoles: roles, userRole }
      });
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    next();
  };
}
