import { z } from "zod";

const username = z.string().trim().min(4).max(64).regex(/^[A-Za-z0-9_-]+$/);
const password = z.string().min(12).max(128);

export const registerSchema = z.object({ username, password, role: z.enum(["analyst", "admin"]).default("analyst") });
export const loginSchema = z.object({ username, password });
export const adminCreateUserSchema = z.object({
  username,
  role: z.enum(["analyst", "admin"]).default("analyst")
});
export const changePasswordSchema = z.object({
  currentPassword: password,
  newPassword: password
}).refine((v) => v.currentPassword !== v.newPassword, {
  message: "New password must be different",
  path: ["newPassword"]
});
export const setInitialPasswordSchema = z.object({
  newUserInitialPassword: password
});

export const paymentSchema = z.object({
  amount: z.number().positive().max(100000),
  currency: z.enum(["USD", "EUR", "GBP"]),
  recipient: z.string().trim().min(2).max(64)
});

export function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
      return;
    }

    req.body = parsed.data;
    next();
  };
}
