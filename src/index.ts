import "dotenv/config";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import { toNodeHandler } from "better-auth/node";
import { auth, pool } from "./auth.js";

const port = Number(process.env.PORT ?? 4000);
const origins = (process.env.TRUSTED_ORIGINS ?? "http://localhost:5173,http://localhost:5174")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const app = express();
app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.use(helmet());
app.use(
  cors({
    origin: origins,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["set-auth-token"],
  }),
);

app.get("/health", async (_req, res) => {
  try {
    await pool.query("select 1");
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

// Make the client IP reliable for rate limiting: never trust a client-supplied x-forwarded-for unless a proxy is in front.
app.use("/api/auth", (req, _res, next) => {
  if (process.env.TRUST_PROXY !== "true") req.headers["x-forwarded-for"] = req.socket.remoteAddress ?? "unknown";
  next();
});

// Better Auth must see the raw body, so do NOT add express.json() before this line.
app.all("/api/auth/*", toNodeHandler(auth));

process.on("unhandledRejection", (e) => console.error("[unhandledRejection]", e));

const server = app.listen(port, () => console.log(`[hvr-auth] listening on :${port}`));

function shutdown(signal: string) {
  console.log(`[hvr-auth] ${signal} received, shutting down`);
  server.close(() => pool.end().finally(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
