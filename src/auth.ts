// NOTE: this file avoids local imports on purpose so the Better Auth CLI (migrate) can load it directly.
import "dotenv/config";
import { betterAuth } from "better-auth";
import { admin, bearer, jwt } from "better-auth/plugins";
import { Pool } from "pg";

const authUrl = process.env.AUTH_URL ?? "http://localhost:4000";
const trustedOrigins = (process.env.TRUSTED_ORIGINS ?? "http://localhost:5173,http://localhost:5174")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const authLimit = Number(process.env.RL_AUTH_MAX ?? 5);

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});
// A dropped idle connection (DB restart/failover) must be logged, not crash the process.
pool.on("error", (err) => console.error("[db] idle client error:", err.message));

export const auth = betterAuth({
  appName: "HVR",
  baseURL: authUrl,
  secret: process.env.BETTER_AUTH_SECRET,
  database: pool,
  trustedOrigins,

  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
    maxPasswordLength: 128,
    autoSignIn: true,
    // Turn on once you have an email provider: requireEmailVerification: true
  },

  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // refresh once a day
    cookieCache: { enabled: true, maxAge: 5 * 60 }, // fewer DB hits on getSession
  },

  // Rate limiting, stored in Postgres so it survives restarts and is shared by every auth instance.
  rateLimit: {
    enabled: true,
    window: 60,
    max: 100,
    storage: "database",
    customRules: {
      "/sign-in/email": { window: 60, max: authLimit },
      "/sign-up/email": { window: 60, max: authLimit },
      "/token": { window: 60, max: 60 },
    },
  },

  advanced: {
    // Rate limits are per client IP. index.ts guarantees x-forwarded-for is trustworthy:
    // behind your proxy (TRUST_PROXY=true) it is the proxy's value, otherwise it is the real socket address.
    ipAddress: { ipAddressHeaders: ["x-forwarded-for"] },
    // Production cross-subdomain setup (app.example.com + auth.example.com):
    // crossSubDomainCookies: { enabled: true, domain: ".example.com" },
  },

  plugins: [
    // Issues short-lived JWTs + a JWKS endpoint so the chat service can verify users WITHOUT calling auth on every request.
    jwt({
      jwt: {
        expirationTime: "15m",
        definePayload: ({ user }) => ({
          name: user.name,
          email: user.email,
          role: (user as { role?: string }).role ?? "user",
        }),
      },
    }),
    // Lets scripts/mobile clients use "Authorization: Bearer <session token>" (the e2e test uses it).
    bearer(),
    // Roles, ban/unban, list users, revoke sessions, impersonate (used by hvr-admin).
    admin({ defaultRole: "user", adminRoles: ["admin"] }),
    // Optional extra: haveIBeenPwned() rejects breached passwords, but it calls an external API on every sign-up
    // (and sign-up fails if that API is down), so it is left out by default.
  ],
});
