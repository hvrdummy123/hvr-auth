
// NOTE: this file avoids local imports on purpose so the Better Auth CLI (migrate) can load it directly.
import "dotenv/config";
import { betterAuth } from "better-auth";
import { admin, bearer, jwt } from "better-auth/plugins";
import nodemailer from "nodemailer";
import { Pool } from "pg";

const authUrl = process.env.AUTH_URL ?? "http://localhost:4000";
const trustedOrigins = (process.env.TRUSTED_ORIGINS ?? "http://localhost:5173,http://localhost:5174")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const authLimit = Number(process.env.RL_AUTH_MAX ?? 5);
const mailLimit = Number(process.env.RL_MAIL_MAX ?? 3); // reset / re-send-verification emails per minute per IP

// ---- email (SMTP) --------------------------------------------------------------------------
// Set SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_FROM to really send. Without them, links are printed to the
// server log instead, so local development works with no email provider.
const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT ?? 587), // 587 = STARTTLS. (GCP blocks outbound port 25.)
      secure: Number(process.env.SMTP_PORT ?? 587) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

function sendMail(to: string, subject: string, text: string, html: string) {
  if (!transporter) {
    console.log(`\n[mail:not-sent] to=${to} subject="${subject}"\n${text}\n`);
    return;
  }
  // Deliberately not awaited by callers: a slow mail server must not slow down (or leak timing about) the API.
  transporter
    .sendMail({ from: process.env.MAIL_FROM ?? process.env.SMTP_USER, to, subject, text, html })
    .catch((e: Error) => console.error("[mail] send failed:", e.message));
}

const button = (url: string, label: string) =>
  `<p><a href="${url}" style="background:#0a6c74;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:600">${label}</a></p><p style="color:#5e6c7b;font-size:13px">If the button doesn't work, paste this link into your browser:<br>${url}</p>`;

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
    // Sign-up only "counts" once the emailed link is clicked: until then sign-in is refused.
    requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION !== "false",
    resetPasswordTokenExpiresIn: 60 * 60, // reset links last 1 hour
    revokeSessionsOnPasswordReset: true, // changing the password signs the account out everywhere
    sendResetPassword: async ({ user, url }) => {
      sendMail(
        user.email,
        "Reset your HVR password",
        `Hi ${user.name},\n\nUse this link to choose a new password (valid for 1 hour):\n${url}\n\nIf you didn't ask for this, you can ignore this email.`,
        `<p>Hi ${user.name},</p><p>Use this button to choose a new password. It works for 1 hour.</p>${button(url, "Reset password")}<p style="color:#5e6c7b;font-size:13px">If you didn't ask for this, you can ignore this email.</p>`,
      );
    },
  },

  emailVerification: {
    sendOnSignUp: true,
    sendOnSignIn: true, // trying to sign in while unverified re-sends the link
    autoSignInAfterVerification: true, // clicking the link also signs you in
    expiresIn: 60 * 60,
    sendVerificationEmail: async ({ user, url }) => {
      sendMail(
        user.email,
        "Verify your email for HVR",
        `Hi ${user.name},\n\nConfirm your email to finish creating your account (valid for 1 hour):\n${url}\n\nIf you didn't sign up, ignore this email.`,
        `<p>Hi ${user.name},</p><p>Confirm your email to finish creating your HVR account. The link works for 1 hour.</p>${button(url, "Verify email")}<p style="color:#5e6c7b;font-size:13px">If you didn't sign up, ignore this email.</p>`,
      );
    },
  },

  // "Continue with Google". Google accounts arrive already email-verified. If the same email already has a
  // password account, Better Auth links the two instead of creating a duplicate.
  socialProviders: {
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? { google: { clientId: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET } }
      : {}),
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
      "/request-password-reset": { window: 60, max: mailLimit },
      "/send-verification-email": { window: 60, max: mailLimit },
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
  ],
});

// // NOTE: this file avoids local imports on purpose so the Better Auth CLI (migrate) can load it directly.
// import "dotenv/config";
// import { betterAuth } from "better-auth";
// import { admin, bearer, jwt } from "better-auth/plugins";
// import { Pool } from "pg";

// const authUrl = process.env.AUTH_URL ?? "http://localhost:4000";
// const trustedOrigins = (process.env.TRUSTED_ORIGINS ?? "http://localhost:5173,http://localhost:5174")
//   .split(",")
//   .map((s) => s.trim())
//   .filter(Boolean);
// const authLimit = Number(process.env.RL_AUTH_MAX ?? 5);

// export const pool = new Pool({
//   connectionString: process.env.DATABASE_URL,
//   max: 10,
//   idleTimeoutMillis: 30_000,
//   connectionTimeoutMillis: 5_000,
// });
// // A dropped idle connection (DB restart/failover) must be logged, not crash the process.
// pool.on("error", (err) => console.error("[db] idle client error:", err.message));

// export const auth = betterAuth({
//   appName: "HVR",
//   baseURL: authUrl,
//   secret: process.env.BETTER_AUTH_SECRET,
//   database: pool,
//   trustedOrigins,

//   emailAndPassword: {
//     enabled: true,
//     minPasswordLength: 8,
//     maxPasswordLength: 128,
//     autoSignIn: true,
//     // Turn on once you have an email provider: requireEmailVerification: true
//   },

//   session: {
//     expiresIn: 60 * 60 * 24 * 7, // 7 days
//     updateAge: 60 * 60 * 24, // refresh once a day
//     cookieCache: { enabled: true, maxAge: 5 * 60 }, // fewer DB hits on getSession
//   },

//   // Rate limiting, stored in Postgres so it survives restarts and is shared by every auth instance.
//   rateLimit: {
//     enabled: true,
//     window: 60,
//     max: 100,
//     storage: "database",
//     customRules: {
//       "/sign-in/email": { window: 60, max: authLimit },
//       "/sign-up/email": { window: 60, max: authLimit },
//       "/token": { window: 60, max: 60 },
//     },
//   },

//   advanced: {
//     // Rate limits are per client IP. index.ts guarantees x-forwarded-for is trustworthy:
//     // behind your proxy (TRUST_PROXY=true) it is the proxy's value, otherwise it is the real socket address.
//     ipAddress: { ipAddressHeaders: ["x-forwarded-for"] },
//     // Production cross-subdomain setup (app.example.com + auth.example.com):
//     // crossSubDomainCookies: { enabled: true, domain: ".example.com" },
//   },

//   plugins: [
//     // Issues short-lived JWTs + a JWKS endpoint so the chat service can verify users WITHOUT calling auth on every request.
//     jwt({
//       jwt: {
//         expirationTime: "15m",
//         definePayload: ({ user }) => ({
//           name: user.name,
//           email: user.email,
//           role: (user as { role?: string }).role ?? "user",
//         }),
//       },
//     }),
//     // Lets scripts/mobile clients use "Authorization: Bearer <session token>" (the e2e test uses it).
//     bearer(),
//     // Roles, ban/unban, list users, revoke sessions, impersonate (used by hvr-admin).
//     admin({ defaultRole: "user", adminRoles: ["admin"] }),
//     // Optional extra: haveIBeenPwned() rejects breached passwords, but it calls an external API on every sign-up
//     // (and sign-up fails if that API is down), so it is left out by default.
//   ],
// });