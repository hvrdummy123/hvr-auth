// Usage: npm run make-admin -- someone@example.com
import "dotenv/config";
import { Pool } from "pg";

const email = process.argv[2]?.toLowerCase();
if (!email) {
  console.error("Usage: npm run make-admin -- <email>");
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const res = await pool.query(`update "user" set role = 'admin' where lower(email) = $1`, [email]);
console.log(res.rowCount ? `${email} is now an admin (sign out and in again to refresh the token).` : `No user with email ${email}`);
await pool.end();
