/**
 * JWT-signed share links — generate read-only URLs that grant access to
 * specific scans (or specific findings) without requiring user accounts.
 *
 * Use case: "post my report to bug-bounty triage; let them verify findings
 * for 7 days, but don't expose anything else."
 *
 * Token shape (HS256, signed with MOBA_SHARE_SECRET):
 *   {
 *     scanId: <uuid>,
 *     scope: "scan" | "finding",
 *     findingId?: <uuid>,        // present iff scope === "finding"
 *     iat: <unix>,
 *     exp: <unix>
 *   }
 *
 * Receiver: `GET /share/<token>` validates + redirects to the read-only viewer.
 */

import { SignJWT, jwtVerify } from "jose";

const SECRET = process.env.MOBA_SHARE_SECRET;

function getKey(): Uint8Array {
  if (!SECRET) throw new Error("MOBA_SHARE_SECRET not set — cannot sign share links");
  return new TextEncoder().encode(SECRET);
}

export interface ShareClaims {
  scanId: string;
  scope: "scan" | "finding";
  findingId?: string;
  iat: number;
  exp: number;
}

export async function signShare(args: { scanId: string; scope: "scan" | "finding"; findingId?: string; ttlSeconds?: number }): Promise<string> {
  const ttl = args.ttlSeconds ?? 7 * 24 * 60 * 60; // default 7 days
  const now = Math.floor(Date.now() / 1000);
  const claims = { scanId: args.scanId, scope: args.scope, ...(args.findingId ? { findingId: args.findingId } : {}) };
  return await new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(getKey());
}

export async function verifyShare(token: string): Promise<ShareClaims> {
  const { payload } = await jwtVerify(token, getKey(), { algorithms: ["HS256"] });
  return payload as unknown as ShareClaims;
}
