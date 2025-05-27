import "server-only";
import bcrypt from "bcrypt";
import { jwtVerify, SignJWT } from "jose";
import { cookies } from "next/headers";

import type { SessionPayload } from "../definitions";

import { env } from "../env";

const secretKey = env.SESSION_SECRET;
const encodedKey = new TextEncoder().encode(secretKey);

/**
 * Encrypt the session payload
 * @param payload - The session payload to encrypt
 * @returns The encrypted session
 */
async function encrypt(payload: SessionPayload) {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1 hour from now")
    .sign(encodedKey);
}

/**
 * Decrypt the session
 * @param session - The session to decrypt
 * @returns The decrypted session
 */
async function decrypt(session: string | undefined = "") {
  try {
    const { payload } = await jwtVerify(session, encodedKey, {
      algorithms: ["HS256"],
    });

    return payload;
  }
  catch (error) {
    console.error("Failed to verify session", error);
  }
}

/**
 * Hash the password
 * @param password - The password to hash
 * @returns The hashed password
 */
export async function hashPassword(password: string) {
  return await bcrypt.hash(password, 10);
}

/**
 * Verify the password
 * @param password - The password to verify
 * @param hashedPassword - The hashed password to verify against
 * @returns True if the password is correct, false otherwise
 */
export async function verifyPassword(password: string, hashedPassword: string) {
  return await bcrypt.compare(password, hashedPassword);
}

/**
 * Create a session
 * @param userId - The user ID to create the session for
 * @returns The created session
 */
export async function createSession(userId: number) {
  // Create the session
  // Expire in 1 hour
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  const session = await encrypt({
    userId,
    expiresAt,
  });

  // Save the session in a cookie
  const cookieStore = await cookies();
  cookieStore.set("session", session, {
    httpOnly: true,
    secure: true,
    expires: expiresAt,
    sameSite: "lax",
    path: "/",
  });
}

/**
 * Get the session
 * @returns The session
 */
export async function getSession() {
  const cookieStore = await cookies();
  const session = cookieStore.get("session")?.value;

  if (!session)
    return null;

  return await decrypt(session);
}

/**
 * Delete the session
 * @returns The deleted session
 */
export async function deleteSession() {
  const cookieStore = await cookies();
  cookieStore.delete("session");
}

/**
 * Update the session
 * @returns The updated session
 */
export async function updateSession() {
  const cookieStore = await cookies();
  const session = cookieStore.get("session")?.value;
  const payload = await decrypt(session);

  if (!session || !payload) {
    return null;
  }

  const expires = new Date(Date.now() + 60 * 60 * 1000);
  cookieStore.set("session", session, {
    httpOnly: true,
    secure: true,
    expires,
    sameSite: "lax",
    path: "/",
  });
}
