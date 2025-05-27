## Stateless Auth (JWT) for Next.js

### Stateless Authentication

[Clerk](https://clerk.com/docs/how-clerk-works/overview#stateless-authentication) has a detailed explanation!🫡

### Setup Nextjs

```cmd
npx create-next-app@latest
```

### Stateless sessions

1. Generate a secret key

Use the `openssl` command to generate a generate a radom secret key:

```cmd
openssl rand -base64 32
```

Store the generated secret key in `.env` file:

```
SESSION_SECRET=your_secret_key
```

2. Encrypt and decrypt sessions

Use (Jose)[https://www.npmjs.com/package/jose] to encrypt and decrypt sessions, and import React's (server-only)[https://www.npmjs.com/package/server-only] package to ensure that your session management logic is only executed on the server. Give you the code under file `lib/session.ts`:

```ts
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
```

3. Auth server functions

Create signUp, signIn and signOut server actions in `app/actions/auth.ts`:

```ts
"use server";

import { eq } from "drizzle-orm";
import { redirect } from "next/navigation";

import type { SigninFormState, SignupFormState } from "@/lib/definitions";

import { db } from "@/db";
import { users } from "@/db/schema";
import { createSession, deleteSession, hashPassword, verifyPassword } from "@/lib/auth/stateless";
import { SigninFormSchema, SignupFormSchema } from "@/lib/definitions";

export async function signup(state: SignupFormState, formData: FormData) {
  // Validate form fields
  const validatedFields = SignupFormSchema.safeParse({
    name: formData.get("name"),
    email: formData.get("email"),
    password: formData.get("password"),
  });

  // If any form fields are invalid, return early
  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
    };
  }

  // Prepare user data for insertion
  const {
    name,
    email,
    password,
  } = validatedFields.data;
  const hashedPassword = await hashPassword(password);

  // Insert user into database
  const data = await db
    .insert(users)
    .values({
      name,
      email,
      password: hashedPassword,
    })
    .returning({
      id: users.id,
    });

  const user = data[0];

  if (!user) {
    return {
      message: "An error occurred while creating account.",
    };
  }

  // Create user session
  await createSession(user.id);
  redirect("/");
}

export async function signin(state: SigninFormState, formData: FormData) {
  const validatedFields = SigninFormSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });

  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
    };
  }

  const { email, password } = validatedFields.data;

  // Find user by email
  const data = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  const user = data[0];

  if (!user) {
    return {
      message: "Invalid email.",
    };
  }

  // Verify password
  const isPasswordValid = await verifyPassword(password, user.password);

  if (!isPasswordValid) {
    return {
      message: "Invalid password.",
    };
  }

  // Create user session
  await createSession(user.id);
  redirect("/");
}

export async function logout() {
  await deleteSession();
  redirect("/sign-in");
}
```

4. Add `middleware.ts`

```ts
import type { NextRequest } from "next/server";

import { jwtVerify } from "jose";
import { NextResponse } from "next/server";

import { env } from "./lib/env";

// 1. Specify protected and public routes
const protectedRoutes = ["/dashboard"];
const publicRoutes = ["/sign-in", "/sign-up", "/"];

export default async function middleware(req: NextRequest) {
  // 2. Check if the current route is protected or public
  const path = req.nextUrl.pathname;
  const isProtectedRoute = protectedRoutes.includes(path);
  const isPublicRoute = publicRoutes.includes(path);

  // 3. Read the session cookie directly from the request
  const cookie = req.cookies.get("session")?.value;
  let session: any = null;

  if (cookie) {
    try {
      const secretKey = env.SESSION_SECRET;
      const encodedKey = new TextEncoder().encode(secretKey);
      const { payload } = await jwtVerify(cookie, encodedKey, {
        algorithms: ["HS256"],
      });
      session = payload;
    }
    catch (e) {
      console.error("Failed to verify session", e);
      // Invalid or expired session
      session = null;
    }
  }

  // 4. Redirect to /sign-in if the user is not authenticated
  if (isProtectedRoute && !session?.userId) {
    return NextResponse.redirect(new URL("/sign-in", req.nextUrl));
  }

  // 5. Redirect to /dashboard if the user is authenticated
  if (
    isPublicRoute
    && session?.userId
    && !req.nextUrl.pathname.startsWith("/dashboard")
  ) {
    return NextResponse.redirect(new URL("/dashboard", req.nextUrl));
  }

  return NextResponse.next();
}

// Routes Middleware should not run on
export const config = {
  matcher: ["/((?!api|_next/static|_next/image|.*\\.png$).*)"],
};
```

5. Create Data Access Layer (DAL)

A DAL can be used to protect data fetched at request time. However, for static routes that share data between users, data will be fetched at build time and not at request time. Use Middlware to protect static routes. Add file `lib/dal.ts`:

```ts
import "server-only";
import { cookies } from "next/headers";

import { decrypt } from "@/app/lib/session";

export const verifySession = cache(async () => {
  const cookie = (await cookies()).get("session")?.value;
  const session = await decrypt(cookie);

  if (!session?.userId) {
    redirect("/login");
  }

  return { isAuth: true, userId: session.userId };
});
```
