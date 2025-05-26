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
