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
