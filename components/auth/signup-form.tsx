"use client";

import { useActionState, useEffect } from "react";
import { toast } from "sonner";

import { signup } from "@/app/actions/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function SignupForm() {
  const [state, action, pending] = useActionState(signup, undefined);

  useEffect(() => {
    if (state?.message) {
      toast.error(state.message);
    }
  }, [state?.message]);

  return (
    <form action={action} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input id="name" name="name" placeholder="Enter your name" />
        {state?.errors?.name && (
          <p className="text-sm text-destructive">{state.errors.name}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input id="email" name="email" type="email" placeholder="Enter your email" />
        {state?.errors?.email && (
          <p className="text-sm text-destructive">{state.errors.email}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input id="password" name="password" type="password" placeholder="Enter your password" />
        {state?.errors?.password && (
          <div className="space-y-1">
            <p className="text-sm text-destructive">Password must:</p>
            <ul className="text-sm text-destructive space-y-1">
              {state.errors.password.map(error => (
                <li key={error} className="flex items-center gap-1">
                  <span>•</span>
                  {error}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <Button disabled={pending} type="submit" className="w-full">
        {pending ? "Creating account..." : "Sign Up"}
      </Button>
    </form>
  );
}
