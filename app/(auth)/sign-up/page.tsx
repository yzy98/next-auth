import Link from "next/link";

import { SignupForm } from "@/components/auth/signup-form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";

export default function SignUpPage() {
  return (
    <section className="flex items-center justify-center min-h-screen">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Sign Up</CardTitle>
          <CardDescription>Create your account to get started</CardDescription>
        </CardHeader>
        <CardContent>
          <SignupForm />
        </CardContent>
        <CardFooter>
          <p className="text-sm text-muted-foreground">
            Already have an account?
            <Button asChild variant="link" className="p-1">
              <Link href="/sign-in">Sign in</Link>
            </Button>
          </p>
        </CardFooter>
      </Card>
    </section>
  );
}
