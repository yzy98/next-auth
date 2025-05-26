import Link from "next/link";

import { Button } from "@/components/ui/button";

export default function Home() {
  return (
    <section>
      <div className="flex gap-2">
        <Button asChild>
          <Link href="/sign-in">Sign In</Link>
        </Button>
        <Button asChild>
          <Link href="/sign-up">Sign Up</Link>
        </Button>
        <Button asChild>
          <Link href="/dashboard">Dashboard</Link>
        </Button>
      </div>
      <h1>Home</h1>
    </section>
  );
}
