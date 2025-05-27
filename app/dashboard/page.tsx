import { LogoutForm } from "@/components/auth/logout-form";
import { getSession } from "@/lib/auth/stateless";

export default async function DashboardPage() {
  const session = await getSession();

  return (
    <section>
      <h1>Dashboard</h1>
      {session && <pre>{String(session?.userId)}</pre>}
      {session && <LogoutForm />}
    </section>
  );
}
