// expected: 0 findings (a server-only route may reference the service_role key)
import { createClient } from "@supabase/supabase-js";

export async function GET() {
  const admin = createClient(
    "https://example.supabase.co",
    process.env.SUPABASE_SERVICE_ROLE_KEY as string,
  );
  const { data } = await admin.from("orders").select("*");
  return Response.json(data);
}
