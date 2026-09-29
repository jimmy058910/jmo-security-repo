// A comment mentioning service_role must never itself produce a finding.
import { createClient } from "@supabase/supabase-js";

export const admin = createClient(
  "https://example.supabase.co",
  process.env.SUPABASE_SERVICE_ROLE_KEY as string,
);
