-- Row Level Security on EVERY table, with no policies.
-- Why: Supabase exposes tables through its auto-generated Data API (PostgREST). With RLS enabled and no policy, that API can read nothing,
-- so it cannot bypass Django's permission checks. Django itself connects as the table-owner role (postgres), which bypasses RLS, so it is unaffected.
-- RE-RUN THIS AFTER EVERY DEPLOY THAT ADDS TABLES (new migrations create new tables with RLS off). It is safe to run repeatedly.
-- Alternatively disable the Data API in the Supabase dashboard (Settings > API) and still run this as defence in depth.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', r.tablename);
  END LOOP;
END $$;

-- Check: every row should say true.
SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY rowsecurity, tablename;
