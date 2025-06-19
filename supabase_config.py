from supabase import create_client, Client

SUPABASE_URL = "https://ttisjwcnjmfznjlxylpk.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR0aXNqd2Nuam1mem5qbHh5bHBrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAxNjQ3MjIsImV4cCI6MjA2NTc0MDcyMn0.-FwbrkhugRSgassXYTEGnhBYhmamWlgbdpyC5moaH7o"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) 