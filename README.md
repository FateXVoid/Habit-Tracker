# Habit Tracker — Key License System

This build adds:
- Key login before the existing loading screen.
- Persistent login on a device via a secure HttpOnly session cookie.
- User keys limited to one bound device.
- Developer keys with unlimited device bindings.
- "Device logged out" to release a bound device and return the user key to 0/1.
- Per-license local app data separation.
- Hidden, unlinked Developer Console at `/void-console-7c2a.html`.
- Developer console with Generate Key, Active / Inactive / All views, device release, and key revoke.
- Server-side password verification. The plaintext Developer password is not present in the front-end code.
- Atomic device claiming in Postgres to prevent two devices from claiming the same user key at the same time.

## Deploy
1. Run `schema.sql` in the Supabase SQL Editor.
2. In Vercel, add the values from `.env.example` as Environment Variables.
3. Replace `PASTE_YOUR_SUPABASE_SERVICE_ROLE_KEY_HERE` with the project's **service role** key. Never put this key in browser JavaScript.
4. Deploy the whole folder as the project root.
5. Open `/void-console-7c2a.html`, enter the Developer password you specified, and generate user/developer keys.

The existing Habit Tracker Supabase sync remains separate from the new license tables.
