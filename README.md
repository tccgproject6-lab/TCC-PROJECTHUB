# GSMS Hub — GitHub → Netlify → Supabase

Mfumo huu umeandaliwa ili source code iwe GitHub, Netlify ijenge/deploy automatically, na Supabase ibaki database. Usihifadhi service-role key, JWT secret, au API secrets kwenye GitHub.

## 1. Supabase

Fungua Supabase SQL Editor na run `supabase/setup.sql` mara moja. Fanya backup kwanza kama una data muhimu.

SQL hii inaweka/kuongeza:
- `users`
- `saved_codes`
- `messages`
- `auth_user_id` UUID kwa kila user
- password hashing migration kwa login ya kwanza
- Row Level Security
- chat realtime publication
- admin/member permissions

Kama hakuna admin, setup huunda:
- Email: `admin@gsms.local`
- Reg No: `ADMIN/2026/001`
- Temporary password: `Admin@12345`

Badilisha password mara moja baada ya kuingia.

## 2. Netlify Environment Variables

Netlify → Site configuration → Environment variables → ongeza:

`SUPABASE_URL`

Thamani: URL ya Supabase project.

`SUPABASE_SERVICE_ROLE_KEY`

Thamani: Supabase server/service-role secret key. HII USIIWEKE KWENYE FILE YA GITHUB.

`SUPABASE_JWT_SECRET`

Thamani: JWT secret ya Supabase project. HII USIIWEKE KWENYE GITHUB.

Baada ya kuweka variables, redeploy site.

## 3. GitHub

Upload yaliyomo ndani ya folder hili moja kwa moja kwenye repository. Root ya repository iwe na `index.html`, `login.html`, `admin.html`, `css/`, `js/`, `netlify/`, `supabase/`, `netlify.toml` na `package.json`.

Usi-upload ZIP yenyewe kama root ya website.

## 4. Netlify

Link Netlify site na GitHub repository. Build settings zinaweza kuachwa zikitumia `netlify.toml`:

- Publish directory: `.`
- Functions directory: `netlify/functions`
- Node: 18+

Kila `git push` itasababisha Netlify deploy mpya.

## 5. Baada ya deploy

Fungua login page na tumia admin account iliyopo au account ya setup. Ukiona login inakataa, angalia kwanza Netlify Functions logs na environment variables.

## Security notes

- Supabase anon key iliyopo `js/config.js` ni public browser key; usiiweke service-role secret humo.
- Passwords hazitumwi moja kwa moja kutoka browser kwenda Supabase database; login na password change hupitia Netlify Functions.
- Database writes za users/admin actions zinapitia server function yenye service-role key.
- `saved_codes` na `messages` zinalindwa na RLS kwa `auth.uid()` kutoka custom short-lived JWT.
- Session token huhifadhiwa `sessionStorage`, si `localStorage`, na ina expiry ya saa 12.
- Chat message rendering hutumia `textContent` kuzuia HTML injection.

## Editing workflow

1. Edit file kwenye GitHub.
2. Commit changes.
3. Netlify ita-deploy automatically.
4. Supabase data haibadiliki isipokuwa umebadilisha SQL/database.

Kwa mabadiliko ya database, andika migration mpya ndani ya `supabase/` badala ya kufuta data bila backup.
