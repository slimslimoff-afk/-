# PENYLI v10.0 — Render deployment

## Fastest path
1. Put this folder in a GitHub repository.
2. Open Render and choose **New → Blueprint**.
3. Select the repository.
4. Render reads `render.yaml`.
5. Set these environment variables in Render:
   - `PENYLI_ALLOWED_ORIGINS=https://YOUR_RENDER_HOST`
   - `STRIPE_SECRET_KEY=...` (use Stripe test key first)
   - `STRIPE_WEBHOOK_SECRET=...` (create after the service URL exists)
   - `BASE_URL=https://YOUR_RENDER_HOST`
6. Deploy.
7. Open `/health`.
8. Open `/api/mvp/status`.
9. Open `/api/mvp/readiness`.

## First deployment
Use Stripe TEST keys. Do not put live keys in the repository.

## Important database warning
The current v10.0 persistence is SQLite. Render's free web service filesystem
is not durable production storage. Use this deployment for functional testing
only. PostgreSQL migration is required before a real public launch.

## Signing key
The app can generate the Ed25519 key on first start, but an ephemeral filesystem
can lose it on redeploy. For production, provision the key as a protected secret
or persistent secure store and keep the same key across deployments.
