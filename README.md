# S.Honed

**Simple name:** Honed

Drop a website or repo, get a polish report.

This is a Grok App Builder project. The sandbox npm name was `app-builder-workspace`. On GitHub it is **S.Honed** (private).

## Run on this Mac

Need **Node.js 22** and **npm**. Postgres is not required (uses PGLite in the browser/process).

```bash
cd "/Users/akshitpareta/Documents/S-projects/S.Honed"
npm install
npm run dev
```

Open http://127.0.0.1:8080

To skip Grok login in local preview:

```bash
VITE_AUTH_ENABLED=false npm run dev
```

Optional AI (only if this app calls Grok): set `XAI_API_KEY`.

## Scripts

- `npm run dev` — Vite on port 8080
- `npm run build` — production build + DB migrate (skipped without DATABASE_URL)
- `npm run typecheck`

## Notes

Do not commit `.env`, `node_modules`, or `.grok/`.
