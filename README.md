# ShipzyCart FTL Dashboard

Single-file React app for Shipzy Logistics FTL operations — bookings, LRs,
multi-invoice e-way bills (full API lifecycle via WhiteBooks GSP), LTL rate
quoting, freight calculator with lane history & vendor route sharing,
billing, PWA/Android support.

Live: https://shipzycart-ftl.web.app

## How it works
- `src/shipzy_dashboard.jsx` — the entire app (source of truth)
- `src/template.html` — HTML shell (React UMD, fonts, PWA head); app code
  is injected at the `/*__APP_CODE__*/` marker
- `build/build.py` — strips module syntax, pre-compiles JSX with Babel,
  injects into the template → `dist/public/index.html`
- `public-extra/` — PWA manifest, icons, service worker, assetlinks

## Deploys
Every push to `main` triggers `.github/workflows/deploy.yml`:
build → deploy to Firebase Hosting (project `shipzycart-ftl`).
Requires repo secret `FIREBASE_SERVICE_ACCOUNT` (see below).

## Local build
```
cd build && npm install && cd ..
python3 build/build.py
firebase deploy --only hosting
```

## Backend (separate Firebase project: shipzy-vendor)
`backend/ewb-functions/` — e-way bill API proxies (details / actions /
GSTIN verify). Deployed manually:
```
cd backend/ewb-functions
cp .env.example .env   # fill real credentials
npm install
firebase deploy --only functions --project shipzy-vendor
```

## Version history
The in-app CHANGELOG (top of `src/shipzy_dashboard.jsx`) documents every
build since v1. Git history takes over from v65.
