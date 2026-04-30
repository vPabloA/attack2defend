# Navigator UI (MVP placeholder)

This path currently hosts static runtime data for the Navigator UI bundle:

- `public/data/knowledge-bundle.json`

The web UI source (`package.json`, Vite app, TypeScript components) is **not present in this repository snapshot/branch**.

## Expected behavior for this repository state

- Knowledge builder publishes `app/navigator-ui/public/data/knowledge-bundle.json`.
- Tests validate that bundle generation completes and that routes/edges are coherent.

## When the full UI source is restored

Run:

```bash
cd app/navigator-ui
npm install
npm run build
npm run dev
```

The UI should load `/data/knowledge-bundle.json` first and use local fallback data only when that file is missing.
