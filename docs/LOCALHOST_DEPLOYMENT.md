# Localhost Deployment

## Full local bootstrap

```bash
git clone https://github.com/vPabloA/attack2defend.git
cd attack2defend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make bootstrap-local-full
make test
make ui
```

Open the Vite URL, usually `http://localhost:5173`.

## Refresh public sources

```bash
A2D_REFRESH_PUBLIC_SOURCES=1 make bootstrap-local-full
```

## Optional NVD enrichment

```bash
export NVD_API_KEY="<optional>"
make bootstrap-local-full
```

## Runtime rule

The UI only loads `/data/knowledge-bundle.json`. Public APIs are builder-time only.
