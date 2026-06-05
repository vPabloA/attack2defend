"""Official source resolvers for NVD, CWE, CAPEC, ATT&CK STIX, D3FEND, and vendor advisories.

All resolvers operate at CLI/build time only. The browser never imports these modules.
Results are cached to data/source-cache/ to avoid redundant API calls.
"""
