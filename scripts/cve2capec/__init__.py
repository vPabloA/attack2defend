"""CVE2CAPEC-style pipeline entrypoints.

Each script in this package mirrors the file names from
https://github.com/Galeax/CVE2CAPEC. They all delegate to the Attack2Defend
canonical exporter so the resulting layout is identical:

* database/CVE-YYYY.jsonl
* resources/{cwe_db,capec_db,techniques_db,techniques_association}.json
* resources/defend_db.jsonl
* results/new_cves.jsonl
* lastUpdate.txt

Running any of the scripts produces the full canonical export. Calling them in
the published order remains supported for users following the original
documentation.
"""
