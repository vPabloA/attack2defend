from attack2defend.capability import resolve_defense_route


BUNDLE = "data/knowledge-bundle.json"
THREAT_TYPES = {"cve", "cwe", "capec", "attack", "d3fend"}
DEFENSE_TYPES = {"control", "detection", "evidence", "gap", "action"}


def test_resolver_returns_separated_two_map_response():
    result = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)

    assert result["threat_route_map"]["nodes"]
    assert result["defense_readiness_map"]["controls"]
    assert result["defense_readiness_map"]["detections"]
    assert result["defense_readiness_map"]["evidence"]
    assert result["defense_readiness_map"]["gaps"]
    assert result["defense_readiness_map"]["actions"]
    assert {node["type"] for node in result["threat_route_map"]["nodes"]} <= THREAT_TYPES
    defense_nodes = (
        result["defense_readiness_map"]["controls"]
        + result["defense_readiness_map"]["detections"]
        + result["defense_readiness_map"]["evidence"]
        + result["defense_readiness_map"]["gaps"]
        + result["defense_readiness_map"]["actions"]
    )
    assert {node["type"] for node in defense_nodes} <= DEFENSE_TYPES


def test_bridges_and_official_links_are_explicit():
    result = resolve_defense_route({"input": "CVE-2024-37079"}, bundle_path=BUNDLE)
    bridge_pairs = {(bridge["source"], bridge["target"], bridge["relationship"]) for bridge in result["bridges"]}
    links = {link["node_id"]: link["url"] for link in result["official_links"]}

    assert ("D3-NTA", "CTRL-VIRTUAL-PATCH", "implemented_by_control") in bridge_pairs
    assert ("CTRL-VIRTUAL-PATCH", "DET-RPC-EXPLOIT-ATTEMPT", "validated_by_detection") in bridge_pairs
    assert ("DET-RPC-EXPLOIT-ATTEMPT", "EV-FIREWALL-LOGS", "requires_evidence") in bridge_pairs
    assert links["CVE-2024-37079"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-37079"
    assert links["CWE-787"] == "https://cwe.mitre.org/data/definitions/787.html"
    assert links["CAPEC-100"] == "https://capec.mitre.org/data/definitions/100.html"
    assert links["T1190"] == "https://attack.mitre.org/techniques/T1190/"
    assert links["D3-NTA"] == "https://d3fend.mitre.org/technique/D3-NTA/"


def test_unresolved_input_does_not_invent_nodes():
    result = resolve_defense_route({"input": "CVE-2099-0000"}, bundle_path=BUNDLE)

    assert result["coverage_status"] == "unresolved"
    assert result["threat_route_map"]["nodes"] == []
    assert result["defense_readiness_map"]["controls"] == []
    assert result["defense_readiness_map"]["actions"] == []
    assert result["bridges"] == []


def test_capability_resolver_does_not_import_ai_stack():
    source = open("src/attack2defend/capability/resolver.py", encoding="utf-8").read()

    assert "langchain" not in source.lower()
    assert "langgraph" not in source.lower()
    assert "openai" not in source.lower()
