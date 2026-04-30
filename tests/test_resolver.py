from attack2defend import KnowledgeEdge, KnowledgeNode, NodeType, RouteRequest, RouteResolver, infer_node_type


def test_infer_node_type():
    assert infer_node_type("CVE-2021-44228") == NodeType.CVE
    assert infer_node_type("CWE-917") == NodeType.CWE
    assert infer_node_type("CAPEC-136") == NodeType.CAPEC
    assert infer_node_type("T1190") == NodeType.ATTACK
    assert infer_node_type("D3-NTA") == NodeType.D3FEND
    assert infer_node_type("unknown") is None


def test_resolve_simple_route():
    nodes = [
        KnowledgeNode(id="CVE-2021-44228", type=NodeType.CVE, name="Log4Shell"),
        KnowledgeNode(id="CWE-917", type=NodeType.CWE, name="Expression Language Injection"),
        KnowledgeNode(id="CAPEC-136", type=NodeType.CAPEC, name="LDAP Injection"),
        KnowledgeNode(id="T1190", type=NodeType.ATTACK, name="Exploit Public-Facing Application"),
        KnowledgeNode(id="D3-NTA", type=NodeType.D3FEND, name="Network Traffic Analysis"),
    ]
    edges = [
        KnowledgeEdge(source="CVE-2021-44228", target="CWE-917", relationship="has_weakness"),
        KnowledgeEdge(source="CWE-917", target="CAPEC-136", relationship="may_enable_attack_pattern"),
        KnowledgeEdge(source="CAPEC-136", target="T1190", relationship="may_map_to_attack_technique"),
        KnowledgeEdge(source="T1190", target="D3-NTA", relationship="may_be_detected_by"),
    ]

    resolver = RouteResolver(nodes, edges)
    result = resolver.resolve(RouteRequest(input_id="CVE-2021-44228"))

    assert result.found is True
    assert "CVE-2021-44228" in result.ordered_path
    assert "D3-NTA" in result.ordered_path
    assert len(result.nodes) == 5
    assert len(result.edges) == 4


def test_missing_input_returns_warning():
    resolver = RouteResolver(nodes=[], edges=[])
    result = resolver.resolve(RouteRequest(input_id="CVE-2099-0000"))

    assert result.found is False
    assert result.warnings
