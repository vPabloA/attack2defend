// Attack2Defend Neo4j query pack

// 1) Full CVE defense route
MATCH p=(c:CVE {id:$cve_id})-[*1..8]->(n:KnowledgeNode)
WHERE n.type IN ['cwe','capec','attack','d3fend','control','detection','evidence','gap','action']
RETURN p LIMIT 50;

// 2) Orphan nodes
MATCH (n:KnowledgeNode)
WHERE NOT (n)--()
RETURN n.id, n.type, n.name LIMIT 100;

// 3) Weak / unknown confidence edges
MATCH (s:KnowledgeNode)-[r]->(t:KnowledgeNode)
WHERE coalesce(r.confidence,'') IN ['', 'low', 'unknown']
RETURN s.id, type(r), t.id, r.confidence, r.source_ref LIMIT 100;

// 4) Missing provenance
MATCH (s:KnowledgeNode)-[r]->(t:KnowledgeNode)
WHERE coalesce(r.source_ref,'') = '' AND coalesce(r.source_feed,'') = ''
RETURN s.id, type(r), t.id, r.confidence LIMIT 100;

// 5) ATT&CK techniques missing defensive path
MATCH (a:ATTACK)
WHERE NOT (a)-[*1..4]->(:D3FEND) AND NOT (a)-[*1..4]->(:Control) AND NOT (a)-[*1..4]->(:Detection)
RETURN a.id, a.name LIMIT 100;

// 6) Detections missing evidence
MATCH (d:Detection)
WHERE NOT (d)-[*1..3]->(:Evidence)
RETURN d.id, d.name LIMIT 100;

// 7) Top gaps by inbound paths
MATCH (n:KnowledgeNode)-[r]->(g:Gap)
RETURN g.id, g.name, count(r) AS inbound_paths
ORDER BY inbound_paths DESC LIMIT 25;

// 8) AI promoted edges
MATCH (s:KnowledgeNode)-[r]->(t:KnowledgeNode)
WHERE r.source_feed IN ['ai_promoted','ai_candidate'] OR r.source_kind IN ['ai_promoted','ai_candidate']
RETURN s.id, type(r), t.id, r.confidence, r.source_ref LIMIT 100;

// 9) Coverage by framework
MATCH (n:KnowledgeNode)
RETURN n.type AS type, count(n) AS nodes
ORDER BY nodes DESC;

// 10) Route quality summary from CVEs
MATCH (c:CVE)
OPTIONAL MATCH (c)-[*1..8]->(d:Detection)
OPTIONAL MATCH (c)-[*1..8]->(e:Evidence)
OPTIONAL MATCH (c)-[*1..8]->(g:Gap)
RETURN c.id, count(DISTINCT d) AS detections, count(DISTINCT e) AS evidence, count(DISTINCT g) AS gaps
ORDER BY detections DESC, evidence DESC;
