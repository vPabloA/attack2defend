// Import with: cypher-shell -f schema.cypher && cypher-shell -f import.cypher
LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
MERGE (n:KnowledgeNode {id: row.id})
SET n.type = row.type,
    n.label = row.label,
    n.name = row.name,
    n.description = row.description,
    n.url = row.url,
    n.source_ref = row.source_ref,
    n.source_feed = row.source_feed,
    n.metadata_json = row.metadata_json
FOREACH (_ IN CASE row.label WHEN 'CVE' THEN [1] ELSE [] END | SET n:CVE)
FOREACH (_ IN CASE row.label WHEN 'CWE' THEN [1] ELSE [] END | SET n:CWE)
FOREACH (_ IN CASE row.label WHEN 'CAPEC' THEN [1] ELSE [] END | SET n:CAPEC)
FOREACH (_ IN CASE row.label WHEN 'ATTACK' THEN [1] ELSE [] END | SET n:ATTACK)
FOREACH (_ IN CASE row.label WHEN 'D3FEND' THEN [1] ELSE [] END | SET n:D3FEND)
FOREACH (_ IN CASE row.label WHEN 'Control' THEN [1] ELSE [] END | SET n:Control)
FOREACH (_ IN CASE row.label WHEN 'Detection' THEN [1] ELSE [] END | SET n:Detection)
FOREACH (_ IN CASE row.label WHEN 'Evidence' THEN [1] ELSE [] END | SET n:Evidence)
FOREACH (_ IN CASE row.label WHEN 'Gap' THEN [1] ELSE [] END | SET n:Gap)
FOREACH (_ IN CASE row.label WHEN 'Action' THEN [1] ELSE [] END | SET n:Action);

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
MATCH (s:KnowledgeNode {id: row.source})
MATCH (t:KnowledgeNode {id: row.target})
CALL apoc.merge.relationship(s, row.relationship_type, {}, {
  relationship: row.relationship,
  confidence: row.confidence,
  source_ref: row.source_ref,
  source_feed: row.source_feed,
  source_kind: row.source_kind,
  deterministic: row.deterministic,
  inferred: row.inferred,
  retrieved_at: row.retrieved_at,
  transform_version: row.transform_version,
  metadata_json: row.metadata_json
}, t) YIELD rel
RETURN count(rel) AS imported_relationships;
