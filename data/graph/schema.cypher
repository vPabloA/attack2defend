// Attack2Defend Graph Sidecar schema
CREATE CONSTRAINT a2d_node_id IF NOT EXISTS FOR (n:KnowledgeNode) REQUIRE n.id IS UNIQUE;
CREATE INDEX a2d_node_type IF NOT EXISTS FOR (n:KnowledgeNode) ON (n.type);
CREATE INDEX a2d_node_label IF NOT EXISTS FOR (n:KnowledgeNode) ON (n.label);
CREATE INDEX a2d_edge_confidence IF NOT EXISTS FOR ()-[r]-() ON (r.confidence);
CREATE INDEX a2d_edge_source_feed IF NOT EXISTS FOR ()-[r]-() ON (r.source_feed);
