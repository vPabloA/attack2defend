"""API contract constants for Attack2Defend automation."""

API_ENDPOINTS = [
    "GET /api/v1/health",
    "GET /api/v1/metadata",
    "GET /api/v1/route/{id}",
    "POST /api/v1/route/batch",
    "GET /api/v1/soc-pack/{id}",
    "GET /api/v1/d3fend/{id}/soc-actions",
    "GET /api/v1/factory/status",
    "GET /api/v1/factory/candidates",
    "GET /api/v1/policy",
    "GET /api/v1/golden/evaluation",
    "GET /api/v1/graph/quality",
    "GET /api/v1/search?q=",
    "GET /api/v1/evidence-pack/{id}",
]
