"""Persistence layer. Active only when DATABASE_URL is set; otherwise VulnIQ
runs exactly as before (in-memory engine seeded from JSON files)."""
