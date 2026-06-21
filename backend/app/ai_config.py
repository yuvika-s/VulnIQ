"""
VulnIQ — AI configuration.

Single source of truth for which model VulnIQ uses and which agentic roles
that model plays. Documented here so it's obvious to anyone reading the code,
the README, or the dashboard.

ARCHITECTURE: ONE model, FOUR agentic roles.

Why one model and not multi-model?
  - Claude is strong enough alone for all four jobs in this pipeline.
  - Multi-model adds integration cost, key management, latency, and failure
    surface for no measurable quality gain on these specific tasks.
  - Choosing the most efficient apt method = one strong model, four well-scoped
    agentic roles, each with its own system prompt + tool surface.
"""
import logging
import os
import ssl

_log = logging.getLogger("vulniq.tls")

# Capture the real stdlib SSLContext class NOW, before configure_tls() may call
# truststore.inject_into_ssl() (which swaps ssl.SSLContext for its own class and
# verifies against the OS trust store even when a client asks for verify=False).
# An on-prem Tenable.sc presents a self-signed cert that the OS store does NOT
# trust, so its connector needs a genuinely-unverified context that truststore
# can't re-verify — this captured class is how we build one.
_STDLIB_SSLCONTEXT = ssl.SSLContext


def insecure_ssl_context() -> "ssl.SSLContext":
    """A real (non-truststore) SSL context with verification disabled. Used only
    for explicitly-opted-in self-signed internal endpoints (e.g. on-prem
    Tenable.sc with TENABLE_VERIFY_SSL=false). Never used for outbound internet
    calls (LLM gateway, Snyk) which keep full verification via truststore.

    truststore.inject_into_ssl() rebinds the module-global ``ssl.SSLContext``,
    which makes the stdlib ``verify_mode`` setter recurse infinitely. So we build
    the context with truststore momentarily extracted, then restore it — the
    finished context is a plain stdlib object the corporate store can't re-verify.
    """
    truststore = None
    try:
        import truststore as _ts
        truststore = _ts
        truststore.extract_from_ssl()
    except Exception:
        truststore = None
    try:
        ctx = _STDLIB_SSLCONTEXT(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    finally:
        if truststore is not None:
            try:
                truststore.inject_into_ssl()
            except Exception:
                pass


# Raw values parsed from backend/.env (and project-root .env), captured even when
# a same-named variable already exists in the environment. The LLM gateway config
# is read from HERE preferentially so a polluting shell export (e.g. a CI/agent
# that sets ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY for its own use) can't silently
# redirect VulnIQ's copilot away from the configured corporate gateway.
_DOTENV: dict[str, str] = {}


def _load_dotenv():
    """Minimal .env loader (no extra dependency). Loads backend/.env then the
    project root .env if present, without overriding vars already in the
    environment (shell exports win) — EXCEPT the parsed values are also retained
    in _DOTENV so the LLM gateway config can treat the .env file as authoritative.
    Keeps secrets like SNYK_API_TOKEN out of code and out of git."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/
    for path in (os.path.join(here, ".env"), os.path.join(here, "..", ".env")):
        if not os.path.exists(path):
            continue
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip().strip('"').strip("'")
                    if not k:
                        continue
                    _DOTENV.setdefault(k, v)          # first file wins; retained always
                    if k not in os.environ:
                        os.environ[k] = v
        except Exception as e:  # never let env loading break startup
            _log.warning("could not read %s: %s", path, e)


def _gateway_base_url() -> str:
    """LLM gateway base URL — .env file is authoritative over a polluting env."""
    return (_DOTENV.get("ANTHROPIC_BASE_URL") or os.environ.get("ANTHROPIC_BASE_URL") or "").strip()


def _gateway_auth_token() -> str:
    """LLM gateway bearer token — .env file is authoritative over a polluting env."""
    return (_DOTENV.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_AUTH_TOKEN") or "").strip()


def _load_db_secret():
    """Build DATABASE_URL from AWS Secrets Manager when deployed on AWS.

    If DATABASE_URL is already set (local dev), do nothing. Otherwise, when
    DB_SECRET_ARN is provided, fetch {username,password} from Secrets Manager and
    assemble the RDS URL using DB_HOST / DB_PORT / DB_NAME. The app only READS the
    secret (secretsmanager:GetSecretValue) — it never writes it.
    """
    if os.environ.get("DATABASE_URL"):
        return
    arn = os.environ.get("DB_SECRET_ARN", "").strip()
    host = os.environ.get("DB_HOST", "").strip()
    if not arn or not host:
        return
    try:
        import json
        import boto3
        from urllib.parse import quote_plus
        region = (os.environ.get("AWS_REGION") or os.environ.get("DB_SECRET_REGION")
                  or (arn.split(":")[3] if arn.count(":") >= 4 else "ap-south-1"))
        sm = boto3.client("secretsmanager", region_name=region)
        sec = json.loads(sm.get_secret_value(SecretId=arn)["SecretString"])
        user, pw = sec.get("username"), sec.get("password")
        port = os.environ.get("DB_PORT", "5432")
        name = os.environ.get("DB_NAME", "vulniq")
        if user and pw:
            os.environ["DATABASE_URL"] = (
                f"postgresql+psycopg2://{quote_plus(user)}:{quote_plus(pw)}@{host}:{port}/{name}")
            _log.info("db: DATABASE_URL assembled from Secrets Manager (host=%s db=%s)", host, name)
    except Exception as e:
        _log.warning("db: could not load DB secret from Secrets Manager (%s)", e)


_load_dotenv()
_load_db_secret()

# --- Snyk Enterprise integration ------------------------------------------- #
SNYK_API_TOKEN = os.environ.get("SNYK_API_TOKEN", "")
SNYK_ORG_ID = os.environ.get("SNYK_ORG_ID", "")
SNYK_REGION_BASE = os.environ.get("SNYK_REGION_BASE", "https://api.us.snyk.io/rest")
SNYK_API_VERSION = os.environ.get("SNYK_API_VERSION", "2024-10-15")
SNYK_LOOKBACK_DAYS = int(os.environ.get("SNYK_LOOKBACK_DAYS", "30"))
# Severity floor applied server-side. Large orgs emit tens of thousands of
# low/medium dependency findings in 30 days; default to the high-signal set.
# Set to "all" (or empty) to ingest every severity.
# Severity filter for the NOISY product only (Open Source + Container, which can
# be tens of thousands of dependency CVEs). Code / IaC / Secrets are capability-
# rich at any severity (a hardcoded key is "medium" CVSS but creates a real
# handoff), so they are NOT severity-filtered.
SNYK_SEVERITY = os.environ.get("SNYK_SEVERITY", "critical,high")
# Per-product fetch cap (severity-first ordering keeps the most important).
# Guarantees Code / IaC get representation instead of being crowded out by the
# dependency-CVE flood.
SNYK_MAX_PER_PRODUCT = int(os.environ.get("SNYK_MAX_PER_PRODUCT", "1500"))
# IaC scans run infrequently, so a 30-day `updated_after` window misses almost
# all of them (org had 1793 open IaC findings but only 2 touched in 30 days).
# Open IaC misconfigs are still "active", so use a much wider window for IaC.
SNYK_IAC_LOOKBACK_DAYS = int(os.environ.get("SNYK_IAC_LOOKBACK_DAYS", "365"))
# Overall safety ceiling across all products. 0 = no overall cap.
SNYK_MAX_FINDINGS = int(os.environ.get("SNYK_MAX_FINDINGS", "6000"))
SNYK_SCHEDULED_SYNC = str(os.environ.get("SNYK_SCHEDULED_SYNC", "")).strip().lower() in ("1", "true", "yes", "on")
SNYK_SYNC_INTERVAL_HOURS = float(os.environ.get("SNYK_SYNC_INTERVAL_HOURS", "24"))


def snyk_configured() -> bool:
    return bool(SNYK_API_TOKEN and SNYK_ORG_ID)


# --- Tenable Security Center (Tenable.sc) integration ---------------------- #
# Tenable is just another finding *source*: its records normalize into the same
# unified Finding schema and flow through the same graph -> chain -> prioritize
# pipeline as Snyk and manual uploads. On-prem SC almost always presents a
# self-signed cert, so TLS verification defaults OFF (override per-deployment).
TENABLE_BASE_URL = os.environ.get("TENABLE_BASE_URL", "").rstrip("/")
TENABLE_ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
TENABLE_SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")
def _env_truthy(name: str, default: str = "") -> bool:
    return str(os.environ.get(name, default)).strip().lower() in ("1", "true", "yes", "on")

TENABLE_VERIFY_SSL = _env_truthy("TENABLE_VERIFY_SSL", "false")
# Severity floor (Tenable ids: 0=Info 1=Low 2=Medium 3=High 4=Critical).
# Default includes MEDIUM: VulnIQ's value is attack-path chaining, and a Medium
# finding is often the pivot that completes a chain. The connector pulls a
# per-severity QUOTA (not Critical-first-until-full), so Medium chain-enablers are
# always represented even on an SC with tens of thousands of High/Critical rows.
# "all" ingests every severity; drop "medium" to go back to high-signal only.
TENABLE_SEVERITY = os.environ.get("TENABLE_SEVERITY", "critical,high,medium")
# Cap how many host findings a single sync pulls (Critical first, then High).
# Bounds graph size the same way SNYK_MAX_PER_PRODUCT does for Snyk.
TENABLE_MAX_FINDINGS = int(os.environ.get("TENABLE_MAX_FINDINGS", "1500"))
TENABLE_LOOKBACK_DAYS = int(os.environ.get("TENABLE_LOOKBACK_DAYS", "0"))  # 0 = no time filter (cumulative)
TENABLE_SCHEDULED_SYNC = _env_truthy("TENABLE_SCHEDULED_SYNC", "")
TENABLE_SYNC_INTERVAL_HOURS = float(os.environ.get("TENABLE_SYNC_INTERVAL_HOURS", "24"))


def tenable_configured() -> bool:
    return bool(TENABLE_BASE_URL and TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY)

# The model used by every Claude call in VulnIQ.
MODEL = "claude-opus-4-8"

# Agentic roles. Each one is a real Claude call with its own system prompt and
# its own scope. They are deliberately separated so failures or fallbacks in one
# role don't cascade.
ROLES = {
    "extraction_normalization": {
        "file": "app/ingestion/extraction_agent.py",
        "purpose": ("THE most crucial agent. Reads raw findings uploaded in any "
                    "format (JSON, XML, CSV, XLSX, PDF) and any documentation "
                    "style, and deeply understands each one to map it into the "
                    "unified Finding schema. Infers OSI layer, finding type, and "
                    "the attacker capabilities each finding grants (the basis for "
                    "all chaining). Fills missing fields by reasoning, assigns an "
                    "extraction-confidence, and flags low-confidence items for "
                    "human review."),
        "agentic": "deep-reading extraction + schema mapping + confidence",
    },
    "edge_inference": {
        "file": "app/graph/edge_agent.py",
        "purpose": ("Semantic edge inference for the attack graph. For every "
                    "candidate finding-pair (A -> B) flagged by the deterministic "
                    "pass, decides whether A's granted capability plausibly "
                    "ENABLES exploitation of B, with confidence 0-1 and a "
                    "one-sentence rationale. Batched 12 pairs/call, cached "
                    "by pair-hash. This is the 'correlation brain' of VulnIQ."),
        "agentic": "batched semantic classification + rationale",
    },
    "chain_narrator": {
        "file": "app/agent/chain_narrator.py",
        "purpose": ("Per-chain breach-story generation. Given the structured "
                    "finding sequence and asset path of an attack chain, "
                    "writes a 2-3 sentence narrative from the perspective of "
                    "a senior offensive-security analyst. Result is what the "
                    "dashboard shows under each chain."),
        "agentic": "structured prompt -> natural language",
    },
    "dashboard_copilot": {
        "file": "app/agent/dashboard_agent.py",
        "purpose": ("Conversational copilot embedded in the dashboard. Full "
                    "tool-calling agent with 6 tools: get_top_chains, "
                    "query_findings, get_stats, get_asset_risk, best_single_fix, "
                    "and simulate_patch (action). Bounded loop up to 6 tool "
                    "calls per question. This is the user-facing AI surface."),
        "agentic": "true ReAct-style tool-calling loop",
    },
}


# --- Network safety knobs -------------------------------------------------- #
# Every Claude call goes through make_client() so timeouts and retry limits are
# enforced in ONE place. Without these, a slow or rate-limited request can hang
# the request handler for minutes (the anthropic SDK defaults to a 10-minute
# timeout), which is exactly what made uploads appear "stuck with no response".
LLM_TIMEOUT_SECONDS = float(os.environ.get("VULNIQ_LLM_TIMEOUT", "60"))
LLM_MAX_RETRIES = int(os.environ.get("VULNIQ_LLM_MAX_RETRIES", "2"))

# Cap how many records a single upload sends to the extraction LLM. A file that
# is small on disk can still hold hundreds of findings; without a cap each one
# fans out into sequential LLM calls (records/6 per batch), which is the usual
# cause of an upload that "hangs" while quietly draining tokens. Extra records
# are reported in the response so nothing is silently dropped (0/neg = no cap).
MAX_UPLOAD_RECORDS = int(os.environ.get("VULNIQ_MAX_UPLOAD_RECORDS", "1000"))

# Cap how many LLM batches a single upload's edge re-inference may fire. Beyond
# this, new candidate pairs fall back to the deterministic heuristic. This stops
# one upload from fanning out LLM calls across the whole graph and draining the
# token budget (set to 0 or a negative number to disable the cap). Raised so the
# LLM actually judges the (capped) candidate set for real cross-app chains
# rather than overflowing to the heuristic — 25 batches x 12 = 300 pairs.
UPLOAD_MAX_EDGE_BATCHES = int(os.environ.get("VULNIQ_UPLOAD_MAX_EDGE_BATCHES", "25"))

# Cap how many ENABLES candidate pairs the graph builder emits. Cross-app attack
# reachability can generate many capability-handoff pairs; we keep the highest-
# signal ones (edges into crown jewels, from internet-facing entries, higher
# severity) so the LLM can judge essentially all of them. 0 = no cap.
MAX_ENABLE_CANDIDATES = int(os.environ.get("VULNIQ_MAX_ENABLE_CANDIDATES", "300"))

# Chains whose evidence-validated confidence is below this (0-100) are marked
# "speculative" and are NOT allowed to materially escalate a finding's priority.
# Reduces false-positive attack paths built on assumed (unverified) hops.
CHAIN_CONFIDENCE_MIN = float(os.environ.get("VULNIQ_CHAIN_CONFIDENCE_MIN", "50"))


# --- TLS / corporate proxy (Zscaler etc.) --------------------------------- #
# Behind an HTTPS-inspecting proxy like Zscaler, the cert presented for
# api.anthropic.com is re-signed by the proxy's corporate root. The OS trust
# store (macOS keychain) trusts that root because IT installed it system-wide —
# which is why curl/browsers work — but Python's bundled `certifi` does not, so
# every Claude call fails with CERTIFICATE_VERIFY_FAILED. The fix is to verify
# against the OS trust store instead of certifi. `truststore` does exactly that.
def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")

INSECURE_SSL = _truthy(os.environ.get("VULNIQ_INSECURE_SSL", ""))
# Honour an explicit corporate CA bundle if the user points us at one. We also
# read the conventional SSL_CERT_FILE / REQUESTS_CA_BUNDLE vars.
CA_BUNDLE = (os.environ.get("VULNIQ_CA_BUNDLE")
             or os.environ.get("SSL_CERT_FILE")
             or os.environ.get("REQUESTS_CA_BUNDLE") or "")

_tls_configured = False


def configure_tls() -> str:
    """Make Python trust the OS / corporate trust store. Call once at startup.

    Returns a short status string (also logged) describing what was applied.
    Safe to call multiple times.
    """
    global _tls_configured
    if _tls_configured:
        return "already configured"
    _tls_configured = True

    if INSECURE_SSL:
        msg = ("VULNIQ_INSECURE_SSL set — TLS certificate verification DISABLED. "
               "Use only for local debugging, never in production.")
        _log.warning(msg)
        return "insecure (verification disabled)"

    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        _log.info("TLS: verifying against explicit CA bundle %s", CA_BUNDLE)
        return f"explicit CA bundle: {CA_BUNDLE}"

    # Preferred path: delegate verification to the OS trust store, which already
    # trusts the Zscaler (or any corporate) root that IT pushed to the machine.
    try:
        import truststore
        truststore.inject_into_ssl()
        _log.info("TLS: using the OS system trust store (truststore) — corporate "
                  "roots such as Zscaler are now trusted by Python.")
        return "os trust store (truststore)"
    except Exception as e:  # truststore missing or failed to inject
        _log.warning("TLS: could not enable the OS trust store (%s); falling back "
                     "to certifi. If you are behind an HTTPS-inspecting proxy "
                     "(Zscaler), `pip install truststore` or set VULNIQ_CA_BUNDLE "
                     "to your corporate root PEM.", e)
        return "certifi (default)"


def _http_client():
    """Return a custom httpx.Client only when we need non-default TLS (insecure
    mode or an explicit CA bundle). Otherwise None, so the Anthropic SDK builds
    its own client — which, after configure_tls(), already trusts the OS store."""
    try:
        import httpx
    except ImportError:
        return None
    if INSECURE_SSL:
        return httpx.Client(verify=False, timeout=LLM_TIMEOUT_SECONDS)
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        return httpx.Client(verify=CA_BUNDLE, timeout=LLM_TIMEOUT_SECONDS)
    return None


def has_credentials() -> bool:
    """True when *some* Anthropic credential is configured.

    Prefers the gateway bearer token from the .env file (the configured corporate
    LLM-inference platform), then any ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY in
    the environment.
    """
    return bool(_gateway_auth_token()
                or os.environ.get("ANTHROPIC_AUTH_TOKEN")
                or os.environ.get("ANTHROPIC_API_KEY"))


def make_client():
    """Construct an Anthropic client with bounded timeout + retries, or None.

    Returns None when the SDK is missing or no credential is set, so callers can
    cleanly fall back to their deterministic path. TLS is configured to trust
    the corporate/OS trust store so this works behind Zscaler-style proxies.

    Gateway auth: the corporate LLM-inference gateway authenticates with
    ``Authorization: Bearer <token>``. We therefore (a) pin the base URL + bearer
    token to the .env-configured gateway and (b) ensure NO ``x-api-key`` header is
    sent — a stray ANTHROPIC_API_KEY in the environment would otherwise make the
    SDK attach BOTH headers, which the gateway rejects with 401. The base URL /
    token are taken from the .env FILE so a polluting shell export can't redirect
    the copilot to a different endpoint.
    """
    try:
        import anthropic
    except ImportError:
        return None
    if not has_credentials():
        return None
    configure_tls()
    kwargs = dict(timeout=LLM_TIMEOUT_SECONDS, max_retries=LLM_MAX_RETRIES)
    base = _gateway_base_url()
    if base:
        kwargs["base_url"] = base
    hc = _http_client()
    if hc is not None:
        kwargs["http_client"] = hc

    token = _gateway_auth_token()
    if token:
        # Bearer-only: build with auth_token and temporarily remove any
        # ANTHROPIC_API_KEY so the SDK doesn't also send x-api-key. (The SDK reads
        # api_key from the env at construction; popping it for the duration yields
        # a client whose only auth header is Authorization: Bearer.)
        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            return anthropic.Anthropic(auth_token=token, **kwargs)
        finally:
            if saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = saved
    return anthropic.Anthropic(**kwargs)


def llm_enabled() -> bool:
    """LLM mode is on when the SDK is installed AND an API key is configured."""
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return has_credentials()


def status() -> dict:
    """Returned by /api/ai-status. Lets the UI display the AI footprint."""
    return {
        "model": MODEL,
        "llm_enabled": llm_enabled(),
        "mode": "live" if llm_enabled() else "offline_fallback",
        "roles": [
            {"name": k, "purpose": v["purpose"].split(".")[0] + ".",
             "agentic_pattern": v["agentic"]}
            for k, v in ROLES.items()
        ],
        "note": (f"VulnIQ uses a single model ({MODEL}) in four "
                 "distinct agentic roles. Each role has a deterministic fallback "
                 "so the pipeline runs end-to-end even when no API key is set, "
                 "but with the API key present, every chain narrative is "
                 "LLM-generated, every semantic edge is LLM-judged, and every "
                 "dashboard question is answered by a real tool-calling agent."),
    }
