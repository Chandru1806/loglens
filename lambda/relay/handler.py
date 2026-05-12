# Lambda relay handler
"""
LogLens — EPCL API Log Ingestion Lambda  (OPTIMIZED)
======================================================
Endpoint 1: Relay Lambda
- Fetches API logs from Endpoint 2 (Kibana / live log source)
- Randomises PII fields in request/response bodies
- Stores sanitised logs in PostgreSQL (RDS)

Optimizations applied:
  [OPT-01] Module-level DB connection reuse (warm-invocation pooling)
  [OPT-02] DDL guard flag — ensure_table() runs only once per container
  [OPT-03] Avoid double JSON parse — _safe_jsonb skips re-validation for
           already-serialised output from randomise_log_entry()
  [OPT-04] execute_values() single multi-row INSERT replaces execute_batch()
  [OPT-05] Inline list literals hoisted to module-level tuples
  [OPT-06] Persistent requests.Session with urllib3 retry + backoff
  [OPT-07] PEP 8 naming: correlationId → _rand_correlation_id
  [OPT-08] Malformed JSON logged with warning before wrapping
  [OPT-09] Lazy PII generation — values created only when key present
  [OPT-10] Structured try/except in lambda_handler with error response
  [OPT-11] conn.close() removed; connection kept alive across warm invocations
  [OPT-12] Conflict skips tracked and logged via rowcount
  [OPT-13] _rand_uuid inlined as module-level lambda

Environment Variables:
    ENDPOINT2_URL      : Base URL of live log-source API (Endpoint 2)
    ENDPOINT2_API_KEY  : Bearer token / API key for Endpoint 2
    DB_HOST            : RDS PostgreSQL host
    DB_PORT            : RDS PostgreSQL port (default 5432)
    DB_NAME            : Database name
    DB_USER            : Database user
    DB_PASSWORD        : Database password
    BATCH_SIZE         : Number of logs to fetch per invocation (default 100)
    LOOKBACK_MINUTES   : How far back to look for new logs (default 6)
    ENDPOINT2_TIMEOUT_S: HTTP timeout in seconds (default 20)
"""

import json
import os
import random
import string
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
import psycopg2
import psycopg2.extras
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ══════════════════════════════════════════════════════════════════════════════
# [OPT-13] Module-level uuid lambda — eliminates unnecessary wrapper call frame
# ══════════════════════════════════════════════════════════════════════════════
_rand_uuid = lambda: str(uuid.uuid4())  # noqa: E731


# ══════════════════════════════════════════════════════════════════════════════
# [OPT-05] All inline list literals hoisted to module-level tuples
#          (tuples are slightly faster for random.choice than lists;
#           defined once at import time instead of rebuilt on every call)
# ══════════════════════════════════════════════════════════════════════════════
_FIRST_NAMES = (
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer",
    "Michael", "Linda", "William", "Barbara", "David", "Susan",
    "Richard", "Jessica", "Joseph", "Sarah", "Thomas", "Karen",
    "Aisha", "Priya", "Wei", "Sofia", "Amara", "Tariq",
)
_LAST_NAMES = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
    "Miller", "Davis", "Wilson", "Anderson", "Taylor", "Thomas",
    "Patel", "Nguyen", "Kim", "Fernandez", "Robinson", "Walker",
)
_US_STATES = (
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID",
    "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS",
    "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK",
    "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV",
    "WI", "WY",
)
_EMAIL_DOMAINS   = ("gmail", "yahoo", "outlook", "hotmail")       # [OPT-05]
_AREA_CODES      = ("212", "312", "415", "617", "713", "214",     # [OPT-05]
                    "404", "503", "602", "702")
_CHANNEL_CODES   = ("WEB", "POS", "JCOM", "GEAPP", "POSCC", "BATCH")
_TIER_CODES      = ("BASE", "CREDIT", "GOLD", "SILVER")
_SOURCE_CODES    = ("WEB", "POS", "JCOM", "GEAPP")
_ENROLL_CHANNELS = ("WEB", "POS", "BATCH")
_STORE_CODES     = ("4302", "1531", "2676", "1052", "0994", "3301", "0500")
_CARD_TYPES      = ("PLCC", "JCMC", "VISA", "MC")
_TENDER_CODES    = ("CREDIT", "CASH", "REWARD", "ECHECK")
_SKU_PREFIXES    = ("11010", "22020", "33030", "44040", "55050")
_STREET_NAMES    = ("Main", "Oak", "Maple", "Cedar", "Elm",       # [OPT-05]
                    "Park", "Lake", "Hill")
_STREET_SUFFIXES = ("St", "Ave", "Blvd", "Dr", "Rd", "Ln", "Way") # [OPT-05]
_CITIES          = (                                                # [OPT-05]
    "Springfield", "Riverside", "Greenfield", "Fairview", "Madison",
    "Georgetown", "Burlington", "Salem", "Ashland", "Clinton",
)


# ══════════════════════════════════════════════════════════════════════════════
# SSM HELPER (optional)
# ══════════════════════════════════════════════════════════════════════════════
def _get_ssm(name: str) -> str:
    ssm = boto3.client("ssm")
    return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]


# ══════════════════════════════════════════════════════════════════════════════
# [OPT-01] Module-level DB connection — reused across warm Lambda invocations.
#          get_db_connection() validates the existing connection before
#          returning it; reconnects only when the socket has been dropped.
# ══════════════════════════════════════════════════════════════════════════════
_db_conn: psycopg2.extensions.connection | None = None


def _new_db_connection() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.environ.get("DB_HOST"),
        port=int(os.environ.get("DB_PORT", 5432)),
        dbname=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        connect_timeout=10,
        options="-c statement_timeout=30000",
    )


def get_db_connection() -> psycopg2.extensions.connection:
    global _db_conn
    if _db_conn is None or _db_conn.closed:
        logger.info("Opening new DB connection.")
        _db_conn = _new_db_connection()
        return _db_conn
    # Cheap liveness probe — avoids stale socket on long idle periods
    try:
        with _db_conn.cursor() as cur:
            cur.execute("SELECT 1")
    except psycopg2.OperationalError:
        logger.warning("DB connection stale — reconnecting.")
        _db_conn = _new_db_connection()
    return _db_conn


# ══════════════════════════════════════════════════════════════════════════════
# [OPT-06] Persistent requests.Session with automatic retry + exponential
#          backoff. Module-level singleton is reused across warm invocations,
#          keeping the underlying TCP connection alive (connection pooling).
# ══════════════════════════════════════════════════════════════════════════════
def _build_http_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,                         # 0.5 s, 1 s, 2 s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session


_http_session: requests.Session = _build_http_session()


# ══════════════════════════════════════════════════════════════════════════════
# RANDOMISATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _rand_str(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _rand_digits(n: int) -> str:
    return "".join(random.choices(string.digits, k=n))


def _rand_email() -> str:
    return f"{_rand_str(6)}{_rand_digits(4)}@{random.choice(_EMAIL_DOMAINS)}.com"


def _rand_phone() -> str:
    return random.choice(_AREA_CODES) + _rand_digits(7)


def _rand_postal() -> str:
    return _rand_digits(5)


def _rand_address() -> str:
    return (
        f"{random.randint(100, 9999)} "
        f"{random.choice(_STREET_NAMES)} "
        f"{random.choice(_STREET_SUFFIXES)}"
    )


def _rand_city() -> str:
    return random.choice(_CITIES)


def _rand_card_number() -> str:
    return "3CE2" + _rand_digits(12).upper()


def _rand_transaction_number() -> str:
    return "TXN" + _rand_digits(12)


def _rand_amount(lo: float = 5.0, hi: float = 500.0) -> float:
    return round(random.uniform(lo, hi), 2)


def _rand_iso_ts(days_back: int = 30) -> str:
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


# [OPT-07] Renamed from camelCase correlationId → _rand_correlation_id (PEP 8)
def _rand_correlation_id() -> str:
    return "corr-" + _rand_str(8) + _rand_digits(8)


# ══════════════════════════════════════════════════════════════════════════════
# PII SCRUBBERS
# ══════════════════════════════════════════════════════════════════════════════

def _scrub_profile(body: dict) -> dict:
    """
    Replace PII fields in a Process Profile request body.
    [OPT-09] Values generated lazily — only when the key is actually present.
    """
    if not isinstance(body, dict):
        return body

    # [OPT-09] Generate shared random values once, used only if needed below
    _fn    = None
    _ln    = None
    _email = None
    _phone = None

    def fn():
        nonlocal _fn
        if _fn is None:
            _fn = random.choice(_FIRST_NAMES)
        return _fn

    def ln():
        nonlocal _ln
        if _ln is None:
            _ln = random.choice(_LAST_NAMES)
        return _ln

    def email():
        nonlocal _email
        if _email is None:
            _email = _rand_email()
        return _email

    def phone():
        nonlocal _phone
        if _phone is None:
            _phone = _rand_phone()
        return _phone

    if "FirstName"  in body: body["FirstName"] = fn()
    if "LastName"   in body: body["LastName"]  = ln()
    if "BirthDate"  in body:
        body["BirthDate"] = (
            f"{random.randint(1950, 2000)}-"
            f"{random.randint(1, 12):02d}-"
            f"{random.randint(1, 28):02d}T00:00:00"
        )
    if "ProfileId"   in body: body["ProfileId"]  = _rand_uuid()
    if "CardNumber"  in body: body["CardNumber"]  = _rand_card_number()

    for em in body.get("Emails", []):
        em["EmailAddress"] = email()
        if "EmailId" in em:
            em["EmailId"] = _rand_uuid()

    for ph in body.get("Phones", []):
        if "PhoneNumber" in ph: ph["PhoneNumber"] = phone()
        if "PhoneId"     in ph: ph["PhoneId"]     = _rand_uuid()

    for addr in body.get("Addresses", []):
        if "AddressLine1" in addr: addr["AddressLine1"] = _rand_address()
        if "City"         in addr: addr["City"]         = _rand_city()
        if "StateCode"    in addr: addr["StateCode"]    = random.choice(_US_STATES)
        if "PostalCode"   in addr: addr["PostalCode"]   = _rand_postal()
        if "AddressId"    in addr: addr["AddressId"]    = _rand_uuid()

    for pk in body.get("PostingKeys", []):
        code = pk.get("PostingKeyCode")
        if code == "EMAIL":
            pk["PostingKeyValue"] = email()
        elif code == "PHONE":
            pk["PostingKeyValue"] = phone()
        elif code == "CCRN":
            pk["PostingKeyValue"] = _rand_digits(16)
        if "PostingKeyId" in pk:
            pk["PostingKeyId"] = _rand_uuid()
        for cd in pk.get("PostingKeyCustomDataGroup", {}).get("CustomData", []):
            name = cd.get("CustomDataName")
            if name == "LAST4DIGIT": cd["CustomDataValue"] = _rand_digits(4)
            if name == "CARDTYPE":   cd["CustomDataValue"] = random.choice(_CARD_TYPES)

    ext = body.get("JsonExternalData")
    if isinstance(ext, dict) and "EnrollmentZipCode" in ext:
        ext["EnrollmentZipCode"] = _rand_postal()

    if "Password"           in body: body["Password"]           = "*" * 22
    if "SourceCode"         in body: body["SourceCode"]         = random.choice(_SOURCE_CODES)
    if "EnrollChannelCode"  in body: body["EnrollChannelCode"]  = random.choice(_ENROLL_CHANNELS)
    if "EnrollmentStoreCode"in body: body["EnrollmentStoreCode"]= random.choice(_STORE_CODES)
    if "TierCode"           in body:
        tier = random.choice(_TIER_CODES)
        body["TierCode"] = tier
        body["TierName"] = tier

    return body


def _scrub_transaction(body: dict) -> dict:
    """Replace PII / identifying fields in a Process Transaction body."""
    if not isinstance(body, dict):
        return body

    if "ProfileId"           in body: body["ProfileId"]           = _rand_uuid()
    if "TransactionNumber"   in body: body["TransactionNumber"]   = _rand_transaction_number()
    if "TransactionDateTime" in body: body["TransactionDateTime"] = _rand_iso_ts(7)
    if "StoreCode"           in body: body["StoreCode"]           = random.choice(_STORE_CODES)
    if "TransactionNetTotal" in body: body["TransactionNetTotal"] = str(_rand_amount(20, 400))
    if "TransactionTotalTax" in body: body["TransactionTotalTax"] = _rand_amount(0.5, 30)
    if "DiscountAmount"      in body: body["DiscountAmount"]      = _rand_amount(0, 50)

    for detail in body.get("TransactionDetails", []):
        if "ItemNumber"      in detail: detail["ItemNumber"]      = random.choice(_SKU_PREFIXES) + _rand_digits(7)
        if "DollarValueGross"in detail: detail["DollarValueGross"]= _rand_amount(5, 150)
        if "Quantity"        in detail: detail["Quantity"]        = random.randint(1, 5)

    for tender in body.get("Tenders", []):
        if "TenderAmount" in tender: tender["TenderAmount"] = _rand_amount(5, 400)
        if "TenderCode"   in tender: tender["TenderCode"]   = random.choice(_TENDER_CODES)

    for cert in body.get("Certificates", []):
        if "CertificateNumber" in cert:
            cert["CertificateNumber"] = _rand_uuid()

    ext = body.get("JsonExternalData")
    if isinstance(ext, dict) and "OrderNumber" in ext:
        ext["OrderNumber"] = "OrdNo" + _rand_digits(6)

    return body


def _scrub_response(body: dict) -> dict:
    """Mask PII fields in API response bodies."""
    if not isinstance(body, dict):
        return body

    for f in ("ProfileId", "RawTransactionId", "TransactionId",
              "PurchaseReferenceTransactionId", "CardNumber",
              "EmailId", "PhoneId", "AddressId", "CertificateNumber"):
        if f in body:
            body[f] = _rand_uuid()

    for em in body.get("Emails", []):
        if "EmailAddress" in em: em["EmailAddress"] = _rand_email()
    for ph in body.get("Phones", []):
        if "PhoneNumber" in ph: ph["PhoneNumber"] = _rand_phone()

    return body


# ── Dispatcher: pick scrubber by API name ────────────────────────────────────
_SCRUB_MAP = {
    "Process Profile":                               _scrub_profile,
    "Process Profile_EmailOnly":                     _scrub_profile,
    "Process Profile_SingleCard":                    _scrub_profile,
    "Process Profile_MultiCard":                     _scrub_profile,
    "Process Profile_EmailCard":                     _scrub_profile,
    "Process Profile_EmailMultiCard":                _scrub_profile,
    "Process Profile_EmailOnlyUpdateEnrollment":     _scrub_profile,
    "Process Profile_SingleCardUpdateEnrollment":    _scrub_profile,
    "Process Transaction - PR-SingleTender":         _scrub_transaction,
    "Process Transaction - PR-Prod":                 _scrub_transaction,
    "Process Transaction - RT-FullReturn":           _scrub_transaction,
    "Process Transaction - RT-PartialReturnSingleQty": _scrub_transaction,
    "Process Transaction - PR-SplitTender":          _scrub_transaction,
    "Process Transaction - PR-Certificate":          _scrub_transaction,
}


# ══════════════════════════════════════════════════════════════════════════════
# LOG ENTRY SANITISER
# ══════════════════════════════════════════════════════════════════════════════

def randomise_log_entry(entry: dict) -> dict:
    """
    Scrub PII from a single log entry.
    Returns a new dict with request_body / response_body as JSON strings
    tagged with _already_serialised=True so _safe_jsonb() can skip re-parsing.
    """
    api_name = entry.get("api_name", "")

    # ── request body ─────────────────────────────────────────────────────────
    req_body = entry.get("request_body")
    req_already_json = False
    if isinstance(req_body, str):
        try:
            req_body = json.loads(req_body)
        except (json.JSONDecodeError, TypeError):
            pass

    scrubber = _SCRUB_MAP.get(api_name)
    if scrubber and isinstance(req_body, dict):
        req_body = scrubber(req_body)

    if isinstance(req_body, dict):
        req_body = json.dumps(req_body)
        req_already_json = True

    # ── response body ─────────────────────────────────────────────────────────
    resp_body = entry.get("response_body")
    resp_already_json = False
    if isinstance(resp_body, str):
        try:
            resp_body = json.loads(resp_body)
        except (json.JSONDecodeError, TypeError):
            pass

    if isinstance(resp_body, dict):
        resp_body = _scrub_response(resp_body)
        resp_body = json.dumps(resp_body)
        resp_already_json = True

    return {
        **entry,
        "request_body":           req_body,
        "response_body":          resp_body,
        "_req_already_json":      req_already_json,   # [OPT-03] skip re-parse hint
        "_resp_already_json":     resp_already_json,  # [OPT-03] skip re-parse hint
        "profile_email":          _rand_email(),
        "profile_id":             _rand_uuid(),
        "correlation_id":         _rand_correlation_id(),  # [OPT-07]
    }


# ══════════════════════════════════════════════════════════════════════════════
# [OPT-02] DB SCHEMA INITIALISATION — runs only once per container lifetime
# ══════════════════════════════════════════════════════════════════════════════
_table_ensured: bool = False

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS epcl_api_logs (
    id               BIGSERIAL PRIMARY KEY,
    log_id           VARCHAR(128)  UNIQUE NOT NULL,
    api_name         VARCHAR(256),
    http_method      VARCHAR(10),
    endpoint_path    TEXT,
    status_code      SMALLINT,
    request_body     JSONB,
    response_body    JSONB,
    profile_id       VARCHAR(128),
    profile_email    VARCHAR(256),
    correlation_id   VARCHAR(128),
    latency_ms       INTEGER,
    log_timestamp    TIMESTAMPTZ,
    ingested_at      TIMESTAMPTZ   DEFAULT NOW(),
    is_error         BOOLEAN       GENERATED ALWAYS AS (status_code >= 400) STORED
);

CREATE INDEX IF NOT EXISTS idx_epcl_logs_api_name       ON epcl_api_logs (api_name);
CREATE INDEX IF NOT EXISTS idx_epcl_logs_status         ON epcl_api_logs (status_code);
CREATE INDEX IF NOT EXISTS idx_epcl_logs_timestamp      ON epcl_api_logs (log_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_epcl_logs_profile_id     ON epcl_api_logs (profile_id);
CREATE INDEX IF NOT EXISTS idx_epcl_logs_is_error       ON epcl_api_logs (is_error);
CREATE INDEX IF NOT EXISTS idx_epcl_logs_ingested_at    ON epcl_api_logs (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_epcl_logs_correlation_id ON epcl_api_logs (correlation_id);
"""


def ensure_table(conn) -> None:
    global _table_ensured
    if _table_ensured:
        return                                   # [OPT-02] skip on warm invocations
    with conn.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)
    conn.commit()
    _table_ensured = True
    logger.info("epcl_api_logs table/indexes verified.")


# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 2 — FETCH LOGS
# [OPT-06] Uses _http_session (persistent + retry) instead of requests.post()
# ══════════════════════════════════════════════════════════════════════════════

def fetch_logs_from_endpoint2(since: datetime, batch_size: int) -> list[dict]:
    base_url = os.environ.get("ENDPOINT2_URL", "").rstrip("/")
    api_key  = os.environ.get("ENDPOINT2_API_KEY", "")
    timeout  = int(os.environ.get("ENDPOINT2_TIMEOUT_S", 20))

    url = f"{base_url}/logs"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    payload = {
        "from":      since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "to":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "page_size": batch_size,
    }

    try:
        # [OPT-06] _http_session retries on 5xx/429 with backoff
        resp = _http_session.post(url, headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("logs", data if isinstance(data, list) else [])
    except requests.RequestException as exc:
        logger.error("Endpoint 2 fetch failed after retries: %s", exc)
        return []


# ══════════════════════════════════════════════════════════════════════════════
# DB INSERT
# [OPT-03] _already_serialised hint skips redundant json.loads in _safe_jsonb
# [OPT-04] execute_values() issues a single multi-row INSERT — faster than
#           execute_batch() with page_size chunks
# [OPT-08] _safe_jsonb logs a warning for malformed strings
# ══════════════════════════════════════════════════════════════════════════════

# execute_values expects a VALUES template — %s per positional column
INSERT_SQL_VALUES = """
INSERT INTO epcl_api_logs
    (log_id, api_name, http_method, endpoint_path, status_code,
     request_body, response_body, profile_id, profile_email,
     correlation_id, latency_ms, log_timestamp)
VALUES %s
ON CONFLICT (log_id) DO NOTHING
"""

# Template used by execute_values — one tuple per row
_ROW_TEMPLATE = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"


def _safe_jsonb(value: Any, already_serialised: bool = False) -> str | None:
    """
    Return a JSONB-ready string.
    [OPT-03] When already_serialised=True the value came from json.dumps()
             inside randomise_log_entry(), so we skip the re-parse entirely.
    [OPT-08] Malformed raw strings are wrapped but always logged.
    """
    if value is None:
        return None
    if already_serialised:
        return value                                  # [OPT-03] zero extra work
    if isinstance(value, str):
        try:
            json.loads(value)
            return value
        except (json.JSONDecodeError, TypeError):
            logger.warning("Non-JSON string stored as raw: %.120s", value)  # [OPT-08]
            return json.dumps({"raw": value})
    return json.dumps(value)


def insert_logs(conn, logs: list[dict]) -> tuple[int, int]:
    """
    Insert sanitised log rows into epcl_api_logs.
    Returns (attempted, inserted) — inserted < attempted when conflicts occur.
    [OPT-04] Single execute_values() call replaces multiple execute_batch() rounds.
    [OPT-12] Conflict skips tracked via cursor.rowcount and logged.
    """
    rows: list[tuple] = []
    for log in logs:
        rows.append((
            log.get("log_id") or _rand_uuid(),
            log.get("api_name"),
            log.get("http_method"),
            log.get("endpoint_path"),
            log.get("status_code"),
            _safe_jsonb(log.get("request_body"),  log.get("_req_already_json",  False)),
            _safe_jsonb(log.get("response_body"), log.get("_resp_already_json", False)),
            log.get("profile_id"),
            log.get("profile_email"),
            log.get("correlation_id"),
            log.get("latency_ms"),
            log.get("timestamp"),
        ))

    if not rows:
        return 0, 0

    with conn.cursor() as cur:
        # [OPT-04] Single round-trip for all rows
        psycopg2.extras.execute_values(
            cur, INSERT_SQL_VALUES, rows,
            template=_ROW_TEMPLATE,
            page_size=len(rows),    # one statement per call
        )
        inserted = cur.rowcount     # [OPT-12] rows actually written (conflicts excluded)
    conn.commit()

    attempted = len(rows)
    skipped   = attempted - inserted
    if skipped:
        logger.info("Conflict skips (duplicate log_id): %d / %d", skipped, attempted)  # [OPT-12]

    return attempted, inserted


# ══════════════════════════════════════════════════════════════════════════════
# LAMBDA HANDLER
# [OPT-10] Structured try/except — DB errors surface as 500, not silent Lambda
#          retries that might re-fetch and re-duplicate.
# [OPT-11] conn.close() removed — connection kept alive for warm invocations.
# ══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    batch_size       = int(os.environ.get("BATCH_SIZE", 100))
    lookback_minutes = int(os.environ.get("LOOKBACK_MINUTES", 6))

    since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    logger.info("Fetching logs since %s (batch_size=%d)", since.isoformat(), batch_size)

    # 1 ── Fetch raw logs from Endpoint 2
    raw_logs = fetch_logs_from_endpoint2(since, batch_size)
    logger.info("Received %d log entries from Endpoint 2", len(raw_logs))

    if not raw_logs:
        return {"statusCode": 200, "body": json.dumps({"inserted": 0, "message": "No new logs"})}

    # 2 ── Randomise / scrub PII in every entry
    sanitised = [randomise_log_entry(entry) for entry in raw_logs]

    # 3 ── Persist to PostgreSQL
    # [OPT-10] Catch DB errors explicitly; return 500 so Lambda dead-letter
    #          queue / alerting can trigger rather than silently swallowing.
    try:
        conn = get_db_connection()          # [OPT-01] reused warm connection
        ensure_table(conn)                  # [OPT-02] no-op after first run
        attempted, inserted = insert_logs(conn, sanitised)
        logger.info("Inserted %d / %d rows into epcl_api_logs", inserted, attempted)
    except psycopg2.Error as db_err:
        logger.exception("DB error during insert: %s", db_err)
        # [OPT-11] Do NOT close — let the connection be garbage-collected or
        #          recovered on the next invocation via the liveness probe.
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "DB insert failed", "detail": str(db_err)}),
        }
    # [OPT-11] No conn.close() — connection stays alive for warm invocations

    return {
        "statusCode": 200,
        "body": json.dumps({
            "fetched":   len(raw_logs),
            "attempted": attempted,
            "inserted":  inserted,
            "skipped":   attempted - inserted,
            "since":     since.isoformat(),
        }),
    }