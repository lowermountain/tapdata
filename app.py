"""
tapdata ingestion API
Receives JSON via a secured POST endpoint and pushes it to FileMaker via OData.
"""

import json
import logging
import os
from base64 import b64encode
from datetime import datetime, timezone

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

load_dotenv()

# API security
API_TOKEN: str = os.environ["API_TOKEN"]

# FileMaker OData
FM_SERVER: str = os.environ["FM_SERVER"].rstrip("/")       # e.g. https://fm.example.com
FM_DATABASE: str = os.environ["FM_DATABASE"]               # e.g. MyDatabase
FM_TABLE: str = os.environ["FM_TABLE"]                     # OData entity name, e.g. Ingest
FM_JSON_FIELD: str = os.environ["FM_JSON_FIELD"]           # FM field that stores the raw JSON
FM_USERNAME: str = os.environ["FM_USERNAME"]
FM_PASSWORD: str = os.environ["FM_PASSWORD"]

# Optional: extra fields to stamp on every record
FM_SOURCE_FIELD: str = os.getenv("FM_SOURCE_FIELD", "")    # e.g. "Source"  (leave blank to skip)

# OData endpoint for creating records
FM_ODATA_URL: str = f"{FM_SERVER}/fmi/odata/v4/{FM_DATABASE}/{FM_TABLE}"

# Basic-Auth header value (OData uses Basic Auth)
_credentials = b64encode(f"{FM_USERNAME}:{FM_PASSWORD}".encode()).decode()
FM_AUTH_HEADER: str = f"Basic {_credentials}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("tapdata")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="tapdata ingestion API",
    description="Receives JSON and pushes it to FileMaker via OData.",
    version="1.0.0",
    docs_url=None,   # disable Swagger UI in production
    redoc_url=None,
)

security = HTTPBearer()


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> None:
    """Validate the bearer token in constant time to prevent timing attacks."""
    import hmac
    token_bytes = credentials.credentials.encode()
    expected_bytes = API_TOKEN.encode()
    if not hmac.compare_digest(token_bytes, expected_bytes):
        logger.warning("Rejected request: invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", include_in_schema=False)
async def health() -> dict:
    """Simple liveness check (no auth required)."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest(
    request: Request,
    _: None = Depends(verify_token),
) -> dict:
    """
    Accept a JSON payload and create a new record in FileMaker via OData.

    The full JSON body is stored as a string in FM_JSON_FIELD.
    """
    # Parse body
    try:
        body: dict = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON.",
        )

    # Serialize the payload to store in FM
    json_string = json.dumps(body, ensure_ascii=False)

    # Build the OData record payload
    fm_record: dict = {FM_JSON_FIELD: json_string}
    if FM_SOURCE_FIELD:
        fm_record[FM_SOURCE_FIELD] = request.headers.get("X-Source", "api")

    logger.info("Pushing record to FM OData: %s / %s", FM_DATABASE, FM_TABLE)

    # Send to FileMaker
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                FM_ODATA_URL,
                json=fm_record,
                headers={
                    "Authorization": FM_AUTH_HEADER,
                    "Content-Type": "application/json",
                    "OData-Version": "4.0",
                    "Accept": "application/json",
                },
            )
    except httpx.RequestError as exc:
        logger.error("Network error contacting FM: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not reach FileMaker server: {exc}",
        )

    # FM OData returns 201 on success
    if response.status_code not in (200, 201):
        logger.error(
            "FM OData error %s: %s",
            response.status_code,
            response.text[:500],
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"FileMaker returned {response.status_code}: {response.text[:200]}",
        )

    logger.info("Record created successfully in FM")

    try:
        fm_response = response.json()
    except Exception:
        fm_response = {}

    return {
        "status": "created",
        "fm_response": fm_response,
    }
