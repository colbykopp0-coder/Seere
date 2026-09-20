"""
SEERE Exposure Index API concept.

Run locally:
    pip install fastapi uvicorn
    uvicorn apps.exposure_api.main:app --reload

This example deliberately gates finding details behind organization verification.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from seere_index.store import ExposureStore
from seere_index.verification import create_dns_challenge, verification_instructions

app = FastAPI(title="SEERE Exposure Index", version="0.1.0")
store = ExposureStore("seere-index.db")

# Concept-only in-memory claim store.
# Production: durable encrypted storage + expiry + audit log.
claims: dict[str, dict] = {}


class ClaimRequest(BaseModel):
    domain: str


@app.get("/")
def root():
    return {
        "name": "SEERE Exposure Index",
        "message": "Have your machines been exposed?",
    }


@app.post("/v1/claims")
def create_claim(request: ClaimRequest):
    challenge = create_dns_challenge(request.domain)
    claims[challenge.domain] = {
        "token": challenge.token,
        "verified": False,
    }
    return verification_instructions(challenge)


@app.post("/v1/claims/{domain}/verify")
def verify_claim(domain: str):
    # Production implementation must independently resolve the DNS TXT record.
    # This prototype intentionally does not auto-verify.
    if domain.lower() not in claims:
        raise HTTPException(status_code=404, detail="Claim not found")

    return {
        "domain": domain.lower(),
        "verified": False,
        "status": "verification adapter not configured in prototype",
    }


@app.get("/v1/exposure/{domain}")
def exposure(domain: str):
    claim = claims.get(domain.lower())

    if not claim or not claim["verified"]:
        return {
            "domain": domain.lower(),
            "verified": False,
            "message": "Verify ownership to view machine-credential exposure.",
        }

    return {
        "domain": domain.lower(),
        "verified": True,
        "summary": store.summary(domain),
        "findings": store.records(domain),
    }
