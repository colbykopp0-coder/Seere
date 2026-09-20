# SEERE Exposure Index API

Prototype API for the "Have your machines been exposed?" experience.

## Run

```bash
python -m pip install -r apps/exposure_api/requirements.txt
uvicorn apps.exposure_api.main:app --reload
```

Open:

```
http://127.0.0.1:8000/docs
```

## Intended flow

1. `POST /v1/claims` with a company domain.
2. SEERE returns a DNS TXT challenge.
3. A production verifier checks ownership.
4. Only verified organizations can receive detailed exposure metadata.

The prototype intentionally leaves DNS verification unimplemented rather than
pretending ownership has been proven.
