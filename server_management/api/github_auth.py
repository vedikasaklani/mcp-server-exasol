import time
import os
import jwt
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

GITHUB_APP_ID = os.environ["GITHUB_APP_ID"]
GITHUB_PRIVATE_KEY = os.environ["GITHUB_PRIVATE_KEY"]


def _load_private_key() -> bytes:
    """
    Load GitHub private key from environment and normalize for JWT signing.
    Handles Render's PEM storage format (escaped newlines).
    Returns bytes suitable for jwt.encode().
    """
    key = GITHUB_PRIVATE_KEY.strip()

    # Step 1: Strip outer quotes (Render wraps multi-line strings)
    if (key.startswith('"') and key.endswith('"')) or \
       (key.startswith("'") and key.endswith("'")):
        key = key[1:-1]

    # Step 2: Normalize escaped sequences to actual newlines
    # Render stores as: "-----BEGIN RSA PRIVATE KEY-----\\n..."
    key = key.replace("\\n", "\n")
    key = key.replace("\\r\\n", "\n")  # Handle Windows line endings
    key = key.replace("\\r", "")        # Remove any remaining carriage returns
    key = key.replace("\\t", "\t")      # In case tabs got escaped

    # Step 3: Clean up whitespace and ensure PEM markers
    key = key.strip()
    
    if not key.startswith("-----BEGIN"):
        raise ValueError(
            "Invalid PEM key: missing BEGIN marker. "
            "Key may not have been properly unescaped from environment."
        )
    if not key.endswith("-----"):
        raise ValueError(
            "Invalid PEM key: missing END marker. "
            "Key may be truncated or improperly stored."
        )

    # Step 4: Reconstruct proper PEM format (normalize line breaks)
    lines = key.split("\n")
    clean_lines = [line.strip() for line in lines if line.strip()]

    # Validate: PEM should have BEGIN, multiple base64 lines, END
    if len(clean_lines) < 3:
        raise ValueError(
            f"Invalid PEM key: too few lines ({len(clean_lines)}). "
            "Key may not have been properly unescaped. "
            f"Got: {key[:100]}..."
        )

    # Reconstruct with proper newlines
    normalized_key = "\n".join(clean_lines) + "\n"

    # Step 5: Validate by attempting to load it
    try:
        serialization.load_pem_private_key(
            normalized_key.encode(),
            password=None,
            backend=default_backend(),
        )
    except Exception as e:
        raise ValueError(
            f"Failed to load PEM key: {str(e)}. "
            f"Key format is invalid after normalization."
        ) from e

    return normalized_key.encode()


def generate_app_jwt() -> str:
    """
    Generate a JWT signed with the GitHub App private key.
    Valid for 10 minutes (600 seconds).
    """
    now = int(time.time())
    payload = {
        "iat": now - 60,        # Issued at (leeway for clock skew)
        "exp": now + 9 * 60,    # Expires in 9 minutes
        "iss": GITHUB_APP_ID,   # GitHub App ID
    }
    
    try:
        private_key = _load_private_key()
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return token
    except ValueError as e:
        # Re-raise with context about what went wrong
        raise RuntimeError(
            f"Failed to generate JWT: {str(e)}. "
            f"Check GITHUB_PRIVATE_KEY environment variable."
        ) from e


async def get_installation_token(installation_id: int) -> str:
    """
    Exchange app JWT for an installation-specific access token.
    This token can be used to make authenticated requests on behalf of the app.
    """
    app_jwt = generate_app_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers)
    
    # Raise HTTP errors with response body for debugging
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(
            f"Failed to get installation token: {resp.status_code} {resp.text}"
        ) from e
    
    return resp.json()["token"]