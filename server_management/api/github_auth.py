import time
import os
import jwt
import httpx

GITHUB_APP_ID = os.environ["GITHUB_APP_ID"]
GITHUB_PRIVATE_KEY = os.environ["GITHUB_PRIVATE_KEY"]  

def _load_private_key() -> str:
    """Normalize a GitHub App PEM private key from an environment variable."""

    key = GITHUB_PRIVATE_KEY.strip()

    key = key.replace(r"\n", "\n")

    if len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}:
        key = key[1:-1].strip()

    return key

def generate_app_jwt() -> str:
    now = int(time.time())
    payload = {
        "iat": now - 60,        
        "exp": now + 9 * 60,   
        "iss": GITHUB_APP_ID,
    }
    return jwt.encode(payload, _load_private_key(), algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    app_jwt = generate_app_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers)
    resp.raise_for_status()
    return resp.json()["token"] 