import time
import os
import jwt
import httpx

GITHUB_APP_ID = os.environ["GITHUB_APP_ID"]
GITHUB_PRIVATE_KEY = os.environ["GITHUB_PRIVATE_KEY"]  


def generate_app_jwt() -> str:
    now = int(time.time())
    payload = {
        "iat": now - 60,        
        "exp": now + 9 * 60,   
        "iss": GITHUB_APP_ID,
    }
    return jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    app_jwt = generate_app_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers)
    resp.raise_for_status()
    return resp.json()["token"] 