import time
import os
import jwt
import httpx

GITHUB_APP_ID = os.environ["GITHUB_APP_ID"]
GITHUB_PRIVATE_KEY = os.environ["GITHUB_PRIVATE_KEY"]  

def _load_private_key() -> str:
    key = GITHUB_PRIVATE_KEY.strip()

    print(
        "GITHUB KEY DEBUG:",
        {
            "length": len(key),
            "starts_with": repr(key[:40]),
            "ends_with": repr(key[-40:]),
            "literal_backslash_n": "\\n" in key,
            "literal_backslash_r": "\\r" in key,
            "newline_count": key.count("\n"),
        },
        flush=True,
    )

    key = key.replace("\\r\\n", "\n")
    key = key.replace("\\n", "\n")
    key = key.replace("\\r", "\n")

    if len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}:
        key = key[1:-1].strip()

    print(
        "GITHUB KEY AFTER NORMALIZATION:",
        {
            "length": len(key),
            "starts_with": repr(key[:40]),
            "ends_with": repr(key[-40:]),
            "newline_count": key.count("\n"),
        },
        flush=True,
    )

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