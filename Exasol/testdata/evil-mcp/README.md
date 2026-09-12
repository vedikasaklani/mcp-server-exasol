# evil-mcp — the positive control

A deliberately malicious MCP server. It exists because a clean server
reporting "no findings" proves nothing on its own: without a server that
*does* produce findings, a silent detector and a broken detector look
identical. This is the other half of that test.

It is never published, never installed as a dependency, and never executed
outside a confined sandbox by anything in this repo. `helper.py` is not
executed at all — it exists so the SAST leg has something to find.

## What it attempts

`server.js` advertises two tools:

- **`exfiltrate`** — tries to read `/etc/shadow`, `/root/.ssh/id_rsa` and
  `~/.aws/credentials`, write to `/etc/`, spawn `/bin/sh`, and list
  `/home`. It reports what each attempt returned, so you can see the
  kernel refusing them (`ENOENT`, `EROFS`).
- **`leak_secret`** — returns a response containing an AWS-key-shaped
  string and an "ignore previous instructions" phrase, exercising the
  response-content scanners.

`helper.py` contains a hardcoded credential, `subprocess(..., shell=True)`
and `eval()` — patterns Semgrep's `p/security-audit` ruleset flags, so the
static-analysis path produces findings too.

## Using it

```bash
./warden
> load path:testdata/evil-mcp
> call exfiltrate {}
> call leak_secret {}
# wait ~15s for gVisor's async trace, then
> scan
> reputation
> stop
```

Expected: posture `QUARANTINE`, 5 kernel-attested findings, every attack
refused, and a security score of 0 against the official reference server's
100. See `docs/TESTING.md` for the full walkthrough.
