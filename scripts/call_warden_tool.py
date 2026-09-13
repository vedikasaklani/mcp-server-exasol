"""Call a live, confined MCP server tool through the Warden API.

Usage:
    python call_warden_tool.py <server_id> <tool_name> '<json_arguments>'

Example:
    python call_warden_tool.py a19eff14-ae1b-4904-8e6f-7abb3ce9ae63 search_nodes '{"query": "Warden"}'
"""

import json
import sys
import urllib.request

API_BASE = "http://localhost:8000"  # or the ngrok URL if calling from a different machine


def call_tool(server_id: str, tool_name: str, arguments: dict) -> dict:
    url = f"{API_BASE}/servers/{server_id}/call"
    body = json.dumps({"tool_name": tool_name, "arguments": arguments}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    server_id, tool_name, raw_args = sys.argv[1], sys.argv[2], sys.argv[3]
    result = call_tool(server_id, tool_name, json.loads(raw_args))
    print(json.dumps(result, indent=2))
